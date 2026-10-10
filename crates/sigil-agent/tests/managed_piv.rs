use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use prost::Message;
use sigil_agent::{
    audit_outbox::AuditOutbox,
    backend::{ManagedAuthority, ManagedGrant, ManagedRequest, ManagedSecret},
    caller::{CallerIdentity, CallerPolicy},
    grant::{GrantVerifier, Unconfigured},
    server::AgentService,
};
use sigil_app::CredentialService;
use sigil_core::{
    DeviceDiscovery, DeviceId, DeviceManagement, ManagementKey, ManagementKeyAlgorithm, PinPolicy,
    PivAlgorithm, PivInspection, PivKeyAlgorithm, PivKeyConfiguration, PivManagement, PivPin,
    PivPuk, PivSlot, TouchPolicy,
};
use sigil_mock::MockDiscovery;
use sigil_proto::{
    backend::v1::AgentAuditEvent,
    error_from_status,
    v1::{self, ManagedAuthorization, Operation, OperationGrant, SignedGrant, agent_server::Agent},
};
use tonic::{Request, Status};
use zeroize::Zeroizing;

const STATION_ID: &str = "sigil-test-station";
const TOKEN_SERIAL: &str = "12345678";
const CALLER: &str = "S-1-5-21-sigil-test";
const KEY_ID: &str = "sigil-dev-v1";
const ACCESS_TOKEN: &str = "test-access-token-not-for-logs";

#[derive(Clone, Default)]
struct GrantOverride {
    operation: Option<Operation>,
    station_id: Option<String>,
    token_serial: Option<String>,
    caller_os_user: Option<String>,
    piv_slot: Option<u32>,
    key_id: Option<String>,
}

struct FakeAuthority {
    signing_key: SigningKey,
    next_grant: AtomicU64,
    authorize_calls: AtomicUsize,
    authorize_error: Mutex<Option<Status>>,
    grant_override: Mutex<GrantOverride>,
    complete_failures: AtomicUsize,
    completions: Mutex<Vec<(String, bool)>>,
}

impl FakeAuthority {
    fn new() -> Self {
        Self {
            signing_key: SigningKey::from_bytes((&[7u8; 32]).into())
                .expect("test grant signing key"),
            next_grant: AtomicU64::new(1),
            authorize_calls: AtomicUsize::new(0),
            authorize_error: Mutex::new(None),
            grant_override: Mutex::new(GrantOverride::default()),
            complete_failures: AtomicUsize::new(0),
            completions: Mutex::new(Vec::new()),
        }
    }

    fn verifier(&self) -> Arc<GrantVerifier> {
        Arc::new(GrantVerifier::new(HashMap::from([(
            KEY_ID.into(),
            VerifyingKey::from(&self.signing_key),
        )])))
    }

    fn set_grant_override(&self, grant_override: GrantOverride) {
        *self.grant_override.lock().expect("grant override mutex") = grant_override;
    }

    fn fail_authorize_with(&self, status: Status) {
        *self
            .authorize_error
            .lock()
            .expect("authorization error mutex") = Some(status);
    }

    fn fail_next_completions(&self, count: usize) {
        self.complete_failures.store(count, Ordering::SeqCst);
    }

    fn completions(&self) -> Vec<(String, bool)> {
        self.completions.lock().expect("completion mutex").clone()
    }
}

#[async_trait::async_trait]
impl ManagedAuthority for FakeAuthority {
    async fn authorize(&self, request: ManagedRequest) -> Result<ManagedGrant, Status> {
        self.authorize_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(status) = self
            .authorize_error
            .lock()
            .expect("authorization error mutex")
            .take()
        {
            return Err(status);
        }
        assert!(!request.access_token.is_empty());
        let override_grant = self
            .grant_override
            .lock()
            .expect("grant override mutex")
            .clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        let grant_id = format!(
            "fake-grant-{}",
            self.next_grant.fetch_add(1, Ordering::Relaxed)
        );
        let operation = override_grant.operation.unwrap_or(request.operation);
        let grant = OperationGrant {
            version: 1,
            grant_id: grant_id.clone(),
            operation: operation as i32,
            subject: "fake-backend-user".into(),
            station_id: override_grant
                .station_id
                .unwrap_or_else(|| STATION_ID.into()),
            token_serial: override_grant
                .token_serial
                .unwrap_or_else(|| request.serial.clone()),
            caller_os_user: override_grant
                .caller_os_user
                .unwrap_or_else(|| request.caller_os_user.clone()),
            not_before_unix: now - 1,
            expires_at_unix: now + 120,
            piv_slot: override_grant
                .piv_slot
                .unwrap_or_else(|| u32::from(request.piv_slot.unwrap_or_default())),
        };
        let grant_bytes = grant.encode_to_vec();
        let signature: Signature = self.signing_key.sign(&grant_bytes);
        let signed_grant = SignedGrant {
            grant: grant_bytes,
            signature: signature.to_der().as_bytes().to_vec(),
            key_id: override_grant.key_id.unwrap_or_else(|| KEY_ID.into()),
        };
        let rotation = matches!(
            request.operation,
            Operation::PivChangePuk
                | Operation::PivChangeManagementKey
                | Operation::PivManagedInitialize
        );
        let default_mk = default_management_key();
        let (current_management_key, current_puk, new_management_key, new_puk) = match request
            .operation
        {
            Operation::PivGenerateKey
            | Operation::PivImportCertificate
            | Operation::PivDeleteCertificate
            | Operation::PivDeleteKey => (Some(secret(default_mk, "aes192")), None, None, None),
            Operation::PivUnblockPin => (None, Some(secret(b"12345678".to_vec(), "")), None, None),
            Operation::PivChangePuk => (
                None,
                Some(secret(b"12345678".to_vec(), "")),
                None,
                Some(secret(b"87654321".to_vec(), "")),
            ),
            Operation::PivChangeManagementKey => (
                Some(secret(default_mk, "aes192")),
                None,
                Some(secret(vec![0x42; 32], "aes256")),
                None,
            ),
            Operation::PivManagedInitialize => (
                None,
                None,
                Some(secret(vec![0x42; 32], "aes256")),
                Some(secret(b"87654321".to_vec(), "")),
            ),
            _ => (None, None, None, None),
        };
        Ok(ManagedGrant {
            signed_grant,
            current_management_key,
            current_puk,
            rotation_id: rotation.then_some(grant_id),
            new_management_key,
            new_puk,
        })
    }

    async fn complete_rotation(&self, rotation_id: &str, applied: bool) -> Result<(), Status> {
        if self
            .complete_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                if remaining > 0 {
                    Some(remaining - 1)
                } else {
                    None
                }
            })
            .is_ok()
        {
            return Err(Status::unavailable(
                "fake backend is temporarily unavailable",
            ));
        }
        self.completions
            .lock()
            .expect("completion mutex")
            .push((rotation_id.to_owned(), applied));
        Ok(())
    }

    async fn report_tokens(
        &self,
        _tokens: Vec<sigil_proto::backend::v1::ObservedToken>,
    ) -> Result<(), Status> {
        Ok(())
    }

    async fn report_audit(&self, events: Vec<AgentAuditEvent>) -> Result<u64, Status> {
        Ok(events
            .iter()
            .map(|event| event.sequence)
            .max()
            .unwrap_or_default())
    }
}

fn secret(value: Vec<u8>, algorithm: &str) -> ManagedSecret {
    ManagedSecret {
        value: Zeroizing::new(value),
        algorithm: algorithm.into(),
    }
}

fn default_management_key() -> Vec<u8> {
    [1, 2, 3, 4, 5, 6, 7, 8]
        .into_iter()
        .cycle()
        .take(24)
        .collect()
}

fn mock_service() -> (Arc<MockDiscovery>, CredentialService) {
    let mock = Arc::new(MockDiscovery::with_example());
    let discovery: Arc<dyn DeviceDiscovery> = mock.clone();
    let management: Arc<dyn PivManagement> = mock.clone();
    let device_management: Arc<dyn DeviceManagement> = mock.clone();
    (
        mock,
        CredentialService::new_with_device_management(discovery, management, device_management),
    )
}

fn agent_service(
    credentials: CredentialService,
    backend: Option<Arc<FakeAuthority>>,
    outbox: Option<Arc<AuditOutbox>>,
) -> AgentService {
    let verifier = backend
        .as_ref()
        .map(|backend| backend.verifier())
        .unwrap_or_else(|| Arc::new(GrantVerifier::new(HashMap::new())));
    let mut service = AgentService::new(credentials, STATION_ID)
        .with_policy(CallerPolicy {
            require_console_session: false,
        })
        .with_authorization(Arc::new(Unconfigured), verifier);
    if let Some(backend) = backend {
        service = service.with_backend(backend);
    }
    if let Some(outbox) = outbox {
        service = service.with_audit_outbox(outbox);
    }
    service
}

fn with_caller<T>(request: Request<T>) -> Request<T> {
    let mut request = request;
    request.extensions_mut().insert(CallerIdentity {
        os_user: CALLER.into(),
        session_id: Some(1),
        pid: 1234,
    });
    request
}

fn managed_token() -> Option<ManagedAuthorization> {
    Some(ManagedAuthorization {
        access_token: ACCESS_TOKEN.into(),
    })
}

fn generate_request(
    slot: PivSlot,
    managed: Option<ManagedAuthorization>,
) -> v1::GeneratePivKeyRequest {
    v1::GeneratePivKeyRequest {
        id: "mock-yubikey-12345678".into(),
        expected_serial: TOKEN_SERIAL.into(),
        management_key: Vec::new(),
        management_key_algorithm: v1::ManagementKeyAlgorithm::Unspecified as i32,
        slot_byte: u32::from(slot.byte()),
        algorithm: v1::PivKeyGenerationAlgorithm::PivKeyGenerationEccP256 as i32,
        pin_policy: v1::PinPolicy::Once as i32,
        touch_policy: v1::TouchPolicy::Never as i32,
        managed,
    }
}

#[tokio::test]
async fn managed_generate_and_key_operations_use_the_released_management_key() {
    let (mock, credentials) = mock_service();
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend), None);
    let id = DeviceId("mock-yubikey-12345678".into());
    let retired = PivSlot::retired(1).expect("retired slot");

    assert!(!mock.has_key_in_slot(&id, retired).unwrap());
    Agent::generate_piv_key(
        &service,
        with_caller(Request::new(generate_request(retired, managed_token()))),
    )
    .await
    .expect("managed key generation");
    assert!(mock.has_key_in_slot(&id, retired).unwrap());

    let certificate = mock
        .piv_certificate(&id, PivSlot::AUTHENTICATION)
        .unwrap()
        .expect("fixture certificate");
    Agent::import_piv_certificate(
        &service,
        with_caller(Request::new(v1::ImportPivCertificateRequest {
            id: id.0.clone(),
            expected_serial: TOKEN_SERIAL.into(),
            management_key: Vec::new(),
            management_key_algorithm: v1::ManagementKeyAlgorithm::Unspecified as i32,
            slot_byte: u32::from(PivSlot::AUTHENTICATION.byte()),
            certificate_der: certificate.der,
            managed: managed_token(),
        })),
    )
    .await
    .expect("managed certificate import");
    Agent::delete_piv_certificate(
        &service,
        with_caller(Request::new(v1::DeletePivCertificateRequest {
            id: id.0.clone(),
            expected_serial: TOKEN_SERIAL.into(),
            management_key: Vec::new(),
            management_key_algorithm: v1::ManagementKeyAlgorithm::Unspecified as i32,
            slot_byte: u32::from(PivSlot::AUTHENTICATION.byte()),
            managed: managed_token(),
        })),
    )
    .await
    .expect("managed certificate deletion");
    assert!(
        mock.piv_certificate(&id, PivSlot::AUTHENTICATION)
            .unwrap()
            .is_none()
    );
    Agent::delete_piv_key(
        &service,
        with_caller(Request::new(v1::DeletePivKeyRequest {
            id: id.0.clone(),
            expected_serial: TOKEN_SERIAL.into(),
            management_key: Vec::new(),
            management_key_algorithm: v1::ManagementKeyAlgorithm::Unspecified as i32,
            slot_byte: u32::from(retired.byte()),
            managed: managed_token(),
        })),
    )
    .await
    .expect("managed key deletion");
    assert!(!mock.has_key_in_slot(&id, retired).unwrap());

    Agent::unblock_piv_pin(
        &service,
        with_caller(Request::new(v1::UnblockPivPinRequest {
            id: id.0.clone(),
            expected_serial: TOKEN_SERIAL.into(),
            puk: Vec::new(),
            new_pin: b"654321".to_vec(),
            managed: managed_token(),
        })),
    )
    .await
    .expect("managed PUK release for PIN unblock");
    assert_eq!(
        mock.piv_info(&id).unwrap().pin.unwrap().default_value,
        Some(false)
    );
}

#[tokio::test]
async fn managed_grant_mismatches_and_caller_secrets_are_rejected_before_mutation() {
    let retired = PivSlot::retired(1).expect("retired slot");
    for grant_override in [
        GrantOverride {
            token_serial: Some("wrong-serial".into()),
            ..GrantOverride::default()
        },
        GrantOverride {
            station_id: Some("wrong-station".into()),
            ..GrantOverride::default()
        },
        GrantOverride {
            operation: Some(Operation::PivDeleteKey),
            ..GrantOverride::default()
        },
        GrantOverride {
            piv_slot: Some(u32::from(PivSlot::AUTHENTICATION.byte())),
            ..GrantOverride::default()
        },
        GrantOverride {
            key_id: Some("untrusted-key".into()),
            ..GrantOverride::default()
        },
    ] {
        let (mock, credentials) = mock_service();
        let backend = Arc::new(FakeAuthority::new());
        backend.set_grant_override(grant_override);
        let service = agent_service(credentials, Some(backend), None);
        let id = DeviceId("mock-yubikey-12345678".into());
        let status = Agent::generate_piv_key(
            &service,
            with_caller(Request::new(generate_request(retired, managed_token()))),
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(matches!(
            error_from_status(&status),
            sigil_core::CredentialError::OperationUnauthorized(_)
        ));
        assert!(!mock.has_key_in_slot(&id, retired).unwrap());
    }

    let (mock, credentials) = mock_service();
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    let mut request = generate_request(retired, managed_token());
    request.management_key = default_management_key();
    request.management_key_algorithm = v1::ManagementKeyAlgorithm::Aes192 as i32;
    let status = Agent::generate_piv_key(&service, with_caller(Request::new(request)))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(backend.authorize_calls.load(Ordering::SeqCst), 0);
    assert!(
        !mock
            .has_key_in_slot(&DeviceId("mock-yubikey-12345678".into()), retired)
            .unwrap()
    );

    let status = Agent::change_piv_puk(
        &service,
        with_caller(Request::new(v1::ChangePivPukRequest {
            id: "mock-yubikey-12345678".into(),
            expected_serial: TOKEN_SERIAL.into(),
            old_puk: b"12345678".to_vec(),
            new_puk: Vec::new(),
            managed: managed_token(),
        })),
    )
    .await
    .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    let status = Agent::change_piv_management_key(
        &service,
        with_caller(Request::new(v1::ChangePivManagementKeyRequest {
            id: "mock-yubikey-12345678".into(),
            expected_serial: TOKEN_SERIAL.into(),
            current_management_key: Vec::new(),
            current_algorithm: v1::ManagementKeyAlgorithm::Aes192 as i32,
            new_algorithm: v1::ManagementKeyAlgorithm::Unspecified as i32,
            new_management_key: Vec::new(),
            managed: managed_token(),
        })),
    )
    .await
    .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    let status = Agent::unblock_piv_pin(
        &service,
        with_caller(Request::new(v1::UnblockPivPinRequest {
            id: "mock-yubikey-12345678".into(),
            expected_serial: TOKEN_SERIAL.into(),
            puk: b"12345678".to_vec(),
            new_pin: b"654321".to_vec(),
            managed: managed_token(),
        })),
    )
    .await
    .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(backend.authorize_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn managed_backend_errors_map_and_missing_backend_is_unavailable() {
    let (mock, credentials) = mock_service();
    let backend = Arc::new(FakeAuthority::new());
    backend.fail_authorize_with(Status::permission_denied("managed operation denied"));
    let service = agent_service(credentials, Some(backend), None);
    let retired = PivSlot::retired(1).unwrap();
    let status = Agent::generate_piv_key(
        &service,
        with_caller(Request::new(generate_request(retired, managed_token()))),
    )
    .await
    .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        error_from_status(&status),
        sigil_core::CredentialError::BackendRejected("managed operation denied".into())
    );
    assert!(
        !mock
            .has_key_in_slot(&DeviceId("mock-yubikey-12345678".into()), retired)
            .unwrap()
    );

    let (mock, credentials) = mock_service();
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    let mut empty_token = managed_token().unwrap();
    empty_token.access_token.clear();
    let status = Agent::generate_piv_key(
        &service,
        with_caller(Request::new(generate_request(retired, Some(empty_token)))),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error_from_status(&status),
        sigil_core::CredentialError::BackendRejected("managed access token is required".into())
    );
    assert_eq!(backend.authorize_calls.load(Ordering::SeqCst), 0);
    assert!(
        !mock
            .has_key_in_slot(&DeviceId("mock-yubikey-12345678".into()), retired)
            .unwrap()
    );

    let (_mock, credentials) = mock_service();
    let service = agent_service(credentials, None, None);
    let status = Agent::initialize_managed_piv(
        &service,
        with_caller(Request::new(v1::InitializeManagedPivRequest {
            id: "mock-yubikey-12345678".into(),
            expected_serial: TOKEN_SERIAL.into(),
            managed: managed_token(),
        })),
    )
    .await
    .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert!(matches!(
        error_from_status(&status),
        sigil_core::CredentialError::BackendUnavailable(_)
    ));
}

#[tokio::test]
async fn managed_puk_rotation_and_initialization_complete_with_correct_outcomes() {
    let (mock, credentials) = mock_service();
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    let id = DeviceId("mock-yubikey-12345678".into());
    Agent::change_piv_puk(
        &service,
        with_caller(Request::new(v1::ChangePivPukRequest {
            id: id.0.clone(),
            expected_serial: TOKEN_SERIAL.into(),
            old_puk: Vec::new(),
            new_puk: Vec::new(),
            managed: managed_token(),
        })),
    )
    .await
    .expect("managed PUK rotation");
    assert!(backend.completions()[0].1);
    let new_puk = PivPuk::new(b"87654321".to_vec()).unwrap();
    let new_pin = PivPin::new(b"654321".to_vec()).unwrap();
    mock.unblock_pin(&id, TOKEN_SERIAL, &new_puk, &new_pin)
        .expect("mock card uses the released PUK");

    let (mock, credentials) = mock_service();
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    Agent::change_piv_management_key(
        &service,
        with_caller(Request::new(v1::ChangePivManagementKeyRequest {
            id: "mock-yubikey-12345678".into(),
            expected_serial: TOKEN_SERIAL.into(),
            current_management_key: Vec::new(),
            current_algorithm: v1::ManagementKeyAlgorithm::Unspecified as i32,
            new_algorithm: v1::ManagementKeyAlgorithm::Unspecified as i32,
            new_management_key: Vec::new(),
            managed: managed_token(),
        })),
    )
    .await
    .expect("managed management-key rotation");
    assert!(backend.completions()[0].1);
    let info = mock.piv_info(&id).unwrap();
    assert_eq!(info.management_key.unwrap().algorithm, PivAlgorithm::Aes256);
    let rotated_key = ManagementKey::new(ManagementKeyAlgorithm::Aes256, vec![0x42; 32]).unwrap();
    mock.generate_key(
        &id,
        TOKEN_SERIAL,
        &rotated_key,
        PivKeyConfiguration {
            slot: PivSlot::retired(2).unwrap(),
            algorithm: PivKeyAlgorithm::EccP256,
            pin_policy: PinPolicy::Once,
            touch_policy: TouchPolicy::Never,
        },
    )
    .expect("mock card uses rotated management key");

    let (mock, credentials) = mock_service();
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    Agent::initialize_managed_piv(
        &service,
        with_caller(Request::new(v1::InitializeManagedPivRequest {
            id: "mock-yubikey-12345678".into(),
            expected_serial: TOKEN_SERIAL.into(),
            managed: managed_token(),
        })),
    )
    .await
    .expect("managed initialization");
    assert!(backend.completions()[0].1);
    let info = mock.piv_info(&id).unwrap();
    assert_eq!(info.puk.unwrap().default_value, Some(false));
    let management = info.management_key.unwrap();
    assert_eq!(management.algorithm, PivAlgorithm::Aes256);
    assert_eq!(management.default_value, Some(false));
    let key = ManagementKey::new(ManagementKeyAlgorithm::Aes256, vec![0x42; 32]).unwrap();
    mock.generate_key(
        &id,
        TOKEN_SERIAL,
        &key,
        PivKeyConfiguration {
            slot: PivSlot::retired(2).unwrap(),
            algorithm: PivKeyAlgorithm::EccP256,
            pin_policy: PinPolicy::Once,
            touch_policy: TouchPolicy::Never,
        },
    )
    .expect("mock card uses the released management key");
}

#[tokio::test]
async fn unified_managed_rotation_rpc_completes_puk_rotation() {
    let (mock, credentials) = mock_service();
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    Agent::rotate_managed_piv_secret(
        &service,
        with_caller(Request::new(v1::RotateManagedPivSecretRequest {
            id: "mock-yubikey-12345678".into(),
            expected_serial: TOKEN_SERIAL.into(),
            managed: managed_token(),
            kind: v1::ManagedSecretKind::Puk as i32,
        })),
    )
    .await
    .expect("managed PUK rotation RPC");
    assert!(backend.completions()[0].1);
    let id = DeviceId("mock-yubikey-12345678".into());
    let new_puk = PivPuk::new(b"87654321".to_vec()).unwrap();
    let new_pin = PivPin::new(b"654321".to_vec()).unwrap();
    mock.unblock_pin(&id, TOKEN_SERIAL, &new_puk, &new_pin)
        .expect("unified managed PUK rotation was applied");
}

#[tokio::test]
async fn managed_rotation_with_incorrect_current_puk_is_abandoned() {
    let (mock, credentials) = mock_service();
    let id = DeviceId("mock-yubikey-12345678".into());
    let original = PivPuk::new(b"12345678".to_vec()).unwrap();
    let changed = PivPuk::new(b"00000000".to_vec()).unwrap();
    mock.change_puk(&id, TOKEN_SERIAL, &original, &changed)
        .unwrap();
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    let status = Agent::change_piv_puk(
        &service,
        with_caller(Request::new(v1::ChangePivPukRequest {
            id: id.0.clone(),
            expected_serial: TOKEN_SERIAL.into(),
            old_puk: Vec::new(),
            new_puk: Vec::new(),
            managed: managed_token(),
        })),
    )
    .await
    .unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(!backend.completions()[0].1);
    let actual_puk = PivPuk::new(b"00000000".to_vec()).unwrap();
    let new_pin = PivPin::new(b"654321".to_vec()).unwrap();
    mock.unblock_pin(&id, TOKEN_SERIAL, &actual_puk, &new_pin)
        .expect("failed managed rotation did not change the PUK");
}

#[tokio::test]
async fn initialize_not_default_and_rollback_outcomes_complete_safely() {
    let (mock, credentials) = mock_service();
    let id = DeviceId("mock-yubikey-12345678".into());
    let factory_puk = PivPuk::new(b"12345678".to_vec()).unwrap();
    let changed_puk = PivPuk::new(b"00000000".to_vec()).unwrap();
    mock.change_puk(&id, TOKEN_SERIAL, &factory_puk, &changed_puk)
        .unwrap();
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    let status = Agent::initialize_managed_piv(
        &service,
        with_caller(Request::new(v1::InitializeManagedPivRequest {
            id: id.0.clone(),
            expected_serial: TOKEN_SERIAL.into(),
            managed: managed_token(),
        })),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error_from_status(&status),
        sigil_core::CredentialError::PivNotFactoryDefault
    );
    assert!(!backend.completions()[0].1);
    assert_eq!(
        mock.piv_info(&id)
            .unwrap()
            .management_key
            .unwrap()
            .default_value,
        Some(true)
    );

    let (mock, credentials) = mock_service();
    mock.inject_managed_initialize_puk_failure(false);
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    assert!(
        Agent::initialize_managed_piv(
            &service,
            with_caller(Request::new(v1::InitializeManagedPivRequest {
                id: "mock-yubikey-12345678".into(),
                expected_serial: TOKEN_SERIAL.into(),
                managed: managed_token(),
            })),
        )
        .await
        .is_err()
    );
    assert!(!backend.completions()[0].1);
    let info = mock.piv_info(&id).unwrap();
    assert_eq!(info.puk.unwrap().default_value, Some(true));
    assert_eq!(info.management_key.unwrap().default_value, Some(true));

    let (mock, credentials) = mock_service();
    mock.inject_managed_initialize_puk_failure(true);
    let backend = Arc::new(FakeAuthority::new());
    let service = agent_service(credentials, Some(backend.clone()), None);
    let status = Agent::initialize_managed_piv(
        &service,
        with_caller(Request::new(v1::InitializeManagedPivRequest {
            id: "mock-yubikey-12345678".into(),
            expected_serial: TOKEN_SERIAL.into(),
            managed: managed_token(),
        })),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error_from_status(&status),
        sigil_core::CredentialError::ManagedRotationIncomplete(_)
    ));
    assert!(backend.completions().is_empty());
    let info = mock.piv_info(&id).unwrap();
    assert_eq!(info.puk.unwrap().default_value, Some(true));
    assert_eq!(info.management_key.unwrap().default_value, Some(false));
}

#[tokio::test]
async fn rotation_completion_is_persisted_and_can_resume_after_reopen() {
    let directory = tempfile::tempdir().expect("outbox directory");
    let outbox = Arc::new(AuditOutbox::open(directory.path()).expect("open outbox"));
    let (mock, credentials) = mock_service();
    let backend = Arc::new(FakeAuthority::new());
    backend.fail_next_completions(3);
    let service = agent_service(
        credentials,
        Some(backend.clone()),
        Some(Arc::clone(&outbox)),
    );
    let id = DeviceId("mock-yubikey-12345678".into());
    Agent::change_piv_puk(
        &service,
        with_caller(Request::new(v1::ChangePivPukRequest {
            id: id.0.clone(),
            expected_serial: TOKEN_SERIAL.into(),
            old_puk: Vec::new(),
            new_puk: Vec::new(),
            managed: managed_token(),
        })),
    )
    .await
    .expect("card change succeeds while completion is queued");
    let pending = outbox.pending_completions().unwrap();
    assert_eq!(pending.len(), 1);
    drop(service);
    drop(outbox);

    let reopened = AuditOutbox::open(directory.path()).expect("reopen outbox");
    sigil_agent::retry_pending_completions_once(backend.as_ref(), &reopened)
        .await
        .expect("retry persisted completion");
    assert!(reopened.pending_completions().unwrap().is_empty());
    assert_eq!(
        backend.completions(),
        vec![(pending[0].rotation_id.clone(), true)]
    );
    let new_puk = PivPuk::new(b"87654321".to_vec()).unwrap();
    let new_pin = PivPin::new(b"654321".to_vec()).unwrap();
    mock.unblock_pin(&id, TOKEN_SERIAL, &new_puk, &new_pin)
        .expect("mock PIV operation applied before the completion retry");
}
