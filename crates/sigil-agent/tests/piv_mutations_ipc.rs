use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use prost::Message;
use sigil_agent::{
    caller::CallerPolicy,
    grant::{GrantProvider, GrantRequest, GrantVerifier, Unconfigured},
    ipc,
    server::AgentService,
};
use sigil_app::CredentialService;
use sigil_client::AgentClient;
use sigil_core::{
    CredentialError, DeviceDiscovery, ManagementKey, ManagementKeyAlgorithm, PinPolicy,
    PivInspection, PivKeyAlgorithm, PivKeyConfiguration, PivManagement, PivPin, PivPuk, PivSlot,
    Result as CoreResult, TouchPolicy,
};
use sigil_mock::MockDiscovery;
use sigil_proto::v1::{OperationGrant, SignedGrant};
use tokio::{runtime::Builder, sync::oneshot};

static NEXT_ENDPOINT: AtomicU64 = AtomicU64::new(1);
const TEST_STATION: &str = "m4-test-station";
const TEST_SERIAL: &str = "12345678";
const DEFAULT_MGMT: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];
const P256_CERT: &[u8] = include_bytes!("../../sigil-mock/fixtures/piv-9a-p256.der");

struct TestServer {
    endpoint: String,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl TestServer {
    fn spawn(service: AgentService) -> Result<Self> {
        let endpoint = unique_endpoint();
        let (ready_sender, ready_receiver) = mpsc::channel();
        let (stop, shutdown) = oneshot::channel();
        let thread_endpoint = endpoint.clone();
        let thread = std::thread::spawn(move || {
            let runtime = Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("test runtime");
            let (ready, ready_receiver) = oneshot::channel();
            runtime.block_on(async move {
                let server = tokio::spawn(ipc::serve(
                    service,
                    thread_endpoint,
                    CallerPolicy {
                        require_console_session: false,
                    },
                    Some(ready),
                    shutdown,
                ));
                if ready_receiver.await.is_ok() {
                    let _ = ready_sender.send(());
                }
                let _ = server.await;
            });
        });
        ready_receiver
            .recv_timeout(Duration::from_secs(10))
            .context("test agent IPC endpoint did not start")?;
        Ok(Self {
            endpoint,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.endpoint);
    }
}

#[cfg(windows)]
fn unique_endpoint() -> String {
    format!(
        r"\\.\pipe\sigil-m4-ipc-{}-{}",
        std::process::id(),
        NEXT_ENDPOINT.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(unix)]
fn unique_endpoint() -> String {
    std::env::temp_dir()
        .join(format!(
            "sigil-m4-ipc-{}-{}.sock",
            std::process::id(),
            NEXT_ENDPOINT.fetch_add(1, Ordering::Relaxed)
        ))
        .to_string_lossy()
        .into_owned()
}

fn credentials(mock: Arc<MockDiscovery>) -> CredentialService {
    let discovery: Arc<dyn DeviceDiscovery> = mock.clone();
    let management: Arc<dyn PivManagement> = mock;
    CredentialService::new_with_piv_management(discovery, management)
}

fn default_management_key() -> ManagementKey {
    ManagementKey::new(ManagementKeyAlgorithm::Aes192, DEFAULT_MGMT.to_vec())
        .expect("default management key")
}

fn key_configuration(slot: PivSlot) -> PivKeyConfiguration {
    PivKeyConfiguration {
        slot,
        algorithm: PivKeyAlgorithm::EccP256,
        pin_policy: PinPolicy::Once,
        touch_policy: TouchPolicy::Never,
    }
}

#[derive(Clone, Copy)]
enum GrantMismatch {
    Serial,
    Slot,
}

struct TestGrantProvider {
    key: SigningKey,
    mismatch: std::sync::atomic::AtomicUsize,
    calls: AtomicUsize,
}

impl TestGrantProvider {
    fn new() -> Self {
        Self {
            key: SigningKey::from_bytes((&[23u8; 32]).into()).expect("test signing key"),
            mismatch: std::sync::atomic::AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
        }
    }

    fn set_mismatch(&self, mismatch: GrantMismatch) {
        self.mismatch.store(
            match mismatch {
                GrantMismatch::Serial => 1,
                GrantMismatch::Slot => 2,
            },
            Ordering::SeqCst,
        );
    }

    fn verifier(&self) -> GrantVerifier {
        GrantVerifier::new(HashMap::from([(
            "test-key".to_owned(),
            *self.key.verifying_key(),
        )]))
    }
}

impl GrantProvider for TestGrantProvider {
    fn obtain(
        &self,
        caller: &sigil_agent::caller::CallerIdentity,
        request: &GrantRequest,
    ) -> CoreResult<SignedGrant> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs() as i64;
        let mismatch = self.mismatch.load(Ordering::SeqCst);
        let mut token_serial = request.token_serial.clone();
        let mut piv_slot = request.piv_slot.map(u32::from).unwrap_or_default();
        if mismatch == 1 {
            token_serial = "other-serial".into();
        } else if mismatch == 2 {
            piv_slot = piv_slot.saturating_add(1);
        }
        let grant = OperationGrant {
            version: 1,
            grant_id: format!("test-grant-{now}-{}", self.calls.load(Ordering::SeqCst)),
            operation: request.operation as i32,
            subject: caller.os_user.clone(),
            station_id: request.station_id.clone(),
            token_serial,
            caller_os_user: request.caller_os_user.clone(),
            not_before_unix: now,
            expires_at_unix: now + 120,
            piv_slot,
        };
        let bytes = grant.encode_to_vec();
        let signature: Signature = self.key.sign(&bytes);
        Ok(SignedGrant {
            grant: bytes,
            signature: signature.to_der().as_bytes().to_vec(),
            key_id: "test-key".into(),
        })
    }
}

fn service(mock: Arc<MockDiscovery>, grants: Option<Arc<TestGrantProvider>>) -> AgentService {
    let credentials = credentials(mock);
    let mut service = AgentService::new(credentials, TEST_STATION).with_policy(CallerPolicy {
        require_console_session: false,
    });
    if let Some(grants) = grants {
        service = service.with_authorization(grants.clone(), Arc::new(grants.verifier()));
    } else {
        service = service.with_authorization(
            Arc::new(Unconfigured),
            Arc::new(GrantVerifier::new(HashMap::new())),
        );
    }
    service
}

#[test]
fn unconfigured_grants_deny_mutations_but_user_operations_use_ipc() -> Result<()> {
    let mock = Arc::new(MockDiscovery::with_example());
    let server = TestServer::spawn(service(mock.clone(), None))?;
    let client = AgentClient::connect(Some(&server.endpoint))?;
    let id = sigil_core::DeviceId("mock-yubikey-12345678".into());
    let serial = TEST_SERIAL;
    let management_key = default_management_key();
    let pin = PivPin::new(b"123456".to_vec())?;
    let new_pin = PivPin::new(b"654321".to_vec())?;
    let puk = PivPuk::new(b"12345678".to_vec())?;
    let new_puk = PivPuk::new(b"87654321".to_vec())?;

    assert!(matches!(
        client.generate_piv_key(
            &id,
            serial,
            &management_key,
            key_configuration(PivSlot::SIGNATURE),
        ),
        Err(CredentialError::OperationUnauthorized(_))
    ));
    assert!(matches!(
        client.change_piv_puk(&id, serial, &puk, &new_puk),
        Err(CredentialError::OperationUnauthorized(_))
    ));
    assert!(matches!(
        client.unblock_piv_pin(&id, serial, &puk, &new_pin),
        Err(CredentialError::OperationUnauthorized(_))
    ));
    assert!(matches!(
        client.change_piv_management_key(
            &id,
            serial,
            &management_key,
            ManagementKeyAlgorithm::Aes256
        ),
        Err(CredentialError::OperationUnauthorized(_))
    ));
    assert!(matches!(
        client.import_piv_certificate(
            &id,
            serial,
            &management_key,
            PivSlot::AUTHENTICATION,
            P256_CERT,
        ),
        Err(CredentialError::OperationUnauthorized(_))
    ));
    assert!(matches!(
        client.delete_piv_certificate(&id, serial, &management_key, PivSlot::AUTHENTICATION),
        Err(CredentialError::OperationUnauthorized(_))
    ));
    assert!(matches!(
        client.delete_piv_key(&id, serial, &management_key, PivSlot::SIGNATURE),
        Err(CredentialError::OperationUnauthorized(_))
    ));

    client.change_piv_pin(&id, serial, &pin, &new_pin)?;
    assert!(matches!(
        client.sign_piv_csr(
            &id,
            serial,
            &new_pin,
            PivSlot::AUTHENTICATION,
            "CN=No signer"
        ),
        Err(CredentialError::UnsupportedOperation(_))
    ));
    assert!(
        !client
            .attest_piv_key(&id, serial, PivSlot::AUTHENTICATION)?
            .attestation_der
            .is_empty()
    );
    assert_eq!(
        client.reset_piv(&id, "wrong-serial"),
        Err(CredentialError::DeviceMismatch)
    );
    assert_eq!(
        mock.piv_info(&id)?
            .pin
            .as_ref()
            .map(|status| status.default_value),
        Some(Some(false))
    );
    client.reset_piv(&id, serial)?;
    assert_eq!(
        mock.piv_info(&id)?
            .pin
            .as_ref()
            .map(|status| status.default_value),
        Some(Some(true))
    );
    Ok(())
}

#[test]
fn signed_grants_cover_mutation_serial_and_slot_over_ipc() -> Result<()> {
    let mock = Arc::new(MockDiscovery::with_example());
    let grants = Arc::new(TestGrantProvider::new());
    let server = TestServer::spawn(service(mock.clone(), Some(grants.clone())))?;
    let client = AgentClient::connect(Some(&server.endpoint))?;
    let id = sigil_core::DeviceId("mock-yubikey-12345678".into());
    let serial = TEST_SERIAL;
    let default_key = default_management_key();
    let puk = PivPuk::new(b"12345678".to_vec())?;
    let new_puk = PivPuk::new(b"87654321".to_vec())?;
    let new_pin = PivPin::new(b"654321".to_vec())?;
    client.change_piv_puk(&id, serial, &puk, &new_puk)?;
    client.unblock_piv_pin(&id, serial, &new_puk, &new_pin)?;

    let management_key = client.change_piv_management_key(
        &id,
        serial,
        &default_key,
        ManagementKeyAlgorithm::Aes256,
    )?;
    let spki = client.generate_piv_key(
        &id,
        serial,
        &management_key,
        key_configuration(PivSlot::SIGNATURE),
    )?;
    assert!(!spki.is_empty());
    assert!(
        !client
            .sign_piv_csr(&id, serial, &new_pin, PivSlot::SIGNATURE, "CN=Mock signer")?
            .is_empty()
    );

    client.import_piv_certificate(
        &id,
        serial,
        &management_key,
        PivSlot::AUTHENTICATION,
        P256_CERT,
    )?;
    client.delete_piv_certificate(&id, serial, &management_key, PivSlot::AUTHENTICATION)?;
    client.delete_piv_key(&id, serial, &management_key, PivSlot::SIGNATURE)?;
    let before_wrong_grants = mock
        .piv_slots(&id)?
        .into_iter()
        .find(|slot| slot.slot == PivSlot::KEY_MANAGEMENT)
        .expect("mock key-management slot")
        .key;

    grants.set_mismatch(GrantMismatch::Serial);
    assert!(matches!(
        client.generate_piv_key(
            &id,
            serial,
            &management_key,
            key_configuration(PivSlot::KEY_MANAGEMENT),
        ),
        Err(CredentialError::OperationUnauthorized(_))
    ));
    grants.set_mismatch(GrantMismatch::Slot);
    assert!(matches!(
        client.generate_piv_key(
            &id,
            serial,
            &management_key,
            key_configuration(PivSlot::KEY_MANAGEMENT),
        ),
        Err(CredentialError::OperationUnauthorized(_))
    ));
    assert_eq!(
        mock.piv_slots(&id)?
            .into_iter()
            .find(|slot| slot.slot == PivSlot::KEY_MANAGEMENT)
            .expect("mock key-management slot")
            .key,
        before_wrong_grants
    );
    assert_eq!(grants.calls.load(Ordering::SeqCst), 9);

    client.reset_piv(&id, serial)?;
    let info = mock.piv_info(&id)?;
    assert_eq!(
        info.pin.as_ref().and_then(|status| status.default_value),
        Some(true)
    );
    assert_eq!(
        info.puk.as_ref().and_then(|status| status.default_value),
        Some(true)
    );
    Ok(())
}
