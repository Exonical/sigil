use std::{collections::HashMap, pin::Pin, sync::Arc, time::Duration};

use futures_util::Stream;
use sigil_app::CredentialService;
use sigil_core::{
    Application, CredentialError, DeviceId, ManagedPivInitializationOutcome, ManagementKey,
    ManagementKeyAlgorithm, PinPolicy, PivKeyAlgorithm, PivKeyConfiguration, PivPin, PivPuk,
    PivSlot, Result as CoreResult, Secret, TouchPolicy,
};
use sigil_proto::{status_from_error, v1};
use tokio::{sync::mpsc, task};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

use crate::enrollment;
use crate::grant::{GrantExpectation, GrantProvider, GrantRequest, GrantVerifier, Unconfigured};
use crate::{
    audit_outbox::{AuditOutbox, PendingCompletion},
    backend::{ManagedAuthority, ManagedGrant, ManagedRequest, ManagedSecret, token_identity},
    caller::{self, CallerIdentity, CallerPolicy},
};

pub type WatchDevicesStream =
    Pin<Box<dyn Stream<Item = std::result::Result<v1::DeviceEvent, Status>> + Send + 'static>>;
pub type EnrollFingerprintStream = Pin<
    Box<
        dyn Stream<Item = std::result::Result<v1::EnrollFingerprintEvent, Status>> + Send + 'static,
    >,
>;

#[derive(Clone, Copy)]
struct ManagedCall<'a> {
    caller: &'a CallerIdentity,
    rpc: &'static str,
    device_id: &'a str,
    operation_name: &'static str,
    operation: v1::Operation,
    slot: Option<u8>,
    serial: &'a str,
    rotation_missing_detail: Option<&'static str>,
    abandon_failure: AbandonFailure,
}

/// What the caller sees when the backend cannot record an abandoned rotation.
#[derive(Clone, Copy)]
enum AbandonFailure {
    /// Return the completion error instead of the card or argument status.
    ReportToCaller,
    /// Return the card or argument status and log the completion error.
    KeepCallerStatus,
}

enum ManagedCardOutcome<T> {
    Applied(T),
    NotApplied(Status),
    Partial,
}

enum ManagedRotationSecrets {
    Puk(PivPuk, PivPuk),
    ManagementKey(ManagementKey, ManagementKey),
}

#[derive(Clone)]
pub struct AgentService {
    credentials: CredentialService,
    station_id: String,
    policy: CallerPolicy,
    grant_provider: Arc<dyn GrantProvider>,
    grant_verifier: Arc<GrantVerifier>,
    backend: Option<Arc<dyn ManagedAuthority>>,
    audit_outbox: Option<Arc<AuditOutbox>>,
    issuing_cas: Vec<Vec<u8>>,
}

impl AgentService {
    pub fn new(credentials: CredentialService, station_id: impl Into<String>) -> Self {
        Self {
            credentials,
            station_id: station_id.into(),
            policy: CallerPolicy::production(),
            grant_provider: Arc::new(Unconfigured),
            grant_verifier: Arc::new(GrantVerifier::new(HashMap::new())),
            backend: None,
            audit_outbox: None,
            issuing_cas: Vec::new(),
        }
    }

    pub fn with_issuing_cas(mut self, issuing_cas: Vec<Vec<u8>>) -> Self {
        self.issuing_cas = issuing_cas;
        self
    }

    pub fn with_authorization(
        mut self,
        grant_provider: Arc<dyn GrantProvider>,
        grant_verifier: Arc<GrantVerifier>,
    ) -> Self {
        self.grant_provider = grant_provider;
        self.grant_verifier = grant_verifier;
        self
    }

    pub fn with_backend(mut self, backend: Arc<dyn ManagedAuthority>) -> Self {
        self.backend = Some(backend);
        self
    }

    pub fn with_audit_outbox(mut self, audit_outbox: Arc<AuditOutbox>) -> Self {
        self.audit_outbox = Some(audit_outbox);
        self
    }

    pub fn with_policy(mut self, policy: CallerPolicy) -> Self {
        self.policy = policy;
        self
    }

    fn caller<T>(
        &self,
        request: &Request<T>,
        rpc: &'static str,
        device_id: &str,
    ) -> std::result::Result<CallerIdentity, Status> {
        let identity = request
            .extensions()
            .get::<CallerIdentity>()
            .cloned()
            .unwrap_or_else(CallerIdentity::rejected);
        if let Err(error) = caller::authorize(&identity, self.policy) {
            let status = status_from_error(&error);
            audit_static(&identity, rpc, device_id, false, Some(&status));
            return Err(status);
        }
        Ok(identity)
    }

    async fn ensure_device_serial(&self, id: &DeviceId) -> std::result::Result<(), Status> {
        let credentials = self.credentials.clone();
        let device_id = id.clone();
        let info = blocking(move || credentials.device(&device_id)).await?;
        if info.serial.is_some() {
            Ok(())
        } else {
            Err(status_from_error(&CredentialError::OperationUnauthorized(
                "the device serial number is unavailable".into(),
            )))
        }
    }

    fn caller_piv<T>(
        &self,
        request: &Request<T>,
        rpc: &'static str,
        device_id: &str,
        operation: &'static str,
        slot: Option<u8>,
    ) -> std::result::Result<CallerIdentity, Status> {
        let identity = request
            .extensions()
            .get::<CallerIdentity>()
            .cloned()
            .unwrap_or_else(CallerIdentity::rejected);
        if let Err(error) = caller::authorize(&identity, self.policy) {
            let status = status_from_error(&error);
            audit_piv::<()>(
                &identity,
                rpc,
                device_id,
                operation,
                slot,
                "",
                None,
                &Err(status.clone()),
            );
            return Err(status);
        }
        Ok(identity)
    }

    fn caller_device<T>(
        &self,
        request: &Request<T>,
        rpc: &'static str,
        device_id: &str,
        operation: &'static str,
    ) -> std::result::Result<CallerIdentity, Status> {
        let identity = request
            .extensions()
            .get::<CallerIdentity>()
            .cloned()
            .unwrap_or_else(CallerIdentity::rejected);
        if let Err(error) = caller::authorize(&identity, self.policy) {
            let status = status_from_error(&error);
            audit_device::<()>(
                &identity,
                rpc,
                device_id,
                operation,
                "",
                &Err(status.clone()),
            );
            return Err(status);
        }
        Ok(identity)
    }

    async fn device_serial(&self, id: &DeviceId) -> std::result::Result<String, Status> {
        let credentials = self.credentials.clone();
        let device_id = id.clone();
        let device = blocking(move || credentials.device(&device_id)).await?;
        device.serial.ok_or_else(|| {
            status_from_error(&CredentialError::OperationUnauthorized(
                "the device serial number is unavailable".into(),
            ))
        })
    }

    async fn ensure_expected_serial(
        &self,
        id: &DeviceId,
        expected_serial: &str,
    ) -> std::result::Result<String, Status> {
        let actual = self.device_serial(id).await?;
        if expected_serial.is_empty() || expected_serial != actual {
            return Err(status_from_error(&CredentialError::DeviceMismatch));
        }
        Ok(actual)
    }

    async fn preflight_device_serial(
        &self,
        caller: &CallerIdentity,
        rpc: &'static str,
        device_id: &str,
        operation: &'static str,
        expected_serial: &str,
    ) -> std::result::Result<String, Status> {
        let id = DeviceId(device_id.to_owned());
        match self.ensure_expected_serial(&id, expected_serial).await {
            Ok(serial) => Ok(serial),
            Err(status) => {
                audit_device::<()>(
                    caller,
                    rpc,
                    device_id,
                    operation,
                    expected_serial,
                    &Err(status.clone()),
                );
                Err(status)
            }
        }
    }

    async fn preflight_piv_serial(
        &self,
        caller: &CallerIdentity,
        rpc: &'static str,
        device_id: &str,
        operation: &'static str,
        slot: Option<u8>,
        expected_serial: &str,
    ) -> std::result::Result<String, Status> {
        let id = DeviceId(device_id.to_owned());
        match self.ensure_expected_serial(&id, expected_serial).await {
            Ok(serial) => Ok(serial),
            Err(status) => {
                audit_piv::<()>(
                    caller,
                    rpc,
                    device_id,
                    operation,
                    slot,
                    expected_serial,
                    None,
                    &Err(status.clone()),
                );
                Err(status)
            }
        }
    }

    #[allow(dead_code)] // used by escrow-backed agent operations
    async fn authorize_piv_grant(
        &self,
        caller: &CallerIdentity,
        id: &DeviceId,
        expected_serial: &str,
        operation: v1::Operation,
        slot: Option<u8>,
    ) -> std::result::Result<PivGrantContext, Status> {
        let serial = self.ensure_expected_serial(id, expected_serial).await?;
        let request = GrantRequest {
            operation,
            station_id: self.station_id.clone(),
            token_serial: serial.clone(),
            caller_os_user: caller.os_user.clone(),
            piv_slot: slot,
        };
        let signed = self
            .grant_provider
            .obtain(caller, &request)
            .map_err(|error| status_from_error(&error))?;
        let expectation = GrantExpectation {
            operation,
            station_id: self.station_id.clone(),
            token_serial: serial.clone(),
            caller_os_user: Some(caller.os_user.clone()),
            piv_slot: slot,
        };
        let grant = self
            .grant_verifier
            .verify(&signed, &expectation, crate::grant::now_unix())
            .map_err(|error| status_from_error(&error))?;
        Ok(PivGrantContext {
            serial,
            grant_id: grant.grant_id,
        })
    }

    async fn authorize_managed(
        &self,
        caller: &CallerIdentity,
        device_id: &str,
        serial: &str,
        operation: v1::Operation,
        slot: Option<u8>,
        mut managed: v1::ManagedAuthorization,
    ) -> std::result::Result<(ManagedGrant, String), Status> {
        let access_token = Zeroizing::new(std::mem::take(&mut managed.access_token));
        let Some(backend) = &self.backend else {
            return Err(status_from_error(&CredentialError::BackendUnavailable(
                "backend is not configured".into(),
            )));
        };
        if access_token.is_empty() {
            return Err(status_from_error(&CredentialError::BackendRejected(
                "managed access token is required".into(),
            )));
        }
        if access_token.len() > 16 * 1024 {
            return Err(Status::invalid_argument(
                "managed access token exceeds 16 KiB",
            ));
        }
        let id = DeviceId(device_id.to_owned());
        let credentials = self.credentials.clone();
        let device = blocking(move || credentials.device(&id)).await?;
        let Some((vendor, token_serial)) = token_identity(&device) else {
            return Err(status_from_error(&CredentialError::OperationUnauthorized(
                "the device vendor or serial number is unavailable".into(),
            )));
        };
        if token_serial != serial {
            return Err(status_from_error(&CredentialError::DeviceMismatch));
        }
        let authorization = backend
            .authorize(ManagedRequest {
                access_token,
                operation,
                vendor,
                serial: token_serial.clone(),
                caller_os_user: caller.os_user.clone(),
                piv_slot: slot,
            })
            .await
            .map_err(map_backend_status)?;
        let expected = GrantExpectation {
            operation,
            station_id: self.station_id.clone(),
            token_serial,
            caller_os_user: Some(caller.os_user.clone()),
            piv_slot: slot,
        };
        let grant_id = match self.grant_verifier.verify(
            &authorization.signed_grant,
            &expected,
            crate::grant::now_unix(),
        ) {
            Ok(grant) => grant.grant_id,
            Err(error) => {
                if let Some(rotation_id) = authorization.rotation_id.as_deref()
                    && self.complete_rotation(rotation_id, false).await.is_err()
                {
                    tracing::warn!(
                        target: "sigil::agent",
                        rotation_id,
                        "could not abandon an invalid managed grant rotation"
                    );
                }
                return Err(status_from_error(&error));
            }
        };
        Ok((authorization, grant_id))
    }

    fn missing_managed_authorization_status(&self) -> Status {
        if self.backend.is_none() {
            status_from_error(&CredentialError::BackendUnavailable(
                "backend is not configured".into(),
            ))
        } else {
            status_from_error(&CredentialError::BackendRejected(
                "managed authorization is required".into(),
            ))
        }
    }

    async fn complete_rotation(
        &self,
        rotation_id: &str,
        applied: bool,
    ) -> std::result::Result<(), Status> {
        let Some(backend) = &self.backend else {
            return Err(status_from_error(&CredentialError::BackendUnavailable(
                "backend is not configured".into(),
            )));
        };
        let mut last_error = None;
        for delay in [
            Duration::ZERO,
            Duration::from_millis(100),
            Duration::from_millis(400),
        ] {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            match backend.complete_rotation(rotation_id, applied).await {
                Ok(()) => return Ok(()),
                Err(error)
                    if matches!(
                        error.code(),
                        tonic::Code::Unavailable
                            | tonic::Code::DeadlineExceeded
                            | tonic::Code::Unknown
                    ) =>
                {
                    last_error = Some(error);
                }
                Err(error) => return Err(map_backend_status(error)),
            }
        }
        if let Some(outbox) = &self.audit_outbox {
            outbox
                .enqueue_completion(PendingCompletion {
                    rotation_id: rotation_id.to_owned(),
                    applied,
                    created_at_unix_ms: crate::backend::current_unix_millis(),
                })
                .map_err(|_| {
                    Status::unavailable("could not persist pending rotation completion")
                })?;
            tracing::warn!(
                target: "sigil::agent",
                rotation_id,
                applied,
                "backend rotation completion will be retried in the background"
            );
            return Ok(());
        }
        Err(last_error.unwrap_or_else(|| {
            Status::unavailable("backend rotation completion could not be recorded")
        }))
    }

    async fn abandon_rotation(
        &self,
        call: ManagedCall<'_>,
        rotation_id: Option<&str>,
        policy: AbandonFailure,
        status: Status,
    ) -> Status {
        let Some(rotation_id) = rotation_id else {
            return status;
        };
        let Err(completion) = self.complete_rotation(rotation_id, false).await else {
            return status;
        };
        match policy {
            AbandonFailure::ReportToCaller => completion,
            AbandonFailure::KeepCallerStatus => {
                tracing::warn!(
                    target: "sigil::agent",
                    rpc = call.rpc,
                    rotation_id,
                    code = ?completion.code(),
                    "could not record an abandoned managed rotation"
                );
                status
            }
        }
    }

    async fn run_managed<T, S, Extract, CardOperation>(
        &self,
        call: ManagedCall<'_>,
        managed: v1::ManagedAuthorization,
        extract: Extract,
        card_operation: CardOperation,
    ) -> std::result::Result<T, Status>
    where
        T: Send + 'static,
        S: Send + 'static,
        Extract: FnOnce(&mut ManagedGrant) -> std::result::Result<S, Status> + Send,
        CardOperation: FnOnce(S) -> CoreResult<ManagedCardOutcome<T>> + Send + 'static,
    {
        let (mut grant, grant_id) = match self
            .authorize_managed(
                call.caller,
                call.device_id,
                call.serial,
                call.operation,
                call.slot,
                managed,
            )
            .await
        {
            Ok(authorization) => authorization,
            Err(status) => {
                audit_managed_call::<()>(call, None, None, &Err(status.clone()));
                return Err(status);
            }
        };
        let rotation_id = if let Some(detail) = call.rotation_missing_detail {
            match grant.rotation_id.take().filter(|id| !id.is_empty()) {
                Some(rotation_id) => Some(rotation_id),
                None => {
                    let status = Status::internal(detail);
                    audit_managed_call::<()>(call, Some(&grant_id), None, &Err(status.clone()));
                    return Err(status);
                }
            }
        } else {
            None
        };
        let extracted = extract(&mut grant);
        drop(grant);
        let arguments = match extracted {
            Ok(arguments) => arguments,
            Err(status) => {
                let status = self
                    .abandon_rotation(
                        call,
                        rotation_id.as_deref(),
                        AbandonFailure::KeepCallerStatus,
                        status,
                    )
                    .await;
                audit_managed_call::<()>(
                    call,
                    Some(&grant_id),
                    rotation_id.as_deref(),
                    &Err(status.clone()),
                );
                return Err(status);
            }
        };
        let result = blocking_core(move || card_operation(arguments)).await;
        match result {
            Ok(ManagedCardOutcome::Applied(value)) => {
                let result = if let Some(rotation_id) = rotation_id.as_deref() {
                    self.complete_rotation(rotation_id, true)
                        .await
                        .map(|()| value)
                } else {
                    Ok(value)
                };
                audit_managed_call(call, Some(&grant_id), rotation_id.as_deref(), &result);
                result
            }
            Ok(ManagedCardOutcome::NotApplied(status)) => {
                let status = self
                    .abandon_rotation(call, rotation_id.as_deref(), call.abandon_failure, status)
                    .await;
                audit_managed_call::<()>(
                    call,
                    Some(&grant_id),
                    rotation_id.as_deref(),
                    &Err(status.clone()),
                );
                Err(status)
            }
            Ok(ManagedCardOutcome::Partial) => {
                let rotation_id = rotation_id.expect("partial rotation requires a rotation ID");
                audit_rotation_unknown(
                    call.caller,
                    call.rpc,
                    call.device_id,
                    call.operation_name,
                    call.serial,
                    Some(&grant_id),
                    &rotation_id,
                );
                Err(status_from_error(
                    &CredentialError::ManagedRotationIncomplete(rotation_id),
                ))
            }
            Err(error) if rotation_id.is_some() && card_failure_is_definite(&error) => {
                let status = self
                    .abandon_rotation(
                        call,
                        rotation_id.as_deref(),
                        call.abandon_failure,
                        status_from_error(&error),
                    )
                    .await;
                audit_managed_call::<()>(
                    call,
                    Some(&grant_id),
                    rotation_id.as_deref(),
                    &Err(status.clone()),
                );
                Err(status)
            }
            Err(_) if rotation_id.is_some() => {
                let rotation_id = rotation_id.expect("rotation ID is present");
                audit_rotation_unknown(
                    call.caller,
                    call.rpc,
                    call.device_id,
                    call.operation_name,
                    call.serial,
                    Some(&grant_id),
                    &rotation_id,
                );
                Err(status_from_error(
                    &CredentialError::ManagedRotationIncomplete(rotation_id),
                ))
            }
            Err(error) => {
                let status = status_from_error(&error);
                audit_managed_call::<()>(call, Some(&grant_id), None, &Err(status.clone()));
                Err(status)
            }
        }
    }
}

#[allow(dead_code)] // used by escrow-backed agent operations
struct PivGrantContext {
    serial: String,
    grant_id: String,
}

fn map_backend_status(status: Status) -> Status {
    match status.code() {
        tonic::Code::Unauthenticated
        | tonic::Code::PermissionDenied
        | tonic::Code::FailedPrecondition => status_from_error(&CredentialError::BackendRejected(
            status.message().to_owned(),
        )),
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Unknown => {
            status_from_error(&CredentialError::BackendUnavailable(
                "backend connection or request failed".into(),
            ))
        }
        _ => status_from_error(&CredentialError::BackendRejected(
            status.message().to_owned(),
        )),
    }
}

fn required_secret(
    secret: Option<ManagedSecret>,
    detail: &'static str,
) -> std::result::Result<ManagedSecret, Status> {
    secret.ok_or_else(|| Status::internal(detail))
}

fn management_key_from_managed(
    mut secret: ManagedSecret,
) -> std::result::Result<ManagementKey, Status> {
    let algorithm = match secret.algorithm.to_ascii_lowercase().as_str() {
        "aes128" | "aes-128" => ManagementKeyAlgorithm::Aes128,
        "aes192" | "aes-192" => ManagementKeyAlgorithm::Aes192,
        "aes256" | "aes-256" => ManagementKeyAlgorithm::Aes256,
        _ => {
            return Err(Status::internal(
                "backend returned an unsupported management-key algorithm",
            ));
        }
    };
    let bytes = std::mem::take(&mut *secret.value);
    ManagementKey::new(algorithm, bytes)
        .map_err(|_| Status::internal("backend returned an invalid management-key value"))
}

fn puk_from_managed(mut secret: ManagedSecret) -> std::result::Result<PivPuk, Status> {
    let bytes = std::mem::take(&mut *secret.value);
    PivPuk::new(bytes).map_err(|_| Status::internal("backend returned an invalid PUK value"))
}

async fn blocking<T, F>(operation: F) -> std::result::Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> CoreResult<T> + Send + 'static,
{
    task::spawn_blocking(operation)
        .await
        .map_err(|error| Status::internal(format!("blocking agent task failed: {error}")))?
        .map_err(|error| status_from_error(&error))
}

async fn blocking_core<T, F>(operation: F) -> CoreResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> CoreResult<T> + Send + 'static,
{
    task::spawn_blocking(operation).await.map_err(|error| {
        CredentialError::BackendUnavailable(format!("PIV operation task failed: {error}"))
    })?
}

fn card_failure_is_definite(error: &CredentialError) -> bool {
    matches!(
        error,
        CredentialError::DeviceNotFound(_)
            | CredentialError::InventoryUnavailable
            | CredentialError::UnsupportedOperation(_)
            | CredentialError::PcscUnavailable(_)
            | CredentialError::InvalidSlot(_)
            | CredentialError::CardStatus(_)
            | CredentialError::PinIncorrect { .. }
            | CredentialError::PukIncorrect { .. }
            | CredentialError::PinBlocked
            | CredentialError::PukBlocked
            | CredentialError::ManagementKeyIncorrect
            | CredentialError::DeviceMismatch
            | CredentialError::PivUnavailable
            | CredentialError::PivFipsNotApproved
            | CredentialError::PivNotFactoryDefault
            | CredentialError::PinComplexity
            | CredentialError::PukComplexity
    )
}

fn audit<T>(
    caller: &CallerIdentity,
    rpc: &'static str,
    device_id: &str,
    result: &std::result::Result<T, Status>,
) {
    match result {
        Ok(_) => tracing::info!(
            target: "sigil::audit",
            caller_os_user = %caller.os_user,
            session_id = ?caller.session_id,
            pid = caller.pid,
            rpc,
            device_id,
            result = "ok"
        ),
        Err(status) => tracing::info!(
            target: "sigil::audit",
            caller_os_user = %caller.os_user,
            session_id = ?caller.session_id,
            pid = caller.pid,
            rpc,
            device_id,
            result = "error",
            code = ?status.code()
        ),
    }
}

/// Holds a managed authorization and zeroizes its access token when dropped, on every return path.
struct AuthorizationGuard(v1::ManagedAuthorization);

impl Drop for AuthorizationGuard {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0.access_token);
    }
}

fn with_caller<T>(message: T, caller: &CallerIdentity) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(caller.clone());
    request
}

impl AgentService {
    async fn backend_profiles(
        &self,
        device_id: &str,
        managed: &v1::ManagedAuthorization,
    ) -> std::result::Result<
        (
            String,
            String,
            sigil_proto::backend::v1::ListProfilesResponse,
        ),
        Status,
    > {
        let backend = self.backend.clone().ok_or_else(|| {
            status_from_error(&CredentialError::BackendUnavailable(
                "backend is not configured".into(),
            ))
        })?;
        if managed.access_token.is_empty() {
            return Err(status_from_error(&CredentialError::BackendRejected(
                "managed access token is required".into(),
            )));
        }
        let id = DeviceId(device_id.to_owned());
        let credentials = self.credentials.clone();
        let info = blocking(move || credentials.device(&id)).await?;
        let (vendor, serial) = token_identity(&info).ok_or_else(|| {
            status_from_error(&CredentialError::OperationUnauthorized(
                "the device serial number is unavailable".into(),
            ))
        })?;
        let profiles = backend
            .list_certificate_profiles(sigil_proto::backend::v1::ListProfilesRequest {
                access_token: managed.access_token.clone(),
                token_vendor: vendor.clone(),
                token_serial: serial.clone(),
            })
            .await?;
        Ok((vendor, serial, profiles))
    }

    async fn enroll_certificate(
        &self,
        caller: &CallerIdentity,
        device_id: &str,
        mut input: v1::EnrollPivCertificateRequest,
    ) -> std::result::Result<v1::EnrollPivCertificateResponse, Status> {
        let managed = AuthorizationGuard(input.managed.take().ok_or_else(|| {
            Status::invalid_argument("managed authorization is required for enrollment")
        })?);
        let pin = Zeroizing::new(std::mem::take(&mut input.pin));
        let serial = input.expected_serial.clone();
        let (vendor, token_serial, profiles) = self.backend_profiles(device_id, &managed.0).await?;
        let profile = profiles
            .profiles
            .into_iter()
            .find(|profile| profile.name == input.profile)
            .ok_or_else(|| Status::invalid_argument("unknown certificate profile"))?;
        if profile.expected_subject.is_empty() {
            return Err(Status::failed_precondition(
                "the token has no assigned user for this certificate profile",
            ));
        }
        let slot_byte = profile.piv_slot;
        let generate = v1::GeneratePivKeyRequest {
            id: device_id.to_owned(),
            expected_serial: serial.clone(),
            management_key: Vec::new(),
            management_key_algorithm: 0,
            slot_byte,
            algorithm: enrollment::key_algorithm_name(&profile.algorithm)? as i32,
            pin_policy: enrollment::pin_policy_name(&profile.pin_policy)? as i32,
            touch_policy: enrollment::touch_policy_name(&profile.touch_policy)? as i32,
            managed: Some(managed.0.clone()),
        };
        let spki = v1::agent_server::Agent::generate_piv_key(self, with_caller(generate, caller))
            .await?
            .into_inner()
            .subject_public_key_info;
        let attested = v1::agent_server::Agent::attest_piv_key(
            self,
            with_caller(
                v1::AttestPivKeyRequest {
                    id: device_id.to_owned(),
                    expected_serial: serial.clone(),
                    slot_byte,
                },
                caller,
            ),
        )
        .await?
        .into_inner();
        let attestation = sigil_client::attestation_from_response(&attested);
        let expected_serial = serial
            .parse::<u64>()
            .map_err(|_| Status::failed_precondition("the token serial is not numeric"))?;
        let expected_pin = pin_policy(enrollment::pin_policy_name(&profile.pin_policy)? as i32)
            .map_err(|error| status_from_error(&error))?;
        let expected_touch =
            touch_policy(enrollment::touch_policy_name(&profile.touch_policy)? as i32)
                .map_err(|error| status_from_error(&error))?;
        let expected_slot = piv_slot(slot_byte).map_err(|error| status_from_error(&error))?;
        sigil_yubikey::attestation::check_expected(
            &attestation.inspection,
            &sigil_yubikey::attestation::ExpectedAttestation {
                serial: expected_serial,
                slot: expected_slot,
                pin_policy: expected_pin,
                touch_policy: expected_touch,
                subject_public_key_info: &spki,
            },
        )
        .map_err(|reason| {
            Status::failed_precondition(format!("attestation rejected before issuance: {reason}"))
        })?;
        let csr_der = v1::agent_server::Agent::sign_piv_csr(
            self,
            with_caller(
                v1::SignPivCsrRequest {
                    id: device_id.to_owned(),
                    expected_serial: serial.clone(),
                    pin: pin.to_vec(),
                    slot_byte,
                    expected_public_key: spki.clone(),
                    subject_dn: format!(
                        "CN={}",
                        enrollment::escape_rdn_value(&profile.expected_subject)
                    ),
                },
                caller,
            ),
        )
        .await?
        .into_inner()
        .csr_der;
        drop(pin);
        let backend = self.backend.clone().ok_or_else(|| {
            status_from_error(&CredentialError::BackendUnavailable(
                "backend is not configured".into(),
            ))
        })?;
        let issued = backend
            .issue_certificate(sigil_proto::backend::v1::IssueCertificateRequest {
                access_token: managed.0.access_token.clone(),
                token_vendor: vendor,
                token_serial,
                caller_os_user: caller.os_user.clone(),
                profile: profile.name.clone(),
                csr_der,
                attestation_der: attested.attestation_der,
                attestation_intermediate_der: attested.intermediate_der,
            })
            .await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or_default();
        enrollment::verify_issued_chain(&issued.chain_der, &self.issuing_cas, &spki, now).map_err(
            |reason| status_from_error(&CredentialError::BackendRejected(reason.to_owned())),
        )?;
        let certificate_der = issued.chain_der[0].clone();
        v1::agent_server::Agent::import_piv_certificate(
            self,
            with_caller(
                v1::ImportPivCertificateRequest {
                    id: device_id.to_owned(),
                    expected_serial: serial,
                    expected_public_key: spki.clone(),
                    management_key: Vec::new(),
                    management_key_algorithm: 0,
                    slot_byte,
                    certificate_der: certificate_der.clone(),
                    managed: Some(managed.0.clone()),
                },
                caller,
            ),
        )
        .await?;
        Ok(v1::EnrollPivCertificateResponse {
            certificate_der,
            not_after_unix: issued.not_after_unix,
            subject: issued.subject,
            serial_number: issued.serial_number,
        })
    }
}

#[tonic::async_trait]
impl v1::agent_server::Agent for AgentService {
    type WatchDevicesStream = WatchDevicesStream;
    type EnrollFingerprintStream = EnrollFingerprintStream;

    async fn get_agent_info(
        &self,
        request: Request<v1::Empty>,
    ) -> std::result::Result<Response<v1::GetAgentInfoResponse>, Status> {
        let caller = self.caller(&request, "GetAgentInfo", "")?;
        let response = v1::GetAgentInfoResponse {
            protocol_version: 1,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            platform: std::env::consts::OS.into(),
            station_id: self.station_id.clone(),
            caller: Some(v1::Caller {
                os_user: caller.os_user.clone(),
                session_id: caller.session_id,
                pid: caller.pid,
            }),
        };
        audit_static(&caller, "GetAgentInfo", "", true, None);
        Ok(Response::new(response))
    }

    async fn list_devices(
        &self,
        request: Request<v1::Empty>,
    ) -> std::result::Result<Response<v1::ListDevicesResponse>, Status> {
        let caller = self.caller(&request, "ListDevices", "")?;
        let credentials = self.credentials.clone();
        let result = blocking(move || credentials.devices()).await;
        audit(&caller, "ListDevices", "", &result);
        Ok(Response::new(v1::ListDevicesResponse {
            devices: result?.iter().map(v1::DeviceInfo::from).collect(),
        }))
    }

    async fn get_device(
        &self,
        request: Request<v1::GetDeviceRequest>,
    ) -> std::result::Result<Response<v1::DeviceInfo>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "GetDevice", &device_id)?;
        let credentials = self.credentials.clone();
        let id = DeviceId(device_id.clone());
        let result = blocking(move || credentials.device(&id)).await;
        audit(&caller, "GetDevice", &device_id, &result);
        result.map(|device| Response::new((&device).into()))
    }

    async fn set_enabled_applications(
        &self,
        request: Request<v1::SetEnabledApplicationsRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let input = request.get_ref();
        let caller = self.caller_device(
            &request,
            "SetEnabledApplications",
            &input.id,
            "DEVICE_SET_ENABLED_APPLICATIONS",
        )?;
        let mut input = request.into_inner();
        let device_id = input.id.clone();
        let expected_serial = input.expected_serial.clone();
        let usb = match applications_from_proto(input.usb_enabled) {
            Ok(applications) => applications,
            Err(error) => {
                return Err(audit_device_error(
                    &caller,
                    "SetEnabledApplications",
                    &device_id,
                    "DEVICE_SET_ENABLED_APPLICATIONS",
                    &expected_serial,
                    error,
                ));
            }
        };
        let nfc = if input.set_nfc {
            match applications_from_proto(input.nfc_enabled) {
                Ok(applications) => Some(applications),
                Err(error) => {
                    return Err(audit_device_error(
                        &caller,
                        "SetEnabledApplications",
                        &device_id,
                        "DEVICE_SET_ENABLED_APPLICATIONS",
                        &expected_serial,
                        error,
                    ));
                }
            }
        } else {
            None
        };
        let mut lock_code_bytes = std::mem::take(&mut input.lock_code);
        let lock_code = (!lock_code_bytes.is_empty())
            .then(|| Secret::new(std::mem::take(&mut lock_code_bytes)));

        let serial = self
            .preflight_device_serial(
                &caller,
                "SetEnabledApplications",
                &device_id,
                "DEVICE_SET_ENABLED_APPLICATIONS",
                &expected_serial,
            )
            .await?;
        let credentials = self.credentials.clone();
        let id = DeviceId(device_id.clone());
        let expected = serial.clone();
        let result = blocking(move || {
            credentials.set_enabled_applications(
                &id,
                &expected,
                &usb,
                nfc.as_deref(),
                lock_code.as_ref(),
            )
        })
        .await;
        audit_device(
            &caller,
            "SetEnabledApplications",
            &device_id,
            "DEVICE_SET_ENABLED_APPLICATIONS",
            &serial,
            &result,
        );
        result.map(|()| Response::new(v1::Empty {}))
    }

    async fn watch_devices(
        &self,
        request: Request<v1::Empty>,
    ) -> std::result::Result<Response<Self::WatchDevicesStream>, Status> {
        let caller = self.caller(&request, "WatchDevices", "")?;
        let credentials = self.credentials.clone();
        let receiver = blocking(move || credentials.watch_devices()).await;
        audit(&caller, "WatchDevices", "", &receiver);
        let receiver = receiver?;
        let (sender, output) = mpsc::channel(64);
        task::spawn_blocking(move || {
            while !sender.is_closed() {
                match receiver.recv_timeout(std::time::Duration::from_millis(200)) {
                    Ok(event) => {
                        if sender
                            .blocking_send(Ok(v1::DeviceEvent::from(&event)))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(output))))
    }

    async fn get_fido_status(
        &self,
        request: Request<v1::DeviceRequest>,
    ) -> std::result::Result<Response<v1::FidoStatus>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "GetFidoStatus", &device_id)?;
        let credentials = self.credentials.clone();
        let id = DeviceId(device_id.clone());
        let result = blocking(move || credentials.fido_status(&id)).await;
        audit(&caller, "GetFidoStatus", &device_id, &result);
        result.map(|status| Response::new((&status).into()))
    }

    async fn list_discoverable_credentials(
        &self,
        request: Request<v1::PinRequest>,
    ) -> std::result::Result<Response<v1::DiscoverableCredentialList>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "ListDiscoverableCredentials", &device_id)?;
        let input = request.into_inner();
        let pin = Zeroizing::new(input.pin);
        let credentials = self.credentials.clone();
        let id = DeviceId(device_id.clone());
        let result = blocking(move || credentials.discoverable_credentials(&id, &pin)).await;
        audit(&caller, "ListDiscoverableCredentials", &device_id, &result);
        result.map(|entries| {
            Response::new(v1::DiscoverableCredentialList {
                credentials: entries
                    .iter()
                    .map(v1::DiscoverableCredential::from)
                    .collect(),
            })
        })
    }

    async fn list_fingerprints(
        &self,
        request: Request<v1::PinRequest>,
    ) -> std::result::Result<Response<v1::FingerprintList>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "ListFingerprints", &device_id)?;
        let input = request.into_inner();
        let pin = Zeroizing::new(input.pin);
        let credentials = self.credentials.clone();
        let id = DeviceId(device_id.clone());
        let result = blocking(move || credentials.fingerprints(&id, &pin)).await;
        audit(&caller, "ListFingerprints", &device_id, &result);
        result.map(|fingerprints| {
            Response::new(v1::FingerprintList {
                fingerprints: fingerprints.iter().map(v1::Fingerprint::from).collect(),
            })
        })
    }

    async fn enroll_fingerprint(
        &self,
        request: Request<v1::EnrollFingerprintRequest>,
    ) -> std::result::Result<Response<Self::EnrollFingerprintStream>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "EnrollFingerprint", &device_id)?;
        let input = request.into_inner();
        let pin = Zeroizing::new(input.pin);
        let id = DeviceId(device_id.clone());
        self.ensure_device_serial(&id).await.inspect_err(|status| {
            audit_static(
                &caller,
                "EnrollFingerprint",
                &device_id,
                false,
                Some(status),
            );
        })?;
        let (sender, receiver) = mpsc::channel(32);
        let progress_sender = sender.clone();
        let credentials = self.credentials.clone();
        let audit_caller = caller.clone();
        let audit_id = device_id.clone();
        let job = task::spawn_blocking(move || {
            let result = credentials.enroll_fingerprint(&id, &pin, &mut |progress| {
                let event = v1::EnrollFingerprintEvent {
                    event: Some(v1::enroll_fingerprint_event::Event::Progress(
                        (&progress).into(),
                    )),
                };
                let _ = progress_sender.blocking_send(Ok(event));
            });
            match result {
                Ok(fingerprint) => {
                    let event = v1::EnrollFingerprintEvent {
                        event: Some(v1::enroll_fingerprint_event::Event::Result(
                            (&fingerprint).into(),
                        )),
                    };
                    let _ = progress_sender.blocking_send(Ok(event));
                    audit_static(&audit_caller, "EnrollFingerprint", &audit_id, true, None);
                }
                Err(error) => {
                    let status = status_from_error(&error);
                    let _ = progress_sender.blocking_send(Err(status.clone()));
                    audit_static(
                        &audit_caller,
                        "EnrollFingerprint",
                        &audit_id,
                        false,
                        Some(&status),
                    );
                }
            }
        });
        tokio::spawn(async move {
            if let Err(error) = job.await {
                let status = Status::internal(format!("blocking enrollment task failed: {error}"));
                let _ = sender.send(Err(status.clone())).await;
                audit_static(
                    &caller,
                    "EnrollFingerprint",
                    &device_id,
                    false,
                    Some(&status),
                );
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn remove_fingerprint(
        &self,
        request: Request<v1::RemoveFingerprintRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "RemoveFingerprint", &device_id)?;
        let input = request.into_inner();
        let pin = Zeroizing::new(input.pin);
        let id = DeviceId(device_id.clone());
        self.ensure_device_serial(&id).await.inspect_err(|status| {
            audit_static(
                &caller,
                "RemoveFingerprint",
                &device_id,
                false,
                Some(status),
            );
        })?;
        let credentials = self.credentials.clone();
        let fingerprint_id = input.fingerprint_id;
        let result =
            blocking(move || credentials.remove_fingerprint(&id, &pin, &fingerprint_id)).await;
        audit(&caller, "RemoveFingerprint", &device_id, &result);
        result.map(|_| Response::new(v1::Empty {}))
    }

    async fn get_piv_info(
        &self,
        request: Request<v1::DeviceRequest>,
    ) -> std::result::Result<Response<v1::PivInfo>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "GetPivInfo", &device_id)?;
        let credentials = self.credentials.clone();
        let id = DeviceId(device_id.clone());
        let result = blocking(move || credentials.piv_info(&id)).await;
        audit(&caller, "GetPivInfo", &device_id, &result);
        result.map(|info| Response::new((&info).into()))
    }

    async fn list_piv_slots(
        &self,
        request: Request<v1::DeviceRequest>,
    ) -> std::result::Result<Response<v1::PivSlotInfoList>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "ListPivSlots", &device_id)?;
        let credentials = self.credentials.clone();
        let id = DeviceId(device_id.clone());
        let result = blocking(move || credentials.piv_slots(&id)).await;
        audit(&caller, "ListPivSlots", &device_id, &result);
        result.map(|slots| {
            Response::new(v1::PivSlotInfoList {
                slots: slots.iter().map(v1::PivSlotInfo::from).collect(),
            })
        })
    }

    async fn get_piv_certificate(
        &self,
        request: Request<v1::GetPivCertificateRequest>,
    ) -> std::result::Result<Response<v1::GetPivCertificateResponse>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "GetPivCertificate", &device_id)?;
        let input = request.into_inner();
        let slot_byte: u8 = match input.slot_byte.try_into() {
            Ok(slot) => slot,
            Err(_) => {
                let status =
                    status_from_error(&CredentialError::InvalidSlot(input.slot_byte.to_string()));
                audit_static(
                    &caller,
                    "GetPivCertificate",
                    &device_id,
                    false,
                    Some(&status),
                );
                return Err(status);
            }
        };
        let Some(slot) = PivSlot::from_byte(slot_byte) else {
            let status = status_from_error(&CredentialError::InvalidSlot(slot_byte.to_string()));
            audit_static(
                &caller,
                "GetPivCertificate",
                &device_id,
                false,
                Some(&status),
            );
            return Err(status);
        };
        let credentials = self.credentials.clone();
        let id = DeviceId(device_id.clone());
        let result = blocking(move || credentials.piv_certificate(&id, slot)).await;
        audit(&caller, "GetPivCertificate", &device_id, &result);
        result.map(|certificate| match certificate {
            Some(certificate) => Response::new(v1::GetPivCertificateResponse {
                found: true,
                summary: Some((&certificate.summary).into()),
                der: certificate.der,
            }),
            None => Response::new(v1::GetPivCertificateResponse {
                found: false,
                summary: None,
                der: Vec::new(),
            }),
        })
    }

    async fn change_piv_pin(
        &self,
        request: Request<v1::ChangePivPinRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller =
            self.caller_piv(&request, "ChangePivPin", &device_id, "PIV_CHANGE_PIN", None)?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        let old_pin = match PivPin::new(std::mem::take(&mut input.old_pin)) {
            Ok(pin) => pin,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ChangePivPin",
                    &device_id,
                    "PIV_CHANGE_PIN",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let new_pin = match PivPin::new(std::mem::take(&mut input.new_pin)) {
            Ok(pin) => pin,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ChangePivPin",
                    &device_id,
                    "PIV_CHANGE_PIN",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let id = DeviceId(device_id.clone());
        let mut audit_serial = serial_hint.clone();
        let result = match self.ensure_expected_serial(&id, &serial_hint).await {
            Ok(serial) => {
                audit_serial = serial.clone();
                let credentials = self.credentials.clone();
                blocking(move || credentials.change_pin(&id, &serial, &old_pin, &new_pin)).await
            }
            Err(status) => Err(status),
        };
        audit_piv(
            &caller,
            "ChangePivPin",
            &device_id,
            "PIV_CHANGE_PIN",
            None,
            &audit_serial,
            None,
            &result,
        );
        result.map(|_| Response::new(v1::Empty {}))
    }

    async fn change_piv_puk(
        &self,
        request: Request<v1::ChangePivPukRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller =
            self.caller_piv(&request, "ChangePivPuk", &device_id, "PIV_CHANGE_PUK", None)?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        if let Some(managed) = input.managed.take() {
            if !input.old_puk.is_empty() || !input.new_puk.is_empty() {
                let status = Status::invalid_argument(
                    "old_puk and new_puk must be empty when managed authorization is supplied",
                );
                audit_managed::<()>(
                    &caller,
                    "ChangePivPuk",
                    &device_id,
                    "PIV_CHANGE_PUK",
                    None,
                    &serial_hint,
                    None,
                    None,
                    &Err(status.clone()),
                );
                return Err(status);
            }
            let serial = self
                .preflight_piv_serial(
                    &caller,
                    "ChangePivPuk",
                    &device_id,
                    "PIV_CHANGE_PUK",
                    None,
                    &serial_hint,
                )
                .await?;
            let credentials = self.credentials.clone();
            let id = DeviceId(device_id.clone());
            let expected_serial = serial.clone();
            return self
                .run_managed(
                    ManagedCall {
                        caller: &caller,
                        rpc: "ChangePivPuk",
                        device_id: &device_id,
                        operation_name: "PIV_CHANGE_PUK",
                        operation: v1::Operation::PivChangePuk,
                        slot: None,
                        serial: &serial,
                        rotation_missing_detail: Some("backend omitted the PUK rotation ID"),
                        abandon_failure: AbandonFailure::KeepCallerStatus,
                    },
                    managed,
                    |grant| {
                        let current = required_secret(
                            grant.current_puk.take(),
                            "backend omitted the current PUK",
                        )
                        .and_then(puk_from_managed)?;
                        let new =
                            required_secret(grant.new_puk.take(), "backend omitted the new PUK")
                                .and_then(puk_from_managed)?;
                        Ok((current, new))
                    },
                    move |(current, new)| {
                        credentials
                            .change_puk(&id, &expected_serial, &current, &new)
                            .map(|()| ManagedCardOutcome::Applied(Response::new(v1::Empty {})))
                    },
                )
                .await;
        }
        let old_puk = match PivPuk::new(std::mem::take(&mut input.old_puk)) {
            Ok(puk) => puk,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ChangePivPuk",
                    &device_id,
                    "PIV_CHANGE_PUK",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let new_puk = match PivPuk::new(std::mem::take(&mut input.new_puk)) {
            Ok(puk) => puk,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ChangePivPuk",
                    &device_id,
                    "PIV_CHANGE_PUK",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let id = DeviceId(device_id.clone());
        let serial = self
            .preflight_piv_serial(
                &caller,
                "ChangePivPuk",
                &device_id,
                "PIV_CHANGE_PUK",
                None,
                &serial_hint,
            )
            .await?;
        let credentials = self.credentials.clone();
        let expected_serial = serial.clone();
        let result =
            blocking(move || credentials.change_puk(&id, &expected_serial, &old_puk, &new_puk))
                .await;
        audit_piv(
            &caller,
            "ChangePivPuk",
            &device_id,
            "PIV_CHANGE_PUK",
            None,
            &serial,
            None,
            &result,
        );
        result.map(|_| Response::new(v1::Empty {}))
    }

    async fn unblock_piv_pin(
        &self,
        request: Request<v1::UnblockPivPinRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller_piv(
            &request,
            "UnblockPivPin",
            &device_id,
            "PIV_UNBLOCK_PIN",
            None,
        )?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        if let Some(managed) = input.managed.take() {
            if !input.puk.is_empty() {
                let status = Status::invalid_argument(
                    "puk must be empty when managed authorization is supplied",
                );
                audit_managed::<()>(
                    &caller,
                    "UnblockPivPin",
                    &device_id,
                    "PIV_UNBLOCK_PIN",
                    None,
                    &serial_hint,
                    None,
                    None,
                    &Err(status.clone()),
                );
                return Err(status);
            }
            let new_pin = match PivPin::new(std::mem::take(&mut input.new_pin)) {
                Ok(pin) => pin,
                Err(error) => {
                    return Err(audit_piv_error(
                        &caller,
                        "UnblockPivPin",
                        &device_id,
                        "PIV_UNBLOCK_PIN",
                        None,
                        &serial_hint,
                        None,
                        error,
                    ));
                }
            };
            let serial = self
                .preflight_piv_serial(
                    &caller,
                    "UnblockPivPin",
                    &device_id,
                    "PIV_UNBLOCK_PIN",
                    None,
                    &serial_hint,
                )
                .await?;
            let id = DeviceId(device_id.clone());
            let credentials = self.credentials.clone();
            let expected_serial = serial.clone();
            return self
                .run_managed(
                    ManagedCall {
                        caller: &caller,
                        rpc: "UnblockPivPin",
                        device_id: &device_id,
                        operation_name: "PIV_UNBLOCK_PIN",
                        operation: v1::Operation::PivUnblockPin,
                        slot: None,
                        serial: &serial,
                        rotation_missing_detail: None,
                        abandon_failure: AbandonFailure::KeepCallerStatus,
                    },
                    managed,
                    move |grant| {
                        let puk = required_secret(
                            grant.current_puk.take(),
                            "backend omitted the current PUK",
                        )
                        .and_then(puk_from_managed)?;
                        Ok((puk, new_pin))
                    },
                    move |(puk, new_pin)| {
                        credentials
                            .unblock_pin(&id, &expected_serial, &puk, &new_pin)
                            .map(|()| ManagedCardOutcome::Applied(Response::new(v1::Empty {})))
                    },
                )
                .await;
        }
        let puk = match PivPuk::new(std::mem::take(&mut input.puk)) {
            Ok(puk) => puk,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "UnblockPivPin",
                    &device_id,
                    "PIV_UNBLOCK_PIN",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let new_pin = match PivPin::new(std::mem::take(&mut input.new_pin)) {
            Ok(pin) => pin,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "UnblockPivPin",
                    &device_id,
                    "PIV_UNBLOCK_PIN",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let id = DeviceId(device_id.clone());
        let serial = self
            .preflight_piv_serial(
                &caller,
                "UnblockPivPin",
                &device_id,
                "PIV_UNBLOCK_PIN",
                None,
                &serial_hint,
            )
            .await?;
        let credentials = self.credentials.clone();
        let expected_serial = serial.clone();
        let result =
            blocking(move || credentials.unblock_pin(&id, &expected_serial, &puk, &new_pin)).await;
        audit_piv(
            &caller,
            "UnblockPivPin",
            &device_id,
            "PIV_UNBLOCK_PIN",
            None,
            &serial,
            None,
            &result,
        );
        result.map(|_| Response::new(v1::Empty {}))
    }

    async fn change_piv_management_key(
        &self,
        request: Request<v1::ChangePivManagementKeyRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller_piv(
            &request,
            "ChangePivManagementKey",
            &device_id,
            "PIV_CHANGE_MANAGEMENT_KEY",
            None,
        )?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        if let Some(managed) = input.managed.take() {
            if !input.current_management_key.is_empty()
                || !input.new_management_key.is_empty()
                || input.current_algorithm != v1::ManagementKeyAlgorithm::Unspecified as i32
                || input.new_algorithm != v1::ManagementKeyAlgorithm::Unspecified as i32
            {
                let status = Status::invalid_argument(
                    "management-key fields and algorithms must be empty when managed authorization is supplied",
                );
                audit_managed::<()>(
                    &caller,
                    "ChangePivManagementKey",
                    &device_id,
                    "PIV_CHANGE_MANAGEMENT_KEY",
                    None,
                    &serial_hint,
                    None,
                    None,
                    &Err(status.clone()),
                );
                return Err(status);
            }
            let serial = self
                .preflight_piv_serial(
                    &caller,
                    "ChangePivManagementKey",
                    &device_id,
                    "PIV_CHANGE_MANAGEMENT_KEY",
                    None,
                    &serial_hint,
                )
                .await?;
            let id = DeviceId(device_id.clone());
            let credentials = self.credentials.clone();
            let expected_serial = serial.clone();
            return self
                .run_managed(
                    ManagedCall {
                        caller: &caller,
                        rpc: "ChangePivManagementKey",
                        device_id: &device_id,
                        operation_name: "PIV_CHANGE_MANAGEMENT_KEY",
                        operation: v1::Operation::PivChangeManagementKey,
                        slot: None,
                        serial: &serial,
                        rotation_missing_detail: Some(
                            "backend omitted the management-key rotation ID",
                        ),
                        abandon_failure: AbandonFailure::KeepCallerStatus,
                    },
                    managed,
                    |grant| {
                        let current = required_secret(
                            grant.current_management_key.take(),
                            "backend omitted the current management key",
                        )
                        .and_then(management_key_from_managed)?;
                        let new = required_secret(
                            grant.new_management_key.take(),
                            "backend omitted the new management key",
                        )
                        .and_then(management_key_from_managed)?;
                        Ok((current, new))
                    },
                    move |(current, new)| {
                        credentials
                            .change_management_key(&id, &expected_serial, &current, &new)
                            .map(|()| ManagedCardOutcome::Applied(Response::new(v1::Empty {})))
                    },
                )
                .await;
        }
        let current_algorithm = match management_key_algorithm(input.current_algorithm) {
            Ok(algorithm) => algorithm,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ChangePivManagementKey",
                    &device_id,
                    "PIV_CHANGE_MANAGEMENT_KEY",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let new_algorithm = match management_key_algorithm(input.new_algorithm) {
            Ok(algorithm) => algorithm,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ChangePivManagementKey",
                    &device_id,
                    "PIV_CHANGE_MANAGEMENT_KEY",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let current = match ManagementKey::new(
            current_algorithm,
            std::mem::take(&mut input.current_management_key),
        ) {
            Ok(key) => key,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ChangePivManagementKey",
                    &device_id,
                    "PIV_CHANGE_MANAGEMENT_KEY",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let new_key = match ManagementKey::new(
            new_algorithm,
            std::mem::take(&mut input.new_management_key),
        ) {
            Ok(key) => key,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ChangePivManagementKey",
                    &device_id,
                    "PIV_CHANGE_MANAGEMENT_KEY",
                    None,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let id = DeviceId(device_id.clone());
        let serial = self
            .preflight_piv_serial(
                &caller,
                "ChangePivManagementKey",
                &device_id,
                "PIV_CHANGE_MANAGEMENT_KEY",
                None,
                &serial_hint,
            )
            .await?;
        let credentials = self.credentials.clone();
        let expected_serial = serial.clone();
        let result = blocking(move || {
            credentials.change_management_key(&id, &expected_serial, &current, &new_key)
        })
        .await;
        audit_piv(
            &caller,
            "ChangePivManagementKey",
            &device_id,
            "PIV_CHANGE_MANAGEMENT_KEY",
            None,
            &serial,
            None,
            &result,
        );
        result.map(|_| Response::new(v1::Empty {}))
    }

    async fn list_certificate_profiles(
        &self,
        request: Request<v1::ListCertificateProfilesRequest>,
    ) -> std::result::Result<Response<v1::ListCertificateProfilesResponse>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller_piv(
            &request,
            "ListCertificateProfiles",
            &device_id,
            "PIV_ENROLL",
            None,
        )?;
        let mut input = request.into_inner();
        let managed = input.managed.take().unwrap_or_default();
        let result =
            self.backend_profiles(&device_id, &managed)
                .await
                .and_then(|(_, _, profiles)| {
                    profiles
                        .profiles
                        .iter()
                        .map(enrollment::profile_message)
                        .collect::<std::result::Result<Vec<_>, Status>>()
                });
        let outcome = result.as_ref().map(|_| ()).map_err(Clone::clone);
        audit_piv(
            &caller,
            "ListCertificateProfiles",
            &device_id,
            "PIV_ENROLL",
            None,
            "",
            None,
            &outcome,
        );
        result.map(|profiles| Response::new(v1::ListCertificateProfilesResponse { profiles }))
    }

    async fn enroll_piv_certificate(
        &self,
        request: Request<v1::EnrollPivCertificateRequest>,
    ) -> std::result::Result<Response<v1::EnrollPivCertificateResponse>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller_piv(
            &request,
            "EnrollPivCertificate",
            &device_id,
            "PIV_ENROLL",
            None,
        )?;
        let input = request.into_inner();
        let serial = input.expected_serial.clone();
        let result = self.enroll_certificate(&caller, &device_id, input).await;
        let outcome = result.as_ref().map(|_| ()).map_err(Clone::clone);
        audit_piv(
            &caller,
            "EnrollPivCertificate",
            &device_id,
            "PIV_ENROLL",
            None,
            &serial,
            None,
            &outcome,
        );
        result.map(Response::new)
    }

    async fn generate_piv_key(
        &self,
        request: Request<v1::GeneratePivKeyRequest>,
    ) -> std::result::Result<Response<v1::GeneratePivKeyResponse>, Status> {
        let device_id = request.get_ref().id.clone();
        let slot_hint = u8::try_from(request.get_ref().slot_byte).ok();
        let caller = self.caller_piv(
            &request,
            "GeneratePivKey",
            &device_id,
            "PIV_GENERATE_KEY",
            slot_hint,
        )?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        let slot = match piv_slot(input.slot_byte) {
            Ok(slot) => slot,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "GeneratePivKey",
                    &device_id,
                    "PIV_GENERATE_KEY",
                    slot_hint,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let key_algorithm = match piv_key_algorithm(input.algorithm) {
            Ok(algorithm) => algorithm,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "GeneratePivKey",
                    &device_id,
                    "PIV_GENERATE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let pin_policy = match pin_policy(input.pin_policy) {
            Ok(policy) => policy,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "GeneratePivKey",
                    &device_id,
                    "PIV_GENERATE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let touch_policy = match touch_policy(input.touch_policy) {
            Ok(policy) => policy,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "GeneratePivKey",
                    &device_id,
                    "PIV_GENERATE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        if let Some(managed) = input.managed.take() {
            if !input.management_key.is_empty()
                || input.management_key_algorithm != v1::ManagementKeyAlgorithm::Unspecified as i32
            {
                let status = Status::invalid_argument(
                    "management_key and management_key_algorithm must be empty when managed authorization is supplied",
                );
                audit_managed::<()>(
                    &caller,
                    "GeneratePivKey",
                    &device_id,
                    "PIV_GENERATE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    None,
                    &Err(status.clone()),
                );
                return Err(status);
            }
            let serial = self
                .preflight_piv_serial(
                    &caller,
                    "GeneratePivKey",
                    &device_id,
                    "PIV_GENERATE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                )
                .await?;
            let id = DeviceId(device_id.clone());
            let credentials = self.credentials.clone();
            let expected_serial = serial.clone();
            return self
                .run_managed(
                    ManagedCall {
                        caller: &caller,
                        rpc: "GeneratePivKey",
                        device_id: &device_id,
                        operation_name: "PIV_GENERATE_KEY",
                        operation: v1::Operation::PivGenerateKey,
                        slot: Some(slot.byte()),
                        serial: &serial,
                        rotation_missing_detail: None,
                        abandon_failure: AbandonFailure::KeepCallerStatus,
                    },
                    managed,
                    |grant| {
                        required_secret(
                            grant.current_management_key.take(),
                            "backend omitted the current management key",
                        )
                        .and_then(management_key_from_managed)
                    },
                    move |management_key| {
                        credentials
                            .generate_key(
                                &id,
                                &expected_serial,
                                &management_key,
                                PivKeyConfiguration {
                                    slot,
                                    algorithm: key_algorithm,
                                    pin_policy,
                                    touch_policy,
                                },
                            )
                            .map(|subject_public_key_info| {
                                ManagedCardOutcome::Applied(Response::new(
                                    v1::GeneratePivKeyResponse {
                                        subject_public_key_info,
                                    },
                                ))
                            })
                    },
                )
                .await;
        }
        let management_algorithm = match management_key_algorithm(input.management_key_algorithm) {
            Ok(algorithm) => algorithm,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "GeneratePivKey",
                    &device_id,
                    "PIV_GENERATE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let management_key = match ManagementKey::new(
            management_algorithm,
            std::mem::take(&mut input.management_key),
        ) {
            Ok(key) => key,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "GeneratePivKey",
                    &device_id,
                    "PIV_GENERATE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let id = DeviceId(device_id.clone());
        let serial = self
            .preflight_piv_serial(
                &caller,
                "GeneratePivKey",
                &device_id,
                "PIV_GENERATE_KEY",
                Some(slot.byte()),
                &serial_hint,
            )
            .await?;
        let credentials = self.credentials.clone();
        let expected_serial = serial.clone();
        let result = blocking(move || {
            credentials.generate_key(
                &id,
                &expected_serial,
                &management_key,
                PivKeyConfiguration {
                    slot,
                    algorithm: key_algorithm,
                    pin_policy,
                    touch_policy,
                },
            )
        })
        .await;
        audit_piv(
            &caller,
            "GeneratePivKey",
            &device_id,
            "PIV_GENERATE_KEY",
            Some(slot.byte()),
            &serial,
            None,
            &result,
        );
        result.map(|subject_public_key_info| {
            Response::new(v1::GeneratePivKeyResponse {
                subject_public_key_info,
            })
        })
    }

    async fn attest_piv_key(
        &self,
        request: Request<v1::AttestPivKeyRequest>,
    ) -> std::result::Result<Response<v1::AttestPivKeyResponse>, Status> {
        let device_id = request.get_ref().id.clone();
        let slot_hint = u8::try_from(request.get_ref().slot_byte).ok();
        let caller = self.caller_piv(
            &request,
            "AttestPivKey",
            &device_id,
            "PIV_ATTEST",
            slot_hint,
        )?;
        let input = request.into_inner();
        let serial_hint = input.expected_serial;
        let slot = match piv_slot(input.slot_byte) {
            Ok(slot) => slot,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "AttestPivKey",
                    &device_id,
                    "PIV_ATTEST",
                    slot_hint,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let id = DeviceId(device_id.clone());
        let mut audit_serial = serial_hint.clone();
        let result = match self.ensure_expected_serial(&id, &serial_hint).await {
            Ok(serial) => {
                audit_serial = serial.clone();
                let credentials = self.credentials.clone();
                blocking(move || credentials.attest(&id, &serial, slot)).await
            }
            Err(status) => Err(status),
        };
        audit_piv(
            &caller,
            "AttestPivKey",
            &device_id,
            "PIV_ATTEST",
            Some(slot.byte()),
            &audit_serial,
            None,
            &result,
        );
        result.map(|attestation| Response::new(attestation_response(attestation)))
    }

    async fn sign_piv_csr(
        &self,
        request: Request<v1::SignPivCsrRequest>,
    ) -> std::result::Result<Response<v1::SignPivCsrResponse>, Status> {
        let device_id = request.get_ref().id.clone();
        let slot_hint = u8::try_from(request.get_ref().slot_byte).ok();
        let caller = self.caller_piv(
            &request,
            "SignPivCsr",
            &device_id,
            "PIV_SIGN_CSR",
            slot_hint,
        )?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        let pin = match PivPin::new(std::mem::take(&mut input.pin)) {
            Ok(pin) => pin,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "SignPivCsr",
                    &device_id,
                    "PIV_SIGN_CSR",
                    slot_hint,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let slot = match piv_slot(input.slot_byte) {
            Ok(slot) => slot,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "SignPivCsr",
                    &device_id,
                    "PIV_SIGN_CSR",
                    slot_hint,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let subject_dn = input.subject_dn;
        let expected_public_key = (!input.expected_public_key.is_empty())
            .then(|| std::mem::take(&mut input.expected_public_key));
        let id = DeviceId(device_id.clone());
        let mut audit_serial = serial_hint.clone();
        let result = match self.ensure_expected_serial(&id, &serial_hint).await {
            Ok(serial) => {
                audit_serial = serial.clone();
                let credentials = self.credentials.clone();
                blocking(move || {
                    credentials.sign_csr(
                        &id,
                        &serial,
                        &pin,
                        slot,
                        &subject_dn,
                        expected_public_key.as_deref(),
                    )
                })
                .await
            }
            Err(status) => Err(status),
        };
        audit_piv(
            &caller,
            "SignPivCsr",
            &device_id,
            "PIV_SIGN_CSR",
            Some(slot.byte()),
            &audit_serial,
            None,
            &result,
        );
        result.map(|csr_der| Response::new(v1::SignPivCsrResponse { csr_der }))
    }

    async fn import_piv_certificate(
        &self,
        request: Request<v1::ImportPivCertificateRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let slot_hint = u8::try_from(request.get_ref().slot_byte).ok();
        let caller = self.caller_piv(
            &request,
            "ImportPivCertificate",
            &device_id,
            "PIV_IMPORT_CERTIFICATE",
            slot_hint,
        )?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        let expected_public_key = (!input.expected_public_key.is_empty())
            .then(|| std::mem::take(&mut input.expected_public_key));
        let slot = match piv_slot(input.slot_byte) {
            Ok(slot) => slot,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ImportPivCertificate",
                    &device_id,
                    "PIV_IMPORT_CERTIFICATE",
                    slot_hint,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        if let Some(managed) = input.managed.take() {
            if !input.management_key.is_empty()
                || input.management_key_algorithm != v1::ManagementKeyAlgorithm::Unspecified as i32
            {
                let status = Status::invalid_argument(
                    "management_key and management_key_algorithm must be empty when managed authorization is supplied",
                );
                audit_managed::<()>(
                    &caller,
                    "ImportPivCertificate",
                    &device_id,
                    "PIV_IMPORT_CERTIFICATE",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    None,
                    &Err(status.clone()),
                );
                return Err(status);
            }
            let certificate_der = std::mem::take(&mut input.certificate_der);
            let serial = self
                .preflight_piv_serial(
                    &caller,
                    "ImportPivCertificate",
                    &device_id,
                    "PIV_IMPORT_CERTIFICATE",
                    Some(slot.byte()),
                    &serial_hint,
                )
                .await?;
            let id = DeviceId(device_id.clone());
            let credentials = self.credentials.clone();
            let expected_serial = serial.clone();
            return self
                .run_managed(
                    ManagedCall {
                        caller: &caller,
                        rpc: "ImportPivCertificate",
                        device_id: &device_id,
                        operation_name: "PIV_IMPORT_CERTIFICATE",
                        operation: v1::Operation::PivImportCertificate,
                        slot: Some(slot.byte()),
                        serial: &serial,
                        rotation_missing_detail: None,
                        abandon_failure: AbandonFailure::KeepCallerStatus,
                    },
                    managed,
                    move |grant| {
                        let management_key = required_secret(
                            grant.current_management_key.take(),
                            "backend omitted the current management key",
                        )
                        .and_then(management_key_from_managed)?;
                        Ok((management_key, certificate_der))
                    },
                    move |(management_key, certificate_der)| {
                        credentials
                            .import_certificate(
                                &id,
                                &expected_serial,
                                &management_key,
                                slot,
                                &certificate_der,
                                expected_public_key.as_deref(),
                            )
                            .map(|()| ManagedCardOutcome::Applied(Response::new(v1::Empty {})))
                    },
                )
                .await;
        }
        let algorithm = match management_key_algorithm(input.management_key_algorithm) {
            Ok(algorithm) => algorithm,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "ImportPivCertificate",
                    &device_id,
                    "PIV_IMPORT_CERTIFICATE",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let management_key =
            match ManagementKey::new(algorithm, std::mem::take(&mut input.management_key)) {
                Ok(key) => key,
                Err(error) => {
                    return Err(audit_piv_error(
                        &caller,
                        "ImportPivCertificate",
                        &device_id,
                        "PIV_IMPORT_CERTIFICATE",
                        Some(slot.byte()),
                        &serial_hint,
                        None,
                        error,
                    ));
                }
            };
        let certificate_der = input.certificate_der;
        let id = DeviceId(device_id.clone());
        let serial = self
            .preflight_piv_serial(
                &caller,
                "ImportPivCertificate",
                &device_id,
                "PIV_IMPORT_CERTIFICATE",
                Some(slot.byte()),
                &serial_hint,
            )
            .await?;
        let credentials = self.credentials.clone();
        let expected_serial = serial.clone();
        let result = blocking(move || {
            credentials.import_certificate(
                &id,
                &expected_serial,
                &management_key,
                slot,
                &certificate_der,
                expected_public_key.as_deref(),
            )
        })
        .await;
        audit_piv(
            &caller,
            "ImportPivCertificate",
            &device_id,
            "PIV_IMPORT_CERTIFICATE",
            Some(slot.byte()),
            &serial,
            None,
            &result,
        );
        result.map(|_| Response::new(v1::Empty {}))
    }

    async fn delete_piv_certificate(
        &self,
        request: Request<v1::DeletePivCertificateRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let slot_hint = u8::try_from(request.get_ref().slot_byte).ok();
        let caller = self.caller_piv(
            &request,
            "DeletePivCertificate",
            &device_id,
            "PIV_DELETE_CERTIFICATE",
            slot_hint,
        )?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        let slot = match piv_slot(input.slot_byte) {
            Ok(slot) => slot,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "DeletePivCertificate",
                    &device_id,
                    "PIV_DELETE_CERTIFICATE",
                    slot_hint,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        if let Some(managed) = input.managed.take() {
            if !input.management_key.is_empty()
                || input.management_key_algorithm != v1::ManagementKeyAlgorithm::Unspecified as i32
            {
                let status = Status::invalid_argument(
                    "management_key and management_key_algorithm must be empty when managed authorization is supplied",
                );
                audit_managed::<()>(
                    &caller,
                    "DeletePivCertificate",
                    &device_id,
                    "PIV_DELETE_CERTIFICATE",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    None,
                    &Err(status.clone()),
                );
                return Err(status);
            }
            let serial = self
                .preflight_piv_serial(
                    &caller,
                    "DeletePivCertificate",
                    &device_id,
                    "PIV_DELETE_CERTIFICATE",
                    Some(slot.byte()),
                    &serial_hint,
                )
                .await?;
            let id = DeviceId(device_id.clone());
            let credentials = self.credentials.clone();
            let expected_serial = serial.clone();
            return self
                .run_managed(
                    ManagedCall {
                        caller: &caller,
                        rpc: "DeletePivCertificate",
                        device_id: &device_id,
                        operation_name: "PIV_DELETE_CERTIFICATE",
                        operation: v1::Operation::PivDeleteCertificate,
                        slot: Some(slot.byte()),
                        serial: &serial,
                        rotation_missing_detail: None,
                        abandon_failure: AbandonFailure::KeepCallerStatus,
                    },
                    managed,
                    |grant| {
                        required_secret(
                            grant.current_management_key.take(),
                            "backend omitted the current management key",
                        )
                        .and_then(management_key_from_managed)
                    },
                    move |management_key| {
                        credentials
                            .delete_certificate(&id, &expected_serial, &management_key, slot)
                            .map(|()| ManagedCardOutcome::Applied(Response::new(v1::Empty {})))
                    },
                )
                .await;
        }
        let algorithm = match management_key_algorithm(input.management_key_algorithm) {
            Ok(algorithm) => algorithm,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "DeletePivCertificate",
                    &device_id,
                    "PIV_DELETE_CERTIFICATE",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let management_key =
            match ManagementKey::new(algorithm, std::mem::take(&mut input.management_key)) {
                Ok(key) => key,
                Err(error) => {
                    return Err(audit_piv_error(
                        &caller,
                        "DeletePivCertificate",
                        &device_id,
                        "PIV_DELETE_CERTIFICATE",
                        Some(slot.byte()),
                        &serial_hint,
                        None,
                        error,
                    ));
                }
            };
        let id = DeviceId(device_id.clone());
        let serial = self
            .preflight_piv_serial(
                &caller,
                "DeletePivCertificate",
                &device_id,
                "PIV_DELETE_CERTIFICATE",
                Some(slot.byte()),
                &serial_hint,
            )
            .await?;
        let credentials = self.credentials.clone();
        let expected_serial = serial.clone();
        let result = blocking(move || {
            credentials.delete_certificate(&id, &expected_serial, &management_key, slot)
        })
        .await;
        audit_piv(
            &caller,
            "DeletePivCertificate",
            &device_id,
            "PIV_DELETE_CERTIFICATE",
            Some(slot.byte()),
            &serial,
            None,
            &result,
        );
        result.map(|_| Response::new(v1::Empty {}))
    }

    async fn delete_piv_key(
        &self,
        request: Request<v1::DeletePivKeyRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let slot_hint = u8::try_from(request.get_ref().slot_byte).ok();
        let caller = self.caller_piv(
            &request,
            "DeletePivKey",
            &device_id,
            "PIV_DELETE_KEY",
            slot_hint,
        )?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        let slot = match piv_slot(input.slot_byte) {
            Ok(slot) => slot,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "DeletePivKey",
                    &device_id,
                    "PIV_DELETE_KEY",
                    slot_hint,
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        if let Some(managed) = input.managed.take() {
            if !input.management_key.is_empty()
                || input.management_key_algorithm != v1::ManagementKeyAlgorithm::Unspecified as i32
            {
                let status = Status::invalid_argument(
                    "management_key and management_key_algorithm must be empty when managed authorization is supplied",
                );
                audit_managed::<()>(
                    &caller,
                    "DeletePivKey",
                    &device_id,
                    "PIV_DELETE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    None,
                    &Err(status.clone()),
                );
                return Err(status);
            }
            let serial = self
                .preflight_piv_serial(
                    &caller,
                    "DeletePivKey",
                    &device_id,
                    "PIV_DELETE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                )
                .await?;
            let id = DeviceId(device_id.clone());
            let credentials = self.credentials.clone();
            let expected_serial = serial.clone();
            return self
                .run_managed(
                    ManagedCall {
                        caller: &caller,
                        rpc: "DeletePivKey",
                        device_id: &device_id,
                        operation_name: "PIV_DELETE_KEY",
                        operation: v1::Operation::PivDeleteKey,
                        slot: Some(slot.byte()),
                        serial: &serial,
                        rotation_missing_detail: None,
                        abandon_failure: AbandonFailure::KeepCallerStatus,
                    },
                    managed,
                    |grant| {
                        required_secret(
                            grant.current_management_key.take(),
                            "backend omitted the current management key",
                        )
                        .and_then(management_key_from_managed)
                    },
                    move |management_key| {
                        credentials
                            .delete_key(&id, &expected_serial, &management_key, slot)
                            .map(|()| ManagedCardOutcome::Applied(Response::new(v1::Empty {})))
                    },
                )
                .await;
        }
        let algorithm = match management_key_algorithm(input.management_key_algorithm) {
            Ok(algorithm) => algorithm,
            Err(error) => {
                return Err(audit_piv_error(
                    &caller,
                    "DeletePivKey",
                    &device_id,
                    "PIV_DELETE_KEY",
                    Some(slot.byte()),
                    &serial_hint,
                    None,
                    error,
                ));
            }
        };
        let management_key =
            match ManagementKey::new(algorithm, std::mem::take(&mut input.management_key)) {
                Ok(key) => key,
                Err(error) => {
                    return Err(audit_piv_error(
                        &caller,
                        "DeletePivKey",
                        &device_id,
                        "PIV_DELETE_KEY",
                        Some(slot.byte()),
                        &serial_hint,
                        None,
                        error,
                    ));
                }
            };
        let id = DeviceId(device_id.clone());
        let serial = self
            .preflight_piv_serial(
                &caller,
                "DeletePivKey",
                &device_id,
                "PIV_DELETE_KEY",
                Some(slot.byte()),
                &serial_hint,
            )
            .await?;
        let credentials = self.credentials.clone();
        let expected_serial = serial.clone();
        let result =
            blocking(move || credentials.delete_key(&id, &expected_serial, &management_key, slot))
                .await;
        audit_piv(
            &caller,
            "DeletePivKey",
            &device_id,
            "PIV_DELETE_KEY",
            Some(slot.byte()),
            &serial,
            None,
            &result,
        );
        result.map(|_| Response::new(v1::Empty {}))
    }

    async fn reset_piv(
        &self,
        request: Request<v1::ResetPivRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller_piv(&request, "ResetPiv", &device_id, "PIV_RESET", None)?;
        let input = request.into_inner();
        let serial_hint = input.confirm_serial;
        let id = DeviceId(device_id.clone());
        let mut audit_serial = serial_hint.clone();
        let result = match self.ensure_expected_serial(&id, &serial_hint).await {
            Ok(serial) => {
                audit_serial = serial.clone();
                let credentials = self.credentials.clone();
                blocking(move || credentials.reset(&id, &serial)).await
            }
            Err(status) => Err(status),
        };
        audit_piv(
            &caller,
            "ResetPiv",
            &device_id,
            "PIV_RESET",
            None,
            &audit_serial,
            None,
            &result,
        );
        result.map(|_| Response::new(v1::Empty {}))
    }

    async fn initialize_managed_piv(
        &self,
        request: Request<v1::InitializeManagedPivRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller_piv(
            &request,
            "InitializeManagedPiv",
            &device_id,
            "PIV_MANAGED_INITIALIZE",
            None,
        )?;
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        let Some(managed) = input.managed.take() else {
            let status = self.missing_managed_authorization_status();
            audit_managed::<()>(
                &caller,
                "InitializeManagedPiv",
                &device_id,
                "PIV_MANAGED_INITIALIZE",
                None,
                &serial_hint,
                None,
                None,
                &Err(status.clone()),
            );
            return Err(status);
        };
        let serial = self
            .preflight_piv_serial(
                &caller,
                "InitializeManagedPiv",
                &device_id,
                "PIV_MANAGED_INITIALIZE",
                None,
                &serial_hint,
            )
            .await?;
        let id = DeviceId(device_id.clone());
        let credentials = self.credentials.clone();
        let expected_serial = serial.clone();
        self.run_managed(
            ManagedCall {
                caller: &caller,
                rpc: "InitializeManagedPiv",
                device_id: &device_id,
                operation_name: "PIV_MANAGED_INITIALIZE",
                operation: v1::Operation::PivManagedInitialize,
                slot: None,
                serial: &serial,
                rotation_missing_detail: Some("backend omitted the managed-initialize rotation ID"),
                abandon_failure: AbandonFailure::ReportToCaller,
            },
            managed,
            |grant| {
                if grant.current_management_key.is_some() || grant.current_puk.is_some() {
                    return Err(Status::internal(
                        "backend returned unexpected current secrets for initialization",
                    ));
                }
                let management_key = required_secret(
                    grant.new_management_key.take(),
                    "backend omitted the new management key",
                )
                .and_then(management_key_from_managed)?;
                if management_key.algorithm() != ManagementKeyAlgorithm::Aes256 {
                    return Err(Status::internal(
                        "backend returned a non-AES-256 initialization key",
                    ));
                }
                let puk = required_secret(grant.new_puk.take(), "backend omitted the new PUK")
                    .and_then(puk_from_managed)?;
                Ok((management_key, puk))
            },
            move |(management_key, puk)| {
                credentials
                    .managed_initialize(&id, &expected_serial, &management_key, &puk)
                    .map(|outcome| match outcome {
                        ManagedPivInitializationOutcome::Applied => {
                            ManagedCardOutcome::Applied(Response::new(v1::Empty {}))
                        }
                        ManagedPivInitializationOutcome::NotApplied => {
                            ManagedCardOutcome::NotApplied(Status::failed_precondition(
                                "managed PIV initialization was not applied",
                            ))
                        }
                        ManagedPivInitializationOutcome::Partial => ManagedCardOutcome::Partial,
                    })
            },
        )
        .await
    }

    async fn rotate_managed_piv_secret(
        &self,
        request: Request<v1::RotateManagedPivSecretRequest>,
    ) -> std::result::Result<Response<v1::Empty>, Status> {
        let device_id = request.get_ref().id.clone();
        let caller = self.caller(&request, "RotateManagedPivSecret", &device_id)?;
        let kind = match v1::ManagedSecretKind::try_from(request.get_ref().kind) {
            Ok(kind) => kind,
            Err(_) => {
                let status = Status::invalid_argument("managed secret kind is invalid");
                audit_managed::<()>(
                    &caller,
                    "RotateManagedPivSecret",
                    &device_id,
                    "PIV_ROTATE_SECRET",
                    None,
                    &request.get_ref().expected_serial,
                    None,
                    None,
                    &Err(status.clone()),
                );
                return Err(status);
            }
        };
        let (operation, operation_name) = match kind {
            v1::ManagedSecretKind::Puk => (v1::Operation::PivChangePuk, "PIV_CHANGE_PUK"),
            v1::ManagedSecretKind::ManagementKey => (
                v1::Operation::PivChangeManagementKey,
                "PIV_CHANGE_MANAGEMENT_KEY",
            ),
            v1::ManagedSecretKind::Unspecified => {
                let status = Status::invalid_argument("managed secret kind is required");
                audit_managed::<()>(
                    &caller,
                    "RotateManagedPivSecret",
                    &device_id,
                    "PIV_ROTATE_SECRET",
                    None,
                    &request.get_ref().expected_serial,
                    None,
                    None,
                    &Err(status.clone()),
                );
                return Err(status);
            }
        };
        let mut input = request.into_inner();
        let serial_hint = input.expected_serial.clone();
        let Some(managed) = input.managed.take() else {
            let status = self.missing_managed_authorization_status();
            audit_managed::<()>(
                &caller,
                "RotateManagedPivSecret",
                &device_id,
                operation_name,
                None,
                &serial_hint,
                None,
                None,
                &Err(status.clone()),
            );
            return Err(status);
        };
        let serial = self
            .preflight_piv_serial(
                &caller,
                "RotateManagedPivSecret",
                &device_id,
                operation_name,
                None,
                &serial_hint,
            )
            .await?;
        let id = DeviceId(device_id.clone());
        let credentials = self.credentials.clone();
        let expected_serial = serial.clone();
        self.run_managed(
            ManagedCall {
                caller: &caller,
                rpc: "RotateManagedPivSecret",
                device_id: &device_id,
                operation_name,
                operation,
                slot: None,
                serial: &serial,
                rotation_missing_detail: Some("backend omitted the secret rotation ID"),
                abandon_failure: AbandonFailure::ReportToCaller,
            },
            managed,
            move |grant| match kind {
                v1::ManagedSecretKind::Puk => {
                    let current = required_secret(
                        grant.current_puk.take(),
                        "backend omitted the current PUK",
                    )
                    .and_then(puk_from_managed)?;
                    let new = required_secret(grant.new_puk.take(), "backend omitted the new PUK")
                        .and_then(puk_from_managed)?;
                    Ok(ManagedRotationSecrets::Puk(current, new))
                }
                v1::ManagedSecretKind::ManagementKey => {
                    let current = required_secret(
                        grant.current_management_key.take(),
                        "backend omitted the current management key",
                    )
                    .and_then(management_key_from_managed)?;
                    let new = required_secret(
                        grant.new_management_key.take(),
                        "backend omitted the new management key",
                    )
                    .and_then(management_key_from_managed)?;
                    if new.algorithm() != ManagementKeyAlgorithm::Aes256 {
                        return Err(Status::internal(
                            "backend returned a non-AES-256 rotation management key",
                        ));
                    }
                    Ok(ManagedRotationSecrets::ManagementKey(current, new))
                }
                v1::ManagedSecretKind::Unspecified => unreachable!("validated above"),
            },
            move |secrets| match secrets {
                ManagedRotationSecrets::Puk(current, new) => credentials
                    .change_puk(&id, &expected_serial, &current, &new)
                    .map(|()| ManagedCardOutcome::Applied(Response::new(v1::Empty {}))),
                ManagedRotationSecrets::ManagementKey(current, new) => credentials
                    .change_management_key(&id, &expected_serial, &current, &new)
                    .map(|()| ManagedCardOutcome::Applied(Response::new(v1::Empty {}))),
            },
        )
        .await
    }
}

fn audit_static(
    caller: &CallerIdentity,
    rpc: &'static str,
    device_id: &str,
    success: bool,
    code: Option<&Status>,
) {
    tracing::info!(
        target: "sigil::audit",
        caller_os_user = %caller.os_user,
        session_id = ?caller.session_id,
        pid = caller.pid,
        rpc,
        device_id,
        result = if success { "ok" } else { "error" },
        code = %sigil_proto::audit_error_code(code)
    );
}

#[allow(clippy::too_many_arguments)]
fn audit_piv<T>(
    caller: &CallerIdentity,
    rpc: &'static str,
    device_id: &str,
    operation: &'static str,
    slot: Option<u8>,
    serial: &str,
    grant_id: Option<&str>,
    result: &std::result::Result<T, Status>,
) {
    let (outcome, code) = match result {
        Ok(_) => ("success", None),
        Err(status) if status.code() == tonic::Code::PermissionDenied => ("denied", Some(status)),
        Err(status) => ("error", Some(status)),
    };
    tracing::info!(
        target: "sigil::audit",
        caller_os_user = %caller.os_user,
        session_id = ?caller.session_id,
        pid = caller.pid,
        rpc,
        device_id,
        operation,
        piv_slot = slot.unwrap_or_default(),
        serial,
        grant_id = grant_id.unwrap_or_default(),
        outcome,
        code = %sigil_proto::audit_error_code(code)
    );
}

#[allow(clippy::too_many_arguments)]
fn audit_managed<T>(
    caller: &CallerIdentity,
    rpc: &'static str,
    device_id: &str,
    operation: &'static str,
    slot: Option<u8>,
    serial: &str,
    grant_id: Option<&str>,
    rotation_id: Option<&str>,
    result: &std::result::Result<T, Status>,
) {
    let (outcome, code) = match result {
        Ok(_) => ("success", None),
        Err(status) if status.code() == tonic::Code::PermissionDenied => ("denied", Some(status)),
        Err(status) => ("error", Some(status)),
    };
    tracing::info!(
        target: "sigil::audit",
        caller_os_user = %caller.os_user,
        session_id = ?caller.session_id,
        pid = caller.pid,
        rpc,
        device_id,
        operation,
        piv_slot = slot.unwrap_or_default(),
        serial,
        grant_id = grant_id.unwrap_or_default(),
        rotation_id = rotation_id.unwrap_or_default(),
        outcome,
        code = %sigil_proto::audit_error_code(code)
    );
}

fn audit_managed_call<T>(
    call: ManagedCall<'_>,
    grant_id: Option<&str>,
    rotation_id: Option<&str>,
    result: &std::result::Result<T, Status>,
) {
    audit_managed(
        call.caller,
        call.rpc,
        call.device_id,
        call.operation_name,
        call.slot,
        call.serial,
        grant_id,
        rotation_id,
        result,
    );
}

#[allow(clippy::too_many_arguments)]
fn audit_rotation_unknown(
    caller: &CallerIdentity,
    rpc: &'static str,
    device_id: &str,
    operation: &'static str,
    serial: &str,
    grant_id: Option<&str>,
    rotation_id: &str,
) {
    tracing::error!(
        target: "sigil::audit",
        caller_os_user = %caller.os_user,
        session_id = ?caller.session_id,
        pid = caller.pid,
        rpc,
        device_id,
        operation,
        serial,
        grant_id = grant_id.unwrap_or_default(),
        rotation_id,
        outcome = "rotation_outcome_unknown",
        code = "rotation_outcome_unknown"
    );
}

#[allow(clippy::too_many_arguments)]
fn audit_piv_error(
    caller: &CallerIdentity,
    rpc: &'static str,
    device_id: &str,
    operation: &'static str,
    slot: Option<u8>,
    serial: &str,
    grant_id: Option<&str>,
    error: CredentialError,
) -> Status {
    let status = status_from_error(&error);
    audit_piv::<()>(
        caller,
        rpc,
        device_id,
        operation,
        slot,
        serial,
        grant_id,
        &Err(status.clone()),
    );
    status
}

fn audit_device<T>(
    caller: &CallerIdentity,
    rpc: &'static str,
    device_id: &str,
    operation: &'static str,
    serial: &str,
    result: &std::result::Result<T, Status>,
) {
    let (outcome, code) = match result {
        Ok(_) => ("success", None),
        Err(status) if status.code() == tonic::Code::PermissionDenied => ("denied", Some(status)),
        Err(status) => ("error", Some(status)),
    };
    tracing::info!(
        target: "sigil::audit",
        caller_os_user = %caller.os_user,
        session_id = ?caller.session_id,
        pid = caller.pid,
        rpc,
        device_id,
        operation,
        serial,
        outcome,
        code = %sigil_proto::audit_error_code(code)
    );
}

fn audit_device_error(
    caller: &CallerIdentity,
    rpc: &'static str,
    device_id: &str,
    operation: &'static str,
    serial: &str,
    error: CredentialError,
) -> Status {
    let status = status_from_error(&error);
    audit_device::<()>(
        caller,
        rpc,
        device_id,
        operation,
        serial,
        &Err(status.clone()),
    );
    status
}

fn applications_from_proto(values: Vec<i32>) -> CoreResult<Vec<Application>> {
    values
        .into_iter()
        .map(|value| {
            match v1::Application::try_from(value).map_err(|_| {
                CredentialError::SmartCardOperation("invalid application value".into())
            })? {
                v1::Application::Piv => Ok(Application::Piv),
                v1::Application::Fido2 => Ok(Application::Fido2),
                v1::Application::U2f => Ok(Application::U2f),
                v1::Application::Otp => Ok(Application::Otp),
                v1::Application::OpenPgp => Ok(Application::OpenPgp),
                v1::Application::Oath => Ok(Application::Oath),
                v1::Application::YubiHsmAuth => Ok(Application::YubiHsmAuth),
                v1::Application::Unspecified => Err(CredentialError::SmartCardOperation(
                    "unspecified application value".into(),
                )),
            }
        })
        .collect()
}

fn piv_slot(slot_byte: u32) -> CoreResult<PivSlot> {
    let slot_byte =
        u8::try_from(slot_byte).map_err(|_| CredentialError::InvalidSlot(slot_byte.to_string()))?;
    PivSlot::from_byte(slot_byte)
        .ok_or_else(|| CredentialError::InvalidSlot(format!("{slot_byte:02x}")))
}

fn management_key_algorithm(value: i32) -> CoreResult<ManagementKeyAlgorithm> {
    match v1::ManagementKeyAlgorithm::try_from(value)
        .map_err(|_| CredentialError::InvalidSlot(value.to_string()))?
    {
        v1::ManagementKeyAlgorithm::Aes128 => Ok(ManagementKeyAlgorithm::Aes128),
        v1::ManagementKeyAlgorithm::Aes192 => Ok(ManagementKeyAlgorithm::Aes192),
        v1::ManagementKeyAlgorithm::Aes256 => Ok(ManagementKeyAlgorithm::Aes256),
        v1::ManagementKeyAlgorithm::Unspecified => Err(CredentialError::UnsupportedOperation(
            "management key algorithm is required".into(),
        )),
    }
}

fn piv_key_algorithm(value: i32) -> CoreResult<PivKeyAlgorithm> {
    match v1::PivKeyGenerationAlgorithm::try_from(value)
        .map_err(|_| CredentialError::UnsupportedOperation("unknown PIV key algorithm".into()))?
    {
        v1::PivKeyGenerationAlgorithm::PivKeyGenerationEccP256 => Ok(PivKeyAlgorithm::EccP256),
        v1::PivKeyGenerationAlgorithm::PivKeyGenerationEccP384 => Ok(PivKeyAlgorithm::EccP384),
        v1::PivKeyGenerationAlgorithm::Unspecified => Err(CredentialError::UnsupportedOperation(
            "PIV key algorithm is required".into(),
        )),
    }
}

fn pin_policy(value: i32) -> CoreResult<PinPolicy> {
    match v1::PinPolicy::try_from(value)
        .map_err(|_| CredentialError::UnsupportedOperation("unknown PIV PIN policy".into()))?
    {
        v1::PinPolicy::Default => Ok(PinPolicy::Default),
        v1::PinPolicy::Never => Ok(PinPolicy::Never),
        v1::PinPolicy::Once => Ok(PinPolicy::Once),
        v1::PinPolicy::Always => Ok(PinPolicy::Always),
        v1::PinPolicy::MatchOnce => Ok(PinPolicy::MatchOnce),
        v1::PinPolicy::MatchAlways => Ok(PinPolicy::MatchAlways),
        v1::PinPolicy::Unspecified => Err(CredentialError::UnsupportedOperation(
            "PIV PIN policy is required".into(),
        )),
    }
}

fn touch_policy(value: i32) -> CoreResult<TouchPolicy> {
    match v1::TouchPolicy::try_from(value)
        .map_err(|_| CredentialError::UnsupportedOperation("unknown PIV touch policy".into()))?
    {
        v1::TouchPolicy::Default => Ok(TouchPolicy::Default),
        v1::TouchPolicy::Never => Ok(TouchPolicy::Never),
        v1::TouchPolicy::Always => Ok(TouchPolicy::Always),
        v1::TouchPolicy::Cached => Ok(TouchPolicy::Cached),
        v1::TouchPolicy::Unspecified => Err(CredentialError::UnsupportedOperation(
            "PIV touch policy is required".into(),
        )),
    }
}

fn attestation_response(attestation: sigil_core::PivAttestation) -> v1::AttestPivKeyResponse {
    let inspection = attestation.inspection;
    v1::AttestPivKeyResponse {
        attestation_der: attestation.attestation_der,
        intermediate_der: attestation.intermediate_der,
        verified: inspection.verified,
        verification_error: inspection.verification_error.unwrap_or_default(),
        attestation_root: inspection.attestation_root.unwrap_or_default(),
        attested_serial: inspection.attested_serial,
        firmware: inspection.firmware.unwrap_or_default(),
        attested_slot: inspection.attested_slot.map(u32::from),
        pin_policy: inspection.pin_policy.map(u32::from),
        touch_policy: inspection.touch_policy.map(u32::from),
        subject_public_key_info: inspection.subject_public_key_info.unwrap_or_default(),
    }
}

#[cfg(test)]
mod audit_tests {
    use std::sync::Arc;

    use tracing_subscriber::prelude::*;

    use super::*;
    use crate::audit_outbox::{AuditOutbox, AuditOutboxLayer};

    #[test]
    fn managed_audit_outbox_contains_ids_but_not_tokens_or_secret_values() {
        let directory = tempfile::tempdir().expect("audit directory");
        let outbox = Arc::new(AuditOutbox::open(directory.path()).expect("open outbox"));
        let subscriber = tracing::Dispatch::new(
            tracing_subscriber::registry().with(AuditOutboxLayer::new(Arc::clone(&outbox))),
        );
        let caller = CallerIdentity {
            os_user: "test-user".into(),
            session_id: Some(7),
            pid: 1,
        };
        let result: std::result::Result<(), Status> = Ok(());
        tracing::dispatcher::with_default(&subscriber, || {
            audit_managed(
                &caller,
                "InitializeManagedPiv",
                "mock-device",
                "PIV_MANAGED_INITIALIZE",
                None,
                "12345678",
                Some("grant-id"),
                Some("rotation-id"),
                &result,
            );
        });
        let events = outbox.batch(1).expect("read managed audit event");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].grant_id, "grant-id");
        assert_eq!(events[0].rotation_id, "rotation-id");
        let fields = [
            events[0].rpc.as_str(),
            events[0].operation.as_str(),
            events[0].device_id.as_str(),
            events[0].token_serial.as_str(),
            events[0].caller_os_user.as_str(),
            events[0].outcome.as_str(),
            events[0].code.as_str(),
            events[0].grant_id.as_str(),
            events[0].rotation_id.as_str(),
        ];
        for field in fields {
            assert!(!field.contains("test-access-token-not-for-logs"));
            assert!(!field.contains("87654321"));
            assert!(!field.contains("[66, 66, 66"));
        }
    }

    #[test]
    fn audit_code_uses_sigil_error_kind_then_grpc_code() {
        let directory = tempfile::tempdir().expect("audit directory");
        let outbox = Arc::new(AuditOutbox::open(directory.path()).expect("open outbox"));
        let subscriber = tracing::Dispatch::new(
            tracing_subscriber::registry().with(AuditOutboxLayer::new(Arc::clone(&outbox))),
        );
        let caller = CallerIdentity {
            os_user: "test-user".into(),
            session_id: Some(7),
            pid: 1,
        };
        let complexity: std::result::Result<(), Status> =
            Err(status_from_error(&CredentialError::PinComplexity));
        let generic: std::result::Result<(), Status> =
            Err(Status::failed_precondition("plain failure"));
        let success: std::result::Result<(), Status> = Ok(());
        tracing::dispatcher::with_default(&subscriber, || {
            audit_piv(
                &caller,
                "ChangePivPin",
                "mock-device",
                "PIV_CHANGE_PIN",
                None,
                "12345678",
                None,
                &complexity,
            );
            audit_managed(
                &caller,
                "GeneratePivKey",
                "mock-device",
                "PIV_GENERATE_KEY",
                None,
                "12345678",
                None,
                None,
                &generic,
            );
            audit_piv(
                &caller,
                "ChangePivPin",
                "mock-device",
                "PIV_CHANGE_PIN",
                None,
                "12345678",
                None,
                &success,
            );
        });
        let codes: Vec<String> = outbox
            .batch(3)
            .expect("read audit events")
            .into_iter()
            .map(|event| event.code)
            .collect();
        assert_eq!(
            codes,
            ["PIN_COMPLEXITY_VIOLATION", "FailedPrecondition", ""]
        );
    }
}
