use std::{collections::HashMap, pin::Pin, sync::Arc};

use futures_util::Stream;
use sigil_app::CredentialService;
use sigil_core::{
    CredentialError, DeviceId, ManagementKey, ManagementKeyAlgorithm, PinPolicy, PivKeyAlgorithm,
    PivKeyConfiguration, PivPin, PivPuk, PivSlot, Result as CoreResult, TouchPolicy,
};
use sigil_proto::{status_from_error, v1};
use tokio::{sync::mpsc, task};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

use crate::caller::{self, CallerIdentity, CallerPolicy};
use crate::grant::{GrantExpectation, GrantProvider, GrantRequest, GrantVerifier, Unconfigured};

pub type WatchDevicesStream =
    Pin<Box<dyn Stream<Item = std::result::Result<v1::DeviceEvent, Status>> + Send + 'static>>;
pub type EnrollFingerprintStream = Pin<
    Box<
        dyn Stream<Item = std::result::Result<v1::EnrollFingerprintEvent, Status>> + Send + 'static,
    >,
>;

#[derive(Clone)]
pub struct AgentService {
    credentials: CredentialService,
    station_id: String,
    policy: CallerPolicy,
    grant_provider: Arc<dyn GrantProvider>,
    grant_verifier: Arc<GrantVerifier>,
}

impl AgentService {
    pub fn new(credentials: CredentialService, station_id: impl Into<String>) -> Self {
        Self {
            credentials,
            station_id: station_id.into(),
            policy: CallerPolicy::production(),
            grant_provider: Arc::new(Unconfigured),
            grant_verifier: Arc::new(GrantVerifier::new(HashMap::new())),
        }
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
            audit_static(&identity, rpc, device_id, false, Some(status.code()));
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
}

#[allow(dead_code)] // used by escrow-backed agent operations
struct PivGrantContext {
    serial: String,
    grant_id: String,
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
                Some(status.code()),
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
                        Some(status.code()),
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
                    Some(status.code()),
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
                Some(status.code()),
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
                    Some(status.code()),
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
                Some(status.code()),
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
        result.map(|attestation| {
            Response::new(v1::AttestPivKeyResponse {
                attestation_der: attestation.attestation_der,
                intermediate_der: attestation.intermediate_der,
            })
        })
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
        let id = DeviceId(device_id.clone());
        let mut audit_serial = serial_hint.clone();
        let result = match self.ensure_expected_serial(&id, &serial_hint).await {
            Ok(serial) => {
                audit_serial = serial.clone();
                let credentials = self.credentials.clone();
                blocking(move || credentials.sign_csr(&id, &serial, &pin, slot, &subject_dn)).await
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
}

fn audit_static(
    caller: &CallerIdentity,
    rpc: &'static str,
    device_id: &str,
    success: bool,
    code: Option<tonic::Code>,
) {
    tracing::info!(
        target: "sigil::audit",
        caller_os_user = %caller.os_user,
        session_id = ?caller.session_id,
        pid = caller.pid,
        rpc,
        device_id,
        result = if success { "ok" } else { "error" },
        code = ?code
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
        Err(status) if status.code() == tonic::Code::PermissionDenied => {
            ("denied", Some(status.code()))
        }
        Err(status) => ("error", Some(status.code())),
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
        code = ?code
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
