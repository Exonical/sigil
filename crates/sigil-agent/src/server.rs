use std::pin::Pin;

use futures_util::Stream;
use sigil_app::CredentialService;
use sigil_core::{CredentialError, DeviceId, PivSlot, Result as CoreResult};
use sigil_proto::{status_from_error, v1};
use tokio::{sync::mpsc, task};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

use crate::caller::{self, CallerIdentity, CallerPolicy};

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
}

impl AgentService {
    pub fn new(credentials: CredentialService, station_id: impl Into<String>) -> Self {
        Self {
            credentials,
            station_id: station_id.into(),
            policy: CallerPolicy::production(),
        }
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
