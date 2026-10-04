//! Synchronous domain-trait client for the local privileged Sigil agent.

use std::{
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
};

use sigil_core::{
    CredentialError, DeviceDiscovery, DeviceEvent, DeviceId, DeviceInfo, DiscoverableCredential,
    FidoInspection, FidoStatus, Fingerprint, FingerprintProgress, PivCertificate, PivInfo,
    PivInspection, PivSlot, PivSlotInfo, Result,
};
use sigil_proto::v1;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

mod trust;

const PROTOCOL_VERSION: u32 = 1;

#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\sigil-agent";
#[cfg(unix)]
pub const DEFAULT_ENDPOINT: &str = "/run/sigil/agent.sock";
#[cfg(not(any(windows, unix)))]
pub const DEFAULT_ENDPOINT: &str = "unsupported-local-agent-transport";

type RpcClient = v1::agent_client::AgentClient<Channel>;
type ChannelConnectResult = std::result::Result<Channel, (tonic::transport::Error, bool)>;

pub struct AgentClient {
    runtime: tokio::runtime::Runtime,
    rpc: RpcClient,
    endpoint: String,
    agent_info: v1::GetAgentInfoResponse,
}

impl AgentClient {
    pub fn connect(endpoint: Option<&str>) -> Result<Self> {
        let endpoint = endpoint
            .map(str::to_owned)
            .or_else(|| std::env::var("SIGIL_AGENT_ENDPOINT").ok())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| CredentialError::AgentUnavailable(error.to_string()))?;
        let channel = runtime
            .block_on(connect_channel(endpoint.clone()))
            .map_err(|(_error, server_untrusted)| {
                if server_untrusted {
                    CredentialError::AgentUntrusted(endpoint.clone())
                } else {
                    CredentialError::AgentUnavailable(format!(
                        "Sigil agent is not running at {endpoint}"
                    ))
                }
            })?;
        let mut rpc = RpcClient::new(channel);
        let info = runtime
            .block_on(rpc.get_agent_info(v1::Empty {}))
            .map_err(|status| sigil_proto::error_from_status(&status))?
            .into_inner();
        if info.protocol_version != PROTOCOL_VERSION {
            return Err(CredentialError::ProtocolMismatch {
                agent: info.protocol_version,
                client: PROTOCOL_VERSION,
            });
        }
        Ok(Self {
            runtime,
            rpc,
            endpoint,
            agent_info: info,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn agent_info(&self) -> &v1::GetAgentInfoResponse {
        &self.agent_info
    }

    fn map_status(status: tonic::Status) -> CredentialError {
        sigil_proto::error_from_status(&status)
    }
}

#[cfg(windows)]
async fn connect_channel(endpoint: String) -> ChannelConnectResult {
    use hyper_util::rt::TokioIo;

    let server_untrusted = Arc::new(AtomicBool::new(false));
    let connector_untrusted = Arc::clone(&server_untrusted);
    let connector = service_fn(move |_uri: tonic::codegen::http::Uri| {
        let endpoint = endpoint.clone();
        let server_untrusted = Arc::clone(&connector_untrusted);
        async move {
            let client = trust::open_named_pipe(&endpoint)?;
            if !trust::named_pipe_server_is_trusted(&client) {
                server_untrusted.store(true, Ordering::SeqCst);
                return Err(trust::untrusted_io_error(&endpoint));
            }
            Ok(TokioIo::new(client))
        }
    });
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(connector)
        .await
        .map_err(|error| (error, server_untrusted.load(Ordering::SeqCst)))
}

#[cfg(unix)]
async fn connect_channel(endpoint: String) -> ChannelConnectResult {
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;

    let server_untrusted = Arc::new(AtomicBool::new(false));
    let connector_untrusted = Arc::clone(&server_untrusted);
    let connector = service_fn(move |_uri: tonic::codegen::http::Uri| {
        let endpoint = endpoint.clone();
        let server_untrusted = Arc::clone(&connector_untrusted);
        async move {
            let stream = UnixStream::connect(endpoint.clone()).await?;
            if !trust::unix_server_is_trusted(&stream) {
                server_untrusted.store(true, Ordering::SeqCst);
                return Err(trust::untrusted_io_error(&endpoint));
            }
            Ok(TokioIo::new(stream))
        }
    });
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(connector)
        .await
        .map_err(|error| (error, server_untrusted.load(Ordering::SeqCst)))
}

#[cfg(not(any(windows, unix)))]
async fn connect_channel(_endpoint: String) -> ChannelConnectResult {
    panic!("local IPC is unavailable on this platform")
}

impl DeviceDiscovery for AgentClient {
    fn list(&self) -> Result<Vec<DeviceInfo>> {
        let response = self
            .runtime
            .block_on(self.rpc.clone().list_devices(v1::Empty {}))
            .map_err(Self::map_status)?
            .into_inner();
        response
            .devices
            .into_iter()
            .map(TryFrom::try_from)
            .collect()
    }

    fn subscribe(&self) -> Result<Receiver<DeviceEvent>> {
        let response = self
            .runtime
            .block_on(self.rpc.clone().watch_devices(v1::Empty {}))
            .map_err(Self::map_status)?;
        let mut stream = response.into_inner();
        let (sender, receiver) = mpsc::channel();
        self.runtime.handle().spawn(async move {
            while let Ok(Some(event)) = stream.message().await {
                let Ok(event) = DeviceEvent::try_from(event) else {
                    continue;
                };
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
        Ok(receiver)
    }
}

impl FidoInspection for AgentClient {
    fn fido_status(&self, id: &DeviceId) -> Result<FidoStatus> {
        self.runtime
            .block_on(
                self.rpc
                    .clone()
                    .get_fido_status(v1::DeviceRequest { id: id.0.clone() }),
            )
            .map(|response| response.into_inner().into())
            .map_err(Self::map_status)
    }

    fn discoverable_credentials(
        &self,
        id: &DeviceId,
        pin: &str,
    ) -> Result<Vec<DiscoverableCredential>> {
        self.runtime
            .block_on(
                self.rpc
                    .clone()
                    .list_discoverable_credentials(v1::PinRequest {
                        id: id.0.clone(),
                        pin: pin.to_owned(),
                    }),
            )
            .map(|response| {
                response
                    .into_inner()
                    .credentials
                    .into_iter()
                    .map(Into::into)
                    .collect()
            })
            .map_err(Self::map_status)
    }

    fn fingerprints(&self, id: &DeviceId, pin: &str) -> Result<Vec<Fingerprint>> {
        self.runtime
            .block_on(self.rpc.clone().list_fingerprints(v1::PinRequest {
                id: id.0.clone(),
                pin: pin.to_owned(),
            }))
            .map(|response| {
                response
                    .into_inner()
                    .fingerprints
                    .into_iter()
                    .map(Into::into)
                    .collect()
            })
            .map_err(Self::map_status)
    }

    fn enroll_fingerprint(
        &self,
        id: &DeviceId,
        pin: &str,
        on_progress: &mut dyn FnMut(FingerprintProgress),
    ) -> Result<Fingerprint> {
        self.runtime.block_on(async {
            let response = self
                .rpc
                .clone()
                .enroll_fingerprint(v1::EnrollFingerprintRequest {
                    id: id.0.clone(),
                    pin: pin.to_owned(),
                })
                .await
                .map_err(Self::map_status)?;
            let mut stream = response.into_inner();
            while let Some(event) = stream.message().await.map_err(Self::map_status)? {
                match event.event {
                    Some(v1::enroll_fingerprint_event::Event::Progress(progress)) => {
                        on_progress(progress.into());
                    }
                    Some(v1::enroll_fingerprint_event::Event::Result(fingerprint)) => {
                        return Ok(fingerprint.into());
                    }
                    None => {
                        return Err(CredentialError::FidoOperation(
                            "agent returned an empty fingerprint event".into(),
                        ));
                    }
                }
            }
            Err(CredentialError::FidoOperation(
                "agent ended fingerprint enrollment without a result".into(),
            ))
        })
    }

    fn remove_fingerprint(&self, id: &DeviceId, pin: &str, fingerprint_id: &str) -> Result<()> {
        self.runtime
            .block_on(
                self.rpc
                    .clone()
                    .remove_fingerprint(v1::RemoveFingerprintRequest {
                        id: id.0.clone(),
                        pin: pin.to_owned(),
                        fingerprint_id: fingerprint_id.to_owned(),
                    }),
            )
            .map(|_| ())
            .map_err(Self::map_status)
    }
}

impl PivInspection for AgentClient {
    fn piv_info(&self, id: &DeviceId) -> Result<PivInfo> {
        self.runtime
            .block_on(
                self.rpc
                    .clone()
                    .get_piv_info(v1::DeviceRequest { id: id.0.clone() }),
            )
            .map(|response| response.into_inner().try_into())
            .map_err(Self::map_status)?
    }

    fn piv_slots(&self, id: &DeviceId) -> Result<Vec<PivSlotInfo>> {
        self.runtime
            .block_on(
                self.rpc
                    .clone()
                    .list_piv_slots(v1::DeviceRequest { id: id.0.clone() }),
            )
            .map_err(Self::map_status)?
            .into_inner()
            .slots
            .into_iter()
            .map(TryFrom::try_from)
            .collect()
    }

    fn piv_certificate(&self, id: &DeviceId, slot: PivSlot) -> Result<Option<PivCertificate>> {
        let response = self
            .runtime
            .block_on(
                self.rpc
                    .clone()
                    .get_piv_certificate(v1::GetPivCertificateRequest {
                        id: id.0.clone(),
                        slot_byte: u32::from(slot.byte()),
                    }),
            )
            .map_err(Self::map_status)?
            .into_inner();
        if !response.found {
            return Ok(None);
        }
        let summary = response
            .summary
            .ok_or_else(|| {
                CredentialError::SmartCardOperation("agent omitted certificate summary".into())
            })?
            .try_into()?;
        Ok(Some(PivCertificate {
            slot,
            summary,
            der: response.der,
        }))
    }
}

impl FromStr for AgentClient {
    type Err = CredentialError;

    fn from_str(endpoint: &str) -> Result<Self> {
        Self::connect(Some(endpoint))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use sigil_core::CredentialError;

    use super::AgentClient;

    #[test]
    fn missing_named_pipe_maps_to_agent_unavailable() {
        let endpoint = format!(r"\\.\pipe\sigil-test-missing-{}", std::process::id());
        let error = match AgentClient::connect(Some(&endpoint)) {
            Ok(_) => panic!("the test pipe unexpectedly has a server"),
            Err(error) => error,
        };
        assert!(matches!(error, CredentialError::AgentUnavailable(_)));
    }
}
