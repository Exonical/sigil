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
    Application, CredentialError, DeviceDiscovery, DeviceEvent, DeviceId, DeviceInfo,
    DeviceManagement, DiscoverableCredential, FidoInspection, FidoStatus, Fingerprint,
    FingerprintProgress, ManagementKey, ManagementKeyAlgorithm, PinPolicy, PivAttestation,
    PivCertificate, PivInfo, PivInspection, PivKeyConfiguration, PivManagement, PivPin, PivPuk,
    PivSlot, PivSlotInfo, Result, Secret, TouchPolicy,
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

struct ClientRuntime(Option<tokio::runtime::Runtime>);

impl ClientRuntime {
    fn new() -> std::io::Result<Self> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map(|runtime| Self(Some(runtime)))
    }

    fn runtime(&self) -> &tokio::runtime::Runtime {
        self.0
            .as_ref()
            .expect("agent client runtime is present until drop")
    }

    fn handle(&self) -> &tokio::runtime::Handle {
        self.runtime().handle()
    }

    fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future + Send,
        F::Output: Send,
    {
        if tokio::runtime::Handle::try_current().is_err() {
            return self.runtime().block_on(future);
        }
        std::thread::scope(|scope| scope.spawn(|| self.runtime().block_on(future)).join())
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }
}

impl Drop for ClientRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

pub struct AgentClient {
    runtime: ClientRuntime,
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
        let runtime = ClientRuntime::new()
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

    fn rpc_change_piv_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_pin: &PivPin,
        new_pin: &PivPin,
    ) -> Result<()> {
        self.runtime
            .block_on(self.rpc.clone().change_piv_pin(v1::ChangePivPinRequest {
                id: id.0.clone(),
                expected_serial: expected_serial.to_owned(),
                old_pin: old_pin.as_bytes().to_vec(),
                new_pin: new_pin.as_bytes().to_vec(),
            }))
            .map(|_| ())
            .map_err(Self::map_status)
    }

    fn rpc_change_piv_puk(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_puk: &PivPuk,
        new_puk: &PivPuk,
    ) -> Result<()> {
        self.runtime
            .block_on(self.rpc.clone().change_piv_puk(v1::ChangePivPukRequest {
                id: id.0.clone(),
                expected_serial: expected_serial.to_owned(),
                old_puk: old_puk.as_bytes().to_vec(),
                new_puk: new_puk.as_bytes().to_vec(),
            }))
            .map(|_| ())
            .map_err(Self::map_status)
    }

    fn rpc_unblock_piv_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        puk: &PivPuk,
        new_pin: &PivPin,
    ) -> Result<()> {
        self.runtime
            .block_on(self.rpc.clone().unblock_piv_pin(v1::UnblockPivPinRequest {
                id: id.0.clone(),
                expected_serial: expected_serial.to_owned(),
                puk: puk.as_bytes().to_vec(),
                new_pin: new_pin.as_bytes().to_vec(),
            }))
            .map(|_| ())
            .map_err(Self::map_status)
    }

    fn rpc_change_piv_management_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        current: &ManagementKey,
        new: &ManagementKey,
    ) -> Result<()> {
        self.runtime
            .block_on(self.rpc.clone().change_piv_management_key(
                v1::ChangePivManagementKeyRequest {
                    id: id.0.clone(),
                    expected_serial: expected_serial.to_owned(),
                    current_management_key: current.as_bytes().to_vec(),
                    current_algorithm: management_key_algorithm_to_proto(current.algorithm()),
                    new_algorithm: management_key_algorithm_to_proto(new.algorithm()),
                    new_management_key: new.as_bytes().to_vec(),
                },
            ))
            .map(|_| ())
            .map_err(Self::map_status)
    }

    fn rpc_generate_piv_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        configuration: PivKeyConfiguration,
    ) -> Result<Vec<u8>> {
        self.runtime
            .block_on(
                self.rpc
                    .clone()
                    .generate_piv_key(v1::GeneratePivKeyRequest {
                        id: id.0.clone(),
                        expected_serial: expected_serial.to_owned(),
                        management_key: management_key.as_bytes().to_vec(),
                        management_key_algorithm: management_key_algorithm_to_proto(
                            management_key.algorithm(),
                        ),
                        slot_byte: u32::from(configuration.slot.byte()),
                        algorithm: match configuration.algorithm {
                            sigil_core::PivKeyAlgorithm::EccP256 => {
                                v1::PivKeyGenerationAlgorithm::PivKeyGenerationEccP256 as i32
                            }
                            sigil_core::PivKeyAlgorithm::EccP384 => {
                                v1::PivKeyGenerationAlgorithm::PivKeyGenerationEccP384 as i32
                            }
                        },
                        pin_policy: pin_policy_to_proto(configuration.pin_policy),
                        touch_policy: touch_policy_to_proto(configuration.touch_policy),
                    }),
            )
            .map(|response| response.into_inner().subject_public_key_info)
            .map_err(Self::map_status)
    }

    fn rpc_attest_piv_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        slot: PivSlot,
    ) -> Result<PivAttestation> {
        self.runtime
            .block_on(self.rpc.clone().attest_piv_key(v1::AttestPivKeyRequest {
                id: id.0.clone(),
                expected_serial: expected_serial.to_owned(),
                slot_byte: u32::from(slot.byte()),
            }))
            .map(|response| {
                let response = response.into_inner();
                PivAttestation {
                    attestation_der: response.attestation_der,
                    intermediate_der: response.intermediate_der,
                }
            })
            .map_err(Self::map_status)
    }

    fn rpc_sign_piv_csr(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        pin: &PivPin,
        slot: PivSlot,
        subject_dn: &str,
    ) -> Result<Vec<u8>> {
        self.runtime
            .block_on(self.rpc.clone().sign_piv_csr(v1::SignPivCsrRequest {
                id: id.0.clone(),
                expected_serial: expected_serial.to_owned(),
                pin: pin.as_bytes().to_vec(),
                slot_byte: u32::from(slot.byte()),
                subject_dn: subject_dn.to_owned(),
            }))
            .map(|response| response.into_inner().csr_der)
            .map_err(Self::map_status)
    }

    fn rpc_import_piv_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
        certificate_der: &[u8],
    ) -> Result<()> {
        self.runtime
            .block_on(
                self.rpc
                    .clone()
                    .import_piv_certificate(v1::ImportPivCertificateRequest {
                        id: id.0.clone(),
                        expected_serial: expected_serial.to_owned(),
                        management_key: management_key.as_bytes().to_vec(),
                        management_key_algorithm: management_key_algorithm_to_proto(
                            management_key.algorithm(),
                        ),
                        slot_byte: u32::from(slot.byte()),
                        certificate_der: certificate_der.to_vec(),
                    }),
            )
            .map(|_| ())
            .map_err(Self::map_status)
    }

    fn rpc_delete_piv_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        self.runtime
            .block_on(
                self.rpc
                    .clone()
                    .delete_piv_certificate(v1::DeletePivCertificateRequest {
                        id: id.0.clone(),
                        expected_serial: expected_serial.to_owned(),
                        management_key: management_key.as_bytes().to_vec(),
                        management_key_algorithm: management_key_algorithm_to_proto(
                            management_key.algorithm(),
                        ),
                        slot_byte: u32::from(slot.byte()),
                    }),
            )
            .map(|_| ())
            .map_err(Self::map_status)
    }

    fn rpc_delete_piv_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        self.runtime
            .block_on(self.rpc.clone().delete_piv_key(v1::DeletePivKeyRequest {
                id: id.0.clone(),
                expected_serial: expected_serial.to_owned(),
                management_key: management_key.as_bytes().to_vec(),
                management_key_algorithm: management_key_algorithm_to_proto(
                    management_key.algorithm(),
                ),
                slot_byte: u32::from(slot.byte()),
            }))
            .map(|_| ())
            .map_err(Self::map_status)
    }

    fn rpc_reset_piv(&self, id: &DeviceId, confirm_serial: &str) -> Result<()> {
        self.runtime
            .block_on(self.rpc.clone().reset_piv(v1::ResetPivRequest {
                id: id.0.clone(),
                confirm_serial: confirm_serial.to_owned(),
            }))
            .map(|_| ())
            .map_err(Self::map_status)
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
        let (progress_sender, progress_receiver) = mpsc::channel();
        std::thread::scope(|scope| {
            let job = scope.spawn(move || self.enroll_fingerprint_rpc(id, pin, progress_sender));
            for progress in progress_receiver {
                on_progress(progress);
            }
            job.join()
        })
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
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

impl AgentClient {
    fn enroll_fingerprint_rpc(
        &self,
        id: &DeviceId,
        pin: &str,
        progress_sender: mpsc::Sender<FingerprintProgress>,
    ) -> Result<Fingerprint> {
        self.runtime.block_on(async move {
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
                        let _ = progress_sender.send(progress.into());
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

impl PivManagement for AgentClient {
    fn change_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_pin: &PivPin,
        new_pin: &PivPin,
    ) -> Result<()> {
        self.rpc_change_piv_pin(id, expected_serial, old_pin, new_pin)
    }

    fn change_puk(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_puk: &PivPuk,
        new_puk: &PivPuk,
    ) -> Result<()> {
        self.rpc_change_piv_puk(id, expected_serial, old_puk, new_puk)
    }

    fn unblock_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        puk: &PivPuk,
        new_pin: &PivPin,
    ) -> Result<()> {
        self.rpc_unblock_piv_pin(id, expected_serial, puk, new_pin)
    }

    fn change_management_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        current: &ManagementKey,
        new: &ManagementKey,
    ) -> Result<()> {
        self.rpc_change_piv_management_key(id, expected_serial, current, new)
    }

    fn generate_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        configuration: PivKeyConfiguration,
    ) -> Result<Vec<u8>> {
        self.rpc_generate_piv_key(id, expected_serial, management_key, configuration)
    }

    fn attest(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        slot: PivSlot,
    ) -> Result<PivAttestation> {
        self.rpc_attest_piv_key(id, expected_serial, slot)
    }

    fn sign_csr(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        pin: &PivPin,
        slot: PivSlot,
        subject_dn: &str,
    ) -> Result<Vec<u8>> {
        self.rpc_sign_piv_csr(id, expected_serial, pin, slot, subject_dn)
    }

    fn import_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
        certificate_der: &[u8],
    ) -> Result<()> {
        self.rpc_import_piv_certificate(id, expected_serial, management_key, slot, certificate_der)
    }

    fn delete_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        self.rpc_delete_piv_certificate(id, expected_serial, management_key, slot)
    }

    fn delete_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        self.rpc_delete_piv_key(id, expected_serial, management_key, slot)
    }

    fn reset(&self, id: &DeviceId, expected_serial: &str) -> Result<()> {
        self.rpc_reset_piv(id, expected_serial)
    }
}

impl DeviceManagement for AgentClient {
    fn set_enabled_applications(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        usb: &[Application],
        nfc: Option<&[Application]>,
        lock_code: Option<&Secret>,
    ) -> Result<()> {
        self.runtime
            .block_on(
                self.rpc
                    .clone()
                    .set_enabled_applications(v1::SetEnabledApplicationsRequest {
                        id: id.0.clone(),
                        expected_serial: expected_serial.to_owned(),
                        usb_enabled: usb.iter().map(application_to_proto).collect(),
                        set_nfc: nfc.is_some(),
                        nfc_enabled: nfc
                            .unwrap_or_default()
                            .iter()
                            .map(application_to_proto)
                            .collect(),
                        lock_code: lock_code
                            .map(|code| code.expose().to_vec())
                            .unwrap_or_default(),
                    }),
            )
            .map(|_| ())
            .map_err(Self::map_status)
    }
}

fn application_to_proto(application: &Application) -> i32 {
    match application {
        Application::Piv => v1::Application::Piv as i32,
        Application::Fido2 => v1::Application::Fido2 as i32,
        Application::U2f => v1::Application::U2f as i32,
        Application::Otp => v1::Application::Otp as i32,
        Application::OpenPgp => v1::Application::OpenPgp as i32,
        Application::Oath => v1::Application::Oath as i32,
        Application::YubiHsmAuth => v1::Application::YubiHsmAuth as i32,
    }
}

fn management_key_algorithm_to_proto(algorithm: ManagementKeyAlgorithm) -> i32 {
    match algorithm {
        ManagementKeyAlgorithm::Aes128 => v1::ManagementKeyAlgorithm::Aes128 as i32,
        ManagementKeyAlgorithm::Aes192 => v1::ManagementKeyAlgorithm::Aes192 as i32,
        ManagementKeyAlgorithm::Aes256 => v1::ManagementKeyAlgorithm::Aes256 as i32,
    }
}

fn pin_policy_to_proto(policy: PinPolicy) -> i32 {
    match policy {
        PinPolicy::Default => v1::PinPolicy::Default as i32,
        PinPolicy::Never => v1::PinPolicy::Never as i32,
        PinPolicy::Once => v1::PinPolicy::Once as i32,
        PinPolicy::Always => v1::PinPolicy::Always as i32,
        PinPolicy::MatchOnce => v1::PinPolicy::MatchOnce as i32,
        PinPolicy::MatchAlways => v1::PinPolicy::MatchAlways as i32,
    }
}

fn touch_policy_to_proto(policy: TouchPolicy) -> i32 {
    match policy {
        TouchPolicy::Default => v1::TouchPolicy::Default as i32,
        TouchPolicy::Never => v1::TouchPolicy::Never as i32,
        TouchPolicy::Always => v1::TouchPolicy::Always as i32,
        TouchPolicy::Cached => v1::TouchPolicy::Cached as i32,
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
    use sigil_core::{CredentialError, DeviceDiscovery};

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

    #[tokio::test(flavor = "current_thread")]
    async fn connecting_inside_a_runtime_does_not_panic() {
        let endpoint = format!(r"\\.\pipe\sigil-test-in-runtime-{}", std::process::id());
        let error = match AgentClient::connect(Some(&endpoint)) {
            Ok(_) => panic!("the test pipe unexpectedly has a server"),
            Err(error) => error,
        };
        assert!(matches!(error, CredentialError::AgentUnavailable(_)));
    }

    #[test]
    fn installed_local_system_service_is_trusted_when_opted_in() {
        if std::env::var("SIGIL_INSTALLED_SERVICE_TESTS").as_deref() != Ok("1") {
            return;
        }
        assert!(
            std::env::var_os("SIGIL_AGENT_TRUST_UNPRIVILEGED").is_none(),
            "installed-service trust test must not use the debug bypass"
        );
        assert!(
            std::env::var_os("SIGIL_AGENT_ENDPOINT").is_none(),
            "installed-service trust test requires the default agent endpoint"
        );

        let client = AgentClient::connect(None).expect("connect to installed SigilAgent");
        let devices = client.list().expect("read installed agent device list");
        eprintln!("installed_service_device_count={}", devices.len());
    }
}
