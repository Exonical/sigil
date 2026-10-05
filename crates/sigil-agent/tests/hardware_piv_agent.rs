#![cfg(target_os = "windows")]

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{Context, Result};
use sigil_agent::{caller::CallerPolicy, ipc, server::AgentService};
use sigil_app::CredentialService;
use sigil_client::AgentClient;
use sigil_core::{
    CredentialError, DeviceDiscovery, KeyStatus, ManagementKey, ManagementKeyAlgorithm, PinPolicy,
    PivAlgorithm, PivInfo, PivInspection, PivKeyAlgorithm, PivKeyConfiguration, PivManagement,
    PivPin, PivPuk, PivSlot, TouchPolicy,
};
use sigil_platform::NativeDiscovery;
use tokio::{runtime::Builder, sync::oneshot};

static NEXT_ENDPOINT: AtomicU64 = AtomicU64::new(1);
const TEST_STATION: &str = "m4-hardware-station";
const APPROVED_SERIAL: &str = "39192733";
const DEFAULT_MGMT: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

struct ResetGuard {
    discovery: NativeDiscovery,
    id: sigil_core::DeviceId,
    serial: String,
    armed: bool,
}

impl ResetGuard {
    fn arm(discovery: NativeDiscovery, id: sigil_core::DeviceId, serial: String) -> Self {
        Self {
            discovery,
            id,
            serial,
            armed: true,
        }
    }

    fn disarm_after_verifying_defaults(&mut self) -> Result<()> {
        verify_factory_defaults(&self.discovery, &self.id, &self.serial)?;
        println!("reset_verified=true");
        self.armed = false;
        Ok(())
    }
}

impl Drop for ResetGuard {
    fn drop(&mut self) {
        if self.armed {
            let reset_verified = self
                .discovery
                .reset(&self.id, &self.serial)
                .and_then(|()| verify_factory_defaults(&self.discovery, &self.id, &self.serial))
                .is_ok();
            println!("reset_verified={reset_verified}");
        }
    }
}

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
                .expect("agent test runtime");
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
            .context("in-process agent endpoint did not start")?;
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
        r"\\.\pipe\sigil-m4-agent-hardware-{}-{}",
        std::process::id(),
        NEXT_ENDPOINT.fetch_add(1, Ordering::Relaxed)
    )
}

#[test]
fn agent_ipc_mutates_only_the_serial_confirmed_hardware_key_and_resets() -> Result<()> {
    if std::env::var("SIGIL_HARDWARE_TESTS").as_deref() != Ok("1") {
        return Ok(());
    }
    let mutation_serial = std::env::var("SIGIL_HARDWARE_MUTATION_SERIAL")
        .context("set SIGIL_HARDWARE_MUTATION_SERIAL to the authorized serial")?;
    assert_eq!(
        mutation_serial, APPROVED_SERIAL,
        "refusing an unapproved serial"
    );
    let discovery = NativeDiscovery;
    let devices = discovery.list()?;
    let matches = devices
        .into_iter()
        .filter(|device| {
            device.id.0.starts_with("windows-pcsc:")
                && device.serial.as_deref() == Some(APPROVED_SERIAL)
        })
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "serial must identify exactly one reader");
    let device = matches.into_iter().next().expect("serial-matched device");
    println!("serial={APPROVED_SERIAL}");
    assert_factory_defaults(&discovery, &device.id, APPROVED_SERIAL);
    let initial_slots = discovery.piv_slots(&device.id)?;
    for slot in PivSlot::STANDARD {
        let status = initial_slots
            .iter()
            .find(|entry| entry.slot == slot)
            .unwrap_or_else(|| panic!("preflight omitted slot {slot}"));
        assert_eq!(status.key, KeyStatus::Absent);
        assert!(status.certificate.is_none());
    }
    assert!(
        discovery
            .piv_certificate(&device.id, PivSlot::ATTESTATION)?
            .is_some(),
        "factory F9 certificate must be present"
    );

    let discovery_arc = Arc::new(NativeDiscovery);
    let discovery_trait: Arc<dyn DeviceDiscovery> = discovery_arc.clone();
    let management_trait: Arc<dyn PivManagement> = discovery_arc.clone();
    let credentials = CredentialService::new_with_piv_management(discovery_trait, management_trait);
    let service = AgentService::new(credentials, TEST_STATION).with_policy(CallerPolicy {
        require_console_session: false,
    });
    let server = TestServer::spawn(service)?;
    let client = AgentClient::connect(Some(&server.endpoint))?;
    let mut guard = ResetGuard::arm(discovery, device.id.clone(), APPROVED_SERIAL.into());

    let initial_pin = PivPin::new(b"123456".to_vec())?;
    let pin1 = PivPin::new(random_code())?;
    println!("operation=change_pin slot=none");
    client.change_pin(&device.id, APPROVED_SERIAL, &initial_pin, &pin1)?;

    let default_puk = PivPuk::new(b"12345678".to_vec())?;
    let puk1 = PivPuk::new(random_code())?;
    println!("operation=change_puk slot=none");
    client.change_puk(&device.id, APPROVED_SERIAL, &default_puk, &puk1)?;

    let default_management_key =
        ManagementKey::new(ManagementKeyAlgorithm::Aes192, DEFAULT_MGMT.to_vec())?;
    let management_key =
        CredentialService::generate_management_key(ManagementKeyAlgorithm::Aes256)?;
    println!("operation=change_management_key slot=none");
    client.change_management_key(
        &device.id,
        APPROVED_SERIAL,
        &default_management_key,
        &management_key,
    )?;

    println!("operation=generate_key slot=9a");
    let public_spki = client.generate_key(
        &device.id,
        APPROVED_SERIAL,
        &management_key,
        PivKeyConfiguration {
            slot: PivSlot::AUTHENTICATION,
            algorithm: PivKeyAlgorithm::EccP256,
            pin_policy: PinPolicy::Once,
            touch_policy: TouchPolicy::Never,
        },
    )?;
    assert!(!public_spki.is_empty());

    println!("operation=delete_key slot=9a");
    client.delete_key(
        &device.id,
        APPROVED_SERIAL,
        &management_key,
        PivSlot::AUTHENTICATION,
    )?;
    println!("operation=reset slot=none");
    client.reset(&device.id, APPROVED_SERIAL)?;
    guard.disarm_after_verifying_defaults()?;
    Ok(())
}

fn assert_factory_defaults(discovery: &NativeDiscovery, id: &sigil_core::DeviceId, serial: &str) {
    verify_factory_defaults(discovery, id, serial).expect("PIV factory defaults");
}

fn verify_factory_defaults(
    discovery: &NativeDiscovery,
    id: &sigil_core::DeviceId,
    serial: &str,
) -> sigil_core::Result<()> {
    let device = discovery
        .list()?
        .into_iter()
        .find(|device| device.id == *id)
        .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))?;
    if device.serial.as_deref() != Some(serial) {
        return Err(CredentialError::DeviceMismatch);
    }
    if device.fips != Some(true) {
        return Err(CredentialError::SmartCardOperation(
            "authorized device is not reported as FIPS-capable".into(),
        ));
    }
    let PivInfo {
        pin,
        puk,
        management_key,
        ..
    } = discovery.piv_info(id)?;
    for retry in [pin, puk] {
        let retry = retry.ok_or_else(|| {
            CredentialError::SmartCardOperation("PIV retry metadata is unavailable".into())
        })?;
        if retry.remaining != 3 || retry.total != Some(3) || retry.default_value != Some(true) {
            return Err(CredentialError::SmartCardOperation(
                "PIV factory retry defaults were not restored".into(),
            ));
        }
    }
    let management_key = management_key.ok_or_else(|| {
        CredentialError::SmartCardOperation("PIV management-key metadata is unavailable".into())
    })?;
    if management_key.algorithm != PivAlgorithm::Aes192
        || management_key.default_value != Some(true)
    {
        return Err(CredentialError::SmartCardOperation(
            "PIV factory management-key defaults were not restored".into(),
        ));
    }
    let slots = discovery.piv_slots(id)?;
    for slot in PivSlot::STANDARD {
        let info = slots.iter().find(|info| info.slot == slot).ok_or_else(|| {
            CredentialError::SmartCardOperation(format!("PIV slot {slot} is unavailable"))
        })?;
        if info.key != KeyStatus::Absent || info.certificate.is_some() {
            return Err(CredentialError::SmartCardOperation(
                "PIV factory slots were not restored".into(),
            ));
        }
    }
    if !slots
        .iter()
        .any(|info| info.slot == PivSlot::ATTESTATION && info.certificate.is_some())
    {
        return Err(CredentialError::SmartCardOperation(
            "factory F9 certificate is missing".into(),
        ));
    }
    Ok(())
}

fn random_code() -> Vec<u8> {
    const CHARACTERS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut result = Vec::with_capacity(8);
    while result.len() < 8 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).expect("OS random source");
        for byte in random {
            if byte < 248 {
                result.push(CHARACTERS[usize::from(byte % 62)]);
                if result.len() == 8 {
                    break;
                }
            }
        }
    }
    result
}
