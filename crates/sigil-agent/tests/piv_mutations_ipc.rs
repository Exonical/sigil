use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{Context, Result};
use sigil_agent::{
    caller::CallerPolicy,
    grant::{GrantVerifier, Unconfigured},
    ipc,
    server::AgentService,
};
use sigil_app::CredentialService;
use sigil_client::AgentClient;
use sigil_core::{
    Application, CredentialError, DeviceDiscovery, DeviceManagement, KeyStatus, ManagementKey,
    ManagementKeyAlgorithm, PinPolicy, PivInspection, PivKeyAlgorithm, PivKeyConfiguration,
    PivManagement, PivPin, PivPuk, PivSlot, TouchPolicy,
};
use sigil_mock::MockDiscovery;
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

fn service(mock: Arc<MockDiscovery>) -> AgentService {
    let discovery: Arc<dyn DeviceDiscovery> = mock.clone();
    let management: Arc<dyn PivManagement> = mock.clone();
    let device_management: Arc<dyn DeviceManagement> = mock;
    let credentials =
        CredentialService::new_with_device_management(discovery, management, device_management);
    AgentService::new(credentials, TEST_STATION)
        .with_policy(CallerPolicy {
            require_console_session: false,
        })
        .with_authorization(
            Arc::new(Unconfigured),
            Arc::new(GrantVerifier::new(HashMap::new())),
        )
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

#[test]
fn caller_supplied_piv_secrets_work_without_a_grant_provider() -> Result<()> {
    let mock = Arc::new(MockDiscovery::with_example());
    let server = TestServer::spawn(service(mock.clone()))?;
    let client = AgentClient::connect(Some(&server.endpoint))?;
    let id = sigil_core::DeviceId("mock-yubikey-12345678".into());
    let serial = TEST_SERIAL;

    let default_pin = PivPin::new(b"123456".to_vec())?;
    let changed_pin = PivPin::new(b"654321".to_vec())?;
    let unblocked_pin = PivPin::new(b"765432".to_vec())?;
    let default_puk = PivPuk::new(b"12345678".to_vec())?;
    let changed_puk = PivPuk::new(b"87654321".to_vec())?;
    client.change_pin(&id, serial, &default_pin, &changed_pin)?;
    client.change_puk(&id, serial, &default_puk, &changed_puk)?;
    client.unblock_pin(&id, serial, &changed_puk, &unblocked_pin)?;

    let default_key = default_management_key();
    let new_management_key = ManagementKey::new(ManagementKeyAlgorithm::Aes256, vec![0x44; 32])?;
    client.change_management_key(&id, serial, &default_key, &new_management_key)?;
    assert!(
        !client
            .generate_key(
                &id,
                serial,
                &new_management_key,
                key_configuration(PivSlot::SIGNATURE),
            )?
            .is_empty()
    );
    assert!(
        !client
            .sign_csr(
                &id,
                serial,
                &unblocked_pin,
                PivSlot::SIGNATURE,
                "CN=Mock signer",
                None,
            )?
            .is_empty()
    );
    assert!(
        !client
            .attest(&id, serial, PivSlot::SIGNATURE)?
            .attestation_der
            .is_empty()
    );

    client.import_certificate(
        &id,
        serial,
        &new_management_key,
        PivSlot::AUTHENTICATION,
        P256_CERT,
        None,
    )?;
    client.delete_certificate(&id, serial, &new_management_key, PivSlot::AUTHENTICATION)?;
    client.delete_key(&id, serial, &new_management_key, PivSlot::SIGNATURE)?;

    let key_management_slot = mock
        .piv_slots(&id)?
        .into_iter()
        .find(|slot| slot.slot == PivSlot::KEY_MANAGEMENT)
        .expect("mock key-management slot")
        .key;
    assert_eq!(
        client.generate_key(
            &id,
            "incorrect-serial",
            &new_management_key,
            key_configuration(PivSlot::KEY_MANAGEMENT),
        ),
        Err(CredentialError::DeviceMismatch)
    );
    assert_eq!(
        mock.piv_slots(&id)?
            .into_iter()
            .find(|slot| slot.slot == PivSlot::KEY_MANAGEMENT)
            .expect("mock key-management slot")
            .key,
        key_management_slot
    );
    assert_eq!(
        client.reset(&id, "incorrect-serial"),
        Err(CredentialError::DeviceMismatch)
    );
    assert_eq!(
        mock.piv_info(&id)?
            .management_key
            .as_ref()
            .and_then(|status| status.default_value),
        Some(false)
    );

    client.reset(&id, serial)?;
    let info = mock.piv_info(&id)?;
    assert_eq!(
        info.pin.as_ref().and_then(|status| status.default_value),
        Some(true)
    );
    assert_eq!(
        info.puk.as_ref().and_then(|status| status.default_value),
        Some(true)
    );
    assert_eq!(
        info.management_key
            .as_ref()
            .and_then(|status| status.default_value),
        Some(true)
    );
    assert!(
        mock.piv_slots(&id)?
            .iter()
            .all(|slot| slot.key == KeyStatus::Absent || slot.slot == PivSlot::ATTESTATION)
    );
    Ok(())
}

#[test]
fn caller_configures_supported_applications_without_a_grant() -> Result<()> {
    let mock = Arc::new(MockDiscovery::with_example());
    let server = TestServer::spawn(service(mock))?;
    let client = AgentClient::connect(Some(&server.endpoint))?;
    let id = sigil_core::DeviceId("mock-yubikey-12345678".into());

    client.set_enabled_applications(
        &id,
        TEST_SERIAL,
        &[Application::Piv, Application::Fido2, Application::Oath],
        Some(&[Application::Piv, Application::Oath]),
        None,
    )?;
    let updated = client.list()?.remove(0);
    assert_eq!(
        updated.usb_enabled,
        vec![Application::Piv, Application::Fido2, Application::Oath]
    );
    assert_eq!(
        updated.nfc_enabled,
        vec![Application::Piv, Application::Oath]
    );

    assert!(matches!(
        client.set_enabled_applications(&id, "wrong-serial", &[Application::Piv], None, None),
        Err(CredentialError::DeviceMismatch)
    ));
    assert!(matches!(
        client.set_enabled_applications(&id, TEST_SERIAL, &[Application::Fido2], None, None),
        Err(CredentialError::SmartCardOperation(_))
    ));
    Ok(())
}
