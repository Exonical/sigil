//! Privileged local agent for Sigil hardware operations.

pub mod caller;
pub mod config;
pub mod grant;
pub mod ipc;
pub mod secure_path;
pub mod server;

use std::sync::Arc;

use sigil_app::CredentialService;
use sigil_core::{DeviceDiscovery, PivManagement};
use tokio::sync::oneshot;

use crate::{caller::CallerPolicy, config::AgentConfig, server::AgentService};

#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\sigil-agent";
#[cfg(unix)]
pub const DEFAULT_ENDPOINT: &str = "/run/sigil/agent.sock";
#[cfg(not(any(unix, windows)))]
pub const DEFAULT_ENDPOINT: &str = "unsupported";

pub async fn run(
    endpoint: String,
    mock: bool,
    config: AgentConfig,
    policy: CallerPolicy,
    ready: Option<oneshot::Sender<()>>,
    shutdown: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let (discovery, piv_management, device_management): (
        Arc<dyn DeviceDiscovery>,
        Arc<dyn PivManagement>,
        Arc<dyn sigil_core::DeviceManagement>,
    ) = if mock {
        let mock = Arc::new(sigil_mock::MockDiscovery::with_example());
        (mock.clone(), mock.clone(), mock)
    } else {
        let native = Arc::new(sigil_platform::NativeDiscovery);
        (native.clone(), native.clone(), native)
    };
    let credentials =
        CredentialService::new_with_device_management(discovery, piv_management, device_management);
    let station_id = config.station_id();
    let (grant_provider, grant_verifier) = config.authorization()?;
    let service = AgentService::new(credentials, station_id)
        .with_authorization(grant_provider, grant_verifier);
    ipc::serve(service, endpoint, policy, ready, shutdown).await?;
    Ok(())
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        thread::JoinHandle,
        time::Duration,
    };

    use anyhow::{Context, Result};
    use sigil_app::CredentialService;
    use sigil_core::{DeviceDiscovery, DeviceManagement, PivManagement};
    use sigil_mock::MockDiscovery;
    use tokio::{runtime::Builder, sync::oneshot};

    use crate::{ipc, server::AgentService};

    static NEXT_TEST_ENDPOINT: AtomicU64 = AtomicU64::new(1);

    pub struct TestAgent {
        endpoint: String,
        stop: Option<oneshot::Sender<()>>,
        thread: Option<JoinHandle<()>>,
        mock: Option<Arc<MockDiscovery>>,
    }

    impl TestAgent {
        pub fn spawn_mock() -> Result<Self> {
            let mock = Arc::new(MockDiscovery::with_example());
            let discovery: Arc<dyn DeviceDiscovery> = mock.clone();
            let piv_management: Arc<dyn PivManagement> = mock.clone();
            let device_management: Arc<dyn DeviceManagement> = mock.clone();
            let service = CredentialService::new_with_device_management(
                discovery,
                piv_management,
                device_management,
            );
            let agent_service = AgentService::new(service, "sigil-test-station");
            Self::spawn_service_inner(agent_service, Some(mock))
        }

        pub fn spawn_service(service: AgentService) -> Result<Self> {
            Self::spawn_service_inner(service, None)
        }

        fn spawn_service_inner(
            service: AgentService,
            mock: Option<Arc<MockDiscovery>>,
        ) -> Result<Self> {
            let endpoint = unique_endpoint();
            let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
            let (stop, shutdown) = oneshot::channel();
            let thread_endpoint = endpoint.clone();
            let thread = std::thread::spawn(move || {
                let runtime = Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime");
                let (ready, ready_rx) = oneshot::channel();
                runtime.block_on(async move {
                    let server = tokio::spawn(ipc::serve_for_test(
                        service,
                        thread_endpoint,
                        ready,
                        shutdown,
                    ));
                    if ready_rx.await.is_ok() {
                        let _ = ready_sender.send(());
                    }
                    if let Err(error) = server.await {
                        tracing::warn!(%error, "test agent task stopped");
                    }
                });
            });
            ready_receiver
                .recv_timeout(Duration::from_secs(10))
                .context("test agent IPC endpoint did not start")?;
            Ok(Self {
                endpoint,
                stop: Some(stop),
                thread: Some(thread),
                mock,
            })
        }

        pub fn endpoint(&self) -> &str {
            &self.endpoint
        }

        pub fn mock(&self) -> Option<&Arc<MockDiscovery>> {
            self.mock.as_ref()
        }
    }

    impl Drop for TestAgent {
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

    fn unique_endpoint() -> String {
        let suffix = NEXT_TEST_ENDPOINT.fetch_add(1, Ordering::Relaxed);
        #[cfg(windows)]
        {
            format!(r"\\.\pipe\sigil-test-{}-{suffix}", std::process::id())
        }
        #[cfg(unix)]
        {
            std::env::temp_dir()
                .join(format!("sigil-test-{}-{suffix}.sock", std::process::id()))
                .to_string_lossy()
                .into_owned()
        }
    }
}
