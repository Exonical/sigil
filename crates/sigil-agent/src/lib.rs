//! Privileged local agent for Sigil hardware operations.

pub mod audit;
pub mod audit_outbox;
pub mod backend;
pub mod caller;
pub mod config;
pub mod enrollment;
pub mod grant;
pub mod ipc;
pub mod secure_path;
pub mod server;

use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use sigil_app::CredentialService;
use sigil_core::{DeviceDiscovery, PivManagement};
use tokio::{
    sync::{mpsc, oneshot},
    time::{MissedTickBehavior, interval, sleep},
};

use crate::{
    audit::{AuditOutcome, AuditRecord},
    audit_outbox::AuditOutbox,
    backend::{GrpcBackend, ManagedAuthority, observed_token},
    caller::CallerPolicy,
    config::AgentConfig,
    server::AgentService,
};

#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\sigil-agent";
#[cfg(unix)]
pub const DEFAULT_ENDPOINT: &str = "/run/sigil/agent.sock";
#[cfg(not(any(unix, windows)))]
pub const DEFAULT_ENDPOINT: &str = "unsupported";

#[allow(clippy::too_many_arguments)]
pub async fn run(
    endpoint: String,
    mock: bool,
    config: AgentConfig,
    policy: CallerPolicy,
    ready: Option<oneshot::Sender<()>>,
    shutdown: oneshot::Receiver<()>,
    audit_outbox: Option<Arc<AuditOutbox>>,
    log_location: String,
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
    let backend = match GrpcBackend::from_agent_config(&config) {
        Ok(backend) => backend.map(|backend| Arc::new(backend) as Arc<dyn ManagedAuthority>),
        Err(error) => {
            tracing::warn!(%error, "backend configuration could not be loaded; managed operations are unavailable");
            None
        }
    };
    let mut service = AgentService::new(credentials.clone(), station_id)
        .with_authorization(grant_provider, grant_verifier)
        .with_log_location(log_location);
    if let Some(backend) = &backend {
        service = service.with_backend(Arc::clone(backend));
    }
    service = service.with_issuing_cas(config.issuing_cas()?);
    if let Some(outbox) = &audit_outbox {
        service = service.with_audit_outbox(Arc::clone(outbox));
    }
    let mut background_tasks = Vec::new();
    let mut token_watch_stop = None;
    if let Some(backend) = backend {
        let (token_reporter, stop) =
            spawn_token_reporter(credentials.clone(), Arc::clone(&backend));
        background_tasks.push(token_reporter);
        token_watch_stop = Some(stop);
        if let Some(outbox) = audit_outbox {
            background_tasks.push(spawn_audit_reporter(
                Arc::clone(&backend),
                Arc::clone(&outbox),
            ));
            background_tasks.push(spawn_completion_reporter(backend, outbox));
        }
    }
    let result = ipc::serve(service, endpoint, policy, ready, shutdown).await;
    if let Some(stop) = token_watch_stop {
        stop.store(true, Ordering::SeqCst);
    }
    for task in background_tasks {
        task.abort();
    }
    result?;
    Ok(())
}

fn spawn_token_reporter(
    credentials: CredentialService,
    backend: Arc<dyn ManagedAuthority>,
) -> (tokio::task::JoinHandle<()>, Arc<AtomicBool>) {
    let (notifications, mut received) = mpsc::channel(1);
    let watch_stop = Arc::new(AtomicBool::new(false));
    match credentials.watch_devices() {
        Ok(receiver) => {
            let stop = Arc::clone(&watch_stop);
            tokio::task::spawn_blocking(move || {
                while !stop.load(Ordering::SeqCst) {
                    match receiver.recv_timeout(Duration::from_millis(200)) {
                        Ok(_) => {
                            let _ = notifications.try_send(());
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });
        }
        Err(error) => {
            tracing::warn!(%error, "device-event reporting is unavailable");
            drop(notifications);
        }
    }
    let task = tokio::spawn(async move {
        let mut schedule = interval(Duration::from_secs(15 * 60));
        schedule.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut watch_open = true;
        let mut backoff = Duration::from_secs(5);
        let mut retry_now = false;
        loop {
            let changed = if retry_now {
                retry_now = false;
                true
            } else if watch_open {
                tokio::select! {
                    _ = schedule.tick() => false,
                    notification = received.recv() => {
                        if notification.is_none() {
                            watch_open = false;
                            false
                        } else {
                            true
                        }
                    }
                }
            } else {
                schedule.tick().await;
                false
            };
            if changed {
                sleep(Duration::from_secs(2)).await;
                while received.try_recv().is_ok() {}
            }
            let inventory = credentials.clone();
            let devices = match tokio::task::spawn_blocking(move || inventory.devices()).await {
                Ok(Ok(devices)) => devices,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "could not enumerate tokens for backend reporting");
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "token reporting task failed");
                    continue;
                }
            };
            let tokens = devices.iter().filter_map(observed_token).collect();
            match backend.report_tokens(tokens).await {
                Ok(()) => backoff = Duration::from_secs(5),
                Err(error) => {
                    tracing::warn!(
                        code = ?error.code(),
                        message = %error.message(),
                        "backend token report failed"
                    );
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(Duration::from_secs(5 * 60));
                    retry_now = true;
                }
            }
        }
    });
    (task, watch_stop)
}

fn spawn_audit_reporter(
    backend: Arc<dyn ManagedAuthority>,
    outbox: Arc<AuditOutbox>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut schedule = interval(Duration::from_secs(10));
        schedule.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut backoff = Duration::from_secs(5);
        let mut retry_now = false;
        loop {
            if retry_now {
                retry_now = false;
            } else {
                schedule.tick().await;
            }
            let events = match outbox.batch(200) {
                Ok(events) => events,
                Err(error) => {
                    tracing::warn!(target: "sigil::agent", %error, "could not read agent audit outbox");
                    continue;
                }
            };
            if events.is_empty() {
                continue;
            }
            match backend.report_audit(events).await {
                Ok(accepted_through) => match outbox.ack(accepted_through) {
                    Ok(()) => backoff = Duration::from_secs(5),
                    Err(error) => {
                        tracing::warn!(target: "sigil::agent", %error, "could not compact agent audit outbox");
                    }
                },
                Err(error) => {
                    tracing::warn!(
                        code = ?error.code(),
                        message = %error.message(),
                        "backend audit report failed"
                    );
                    sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(Duration::from_secs(5 * 60));
                    retry_now = true;
                }
            }
        }
    })
}

fn spawn_completion_reporter(
    backend: Arc<dyn ManagedAuthority>,
    outbox: Arc<AuditOutbox>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut schedule = interval(Duration::from_secs(10));
        schedule.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut retry_schedule: HashMap<String, (Instant, Duration)> = HashMap::new();
        loop {
            schedule.tick().await;
            let completions = match outbox.pending_completions() {
                Ok(completions) => completions,
                Err(error) => {
                    tracing::warn!(target: "sigil::agent", %error, "could not read pending rotation completions");
                    continue;
                }
            };
            for completion in completions {
                if retry_schedule
                    .get(&completion.rotation_id)
                    .is_some_and(|(next_retry, _)| *next_retry > Instant::now())
                {
                    continue;
                }
                if crate::backend::current_unix_millis()
                    .saturating_sub(completion.created_at_unix_ms)
                    > 14 * 60 * 1000
                {
                    let _ = outbox.remove_completion(&completion.rotation_id);
                    retry_schedule.remove(&completion.rotation_id);
                    audit_completion_expired(&completion.rotation_id);
                    continue;
                }
                match backend
                    .complete_rotation(&completion.rotation_id, completion.applied)
                    .await
                {
                    Ok(()) => {
                        retry_schedule.remove(&completion.rotation_id);
                        if outbox.remove_completion(&completion.rotation_id).is_err() {
                            tracing::warn!(
                                target: "sigil::agent",
                                "could not remove acknowledged rotation completion"
                            );
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            code = ?error.code(),
                            message = %error.message(),
                            "backend rotation completion retry failed"
                        );
                        let retry = retry_schedule
                            .entry(completion.rotation_id.clone())
                            .or_insert((Instant::now(), Duration::from_secs(5)));
                        retry.0 = Instant::now() + retry.1;
                        retry.1 = retry.1.saturating_mul(2).min(Duration::from_secs(60));
                    }
                }
            }
        }
    })
}

fn audit_completion_expired(rotation_id: &str) {
    audit::emit(&AuditRecord {
        rpc: "CompleteRotation",
        operation: "rotation_completion",
        device_id: "",
        token_serial: "",
        piv_slot: None,
        caller: None,
        outcome: AuditOutcome::Error,
        code: "completion_expired",
        grant_id: "",
        rotation_id,
    });
    tracing::error!(
        target: "sigil::agent",
        rotation_id,
        "pending rotation completion expired before backend confirmation"
    );
}

pub async fn retry_pending_completions_once(
    backend: &dyn ManagedAuthority,
    outbox: &AuditOutbox,
) -> anyhow::Result<()> {
    for completion in outbox.pending_completions()? {
        if crate::backend::current_unix_millis().saturating_sub(completion.created_at_unix_ms)
            > 14 * 60 * 1000
        {
            outbox.remove_completion(&completion.rotation_id)?;
            audit_completion_expired(&completion.rotation_id);
            continue;
        }
        if backend
            .complete_rotation(&completion.rotation_id, completion.applied)
            .await
            .is_ok()
        {
            outbox.remove_completion(&completion.rotation_id)?;
        }
    }
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
