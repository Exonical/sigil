use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sigil_agent::{caller::CallerPolicy, config::AgentConfig};
use tokio::{runtime::Builder, sync::oneshot};

#[derive(Parser)]
#[command(name = "sigil-agent", about = "Privileged local Sigil hardware agent")]
struct Args {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(long)]
        mock: bool,
        #[arg(long)]
        endpoint: Option<String>,
        #[cfg(debug_assertions)]
        #[arg(long)]
        dev_insecure_config: bool,
    },
    Service,
    Install {
        #[cfg(debug_assertions)]
        #[arg(long)]
        allow_unprotected_path: bool,
    },
    Uninstall,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let config_path = args.config.clone();
    match args.command {
        #[cfg(debug_assertions)]
        Command::Run {
            mock,
            endpoint,
            dev_insecure_config,
        } => run_agent_mode(config_path, mock, endpoint, dev_insecure_config),
        #[cfg(not(debug_assertions))]
        Command::Run { mock, endpoint } => run_agent_mode(config_path, mock, endpoint, false),
        Command::Service => {
            #[cfg(windows)]
            return windows_service::dispatch(config_path);
            #[cfg(not(windows))]
            anyhow::bail!("the service command is only available on Windows")
        }
        #[cfg(all(windows, debug_assertions))]
        Command::Install {
            allow_unprotected_path,
        } => windows_service::install(config_path.as_deref(), allow_unprotected_path),
        #[cfg(all(windows, not(debug_assertions)))]
        Command::Install {} => windows_service::install(config_path.as_deref(), false),
        #[cfg(not(windows))]
        Command::Install { .. } => {
            anyhow::bail!("service installation is only available on Windows")
        }
        Command::Uninstall => {
            #[cfg(windows)]
            return windows_service::uninstall();
            #[cfg(not(windows))]
            anyhow::bail!("service removal is only available on Windows")
        }
    }
}

fn run_agent_mode(
    config_path: Option<PathBuf>,
    mock: bool,
    endpoint: Option<String>,
    allow_insecure_paths: bool,
) -> Result<()> {
    init_stderr_logging()?;
    #[cfg(debug_assertions)]
    let config = if allow_insecure_paths {
        AgentConfig::load_development(config_path)?
    } else {
        AgentConfig::load(config_path)?
    };
    #[cfg(not(debug_assertions))]
    let config = {
        let _ = allow_insecure_paths;
        AgentConfig::load(config_path)?
    };
    let endpoint = endpoint
        .or_else(|| std::env::var("SIGIL_AGENT_ENDPOINT").ok())
        .unwrap_or_else(|| sigil_agent::DEFAULT_ENDPOINT.to_owned());
    run_foreground(config, endpoint, mock)
}

fn run_foreground(config: AgentConfig, endpoint: String, mock: bool) -> Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    runtime.block_on(async move {
        let mut server = tokio::spawn(sigil_agent::run(
            endpoint,
            mock,
            config,
            CallerPolicy::production(),
            None,
            shutdown_rx,
        ));
        tokio::select! {
            result = &mut server => result.context("agent server task panicked")??,
            signal = wait_for_shutdown() => {
                signal.context("could not listen for Ctrl-C")?;
                let _ = shutdown_tx.send(());
                server.await.context("agent server task panicked")??;
            }
        }
        Ok(())
    })
}

#[cfg(unix)]
async fn wait_for_shutdown() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(windows)]
async fn wait_for_shutdown() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

fn log_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        .add_directive("sigil::audit=info".parse().expect("valid audit filter"))
}

fn init_stderr_logging() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|error| anyhow::anyhow!("could not initialize agent logging: {error}"))
}

#[cfg(windows)]
mod windows_service {
    use std::{ffi::OsString, path::Path, sync::Mutex, time::Duration};

    use anyhow::{Context, Result, anyhow};
    use sigil_agent::{caller::CallerPolicy, config::AgentConfig};
    use tokio::{
        runtime::Builder,
        sync::{oneshot, watch},
    };
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    const SERVICE_NAME: &str = "SigilAgent";

    pub fn dispatch(config: Option<std::path::PathBuf>) -> Result<()> {
        *SERVICE_CONFIG.lock().expect("service config lock") = config;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("could not connect to the Windows Service Control Manager")
    }

    static SERVICE_CONFIG: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        if let Err(error) = run_service() {
            tracing::error!(%error, "SigilAgent service failed");
            eprintln!("SigilAgent service failed: {error:#}");
        }
    }

    fn run_service() -> Result<()> {
        let (stop_sender, stop_receiver) = watch::channel(false);
        let handler = move |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_sender.send(true);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;
        status_handle.set_service_status(service_status(ServiceState::StartPending, 0))?;
        let result = run_service_after_start(&status_handle, stop_receiver);
        status_handle.set_service_status(service_status(
            ServiceState::Stopped,
            u32::from(result.is_err()),
        ))?;
        result
    }

    fn run_service_after_start(
        status_handle: &windows_service::service_control_handler::ServiceStatusHandle,
        mut stop_receiver: watch::Receiver<bool>,
    ) -> Result<()> {
        let config_path = SERVICE_CONFIG
            .lock()
            .map_err(|_| anyhow!("service config lock poisoned"))?
            .clone();
        let paths = sigil_agent::secure_path::prepare_agent_paths(config_path.as_deref())?;
        init_file_logging(&paths.log_file)?;
        let config = AgentConfig::load(Some(paths.config_file))?;
        let endpoint = std::env::var("SIGIL_AGENT_ENDPOINT")
            .unwrap_or_else(|_| sigil_agent::DEFAULT_ENDPOINT.to_owned());

        let runtime = Builder::new_multi_thread().enable_all().build()?;
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let (ready_sender, ready_receiver) = oneshot::channel();
        let mut task = runtime.spawn(sigil_agent::run(
            endpoint,
            false,
            config,
            CallerPolicy::production(),
            Some(ready_sender),
            shutdown_receiver,
        ));
        let server_result = runtime.block_on(async {
            tokio::select! {
                result = &mut task => result.context("agent server task panicked")?,
                ready = ready_receiver => {
                    ready.context("agent server stopped before its IPC endpoint was ready")?;
                    status_handle
                        .set_service_status(service_status(ServiceState::Running, 0))
                        .context("could not report service running")?;
                    tokio::select! {
                        result = &mut task => result.context("agent server task panicked")?,
                        _ = stop_receiver.changed() => {
                            status_handle
                                .set_service_status(service_status(ServiceState::StopPending, 0))
                                .context("could not report service stop pending")?;
                            let _ = shutdown_sender.send(());
                            task.await.context("agent server task panicked")?
                        }
                    }
                }
            }
        });
        if let Err(error) = &server_result {
            tracing::error!(%error, "agent server stopped with error");
        }
        server_result
    }

    fn service_status(state: ServiceState, exit_code: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(exit_code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        }
    }

    pub fn install(config_path: Option<&Path>, allow_unprotected_path: bool) -> Result<()> {
        let executable = std::env::current_exe()?;
        let executable_directory = executable
            .parent()
            .ok_or_else(|| anyhow!("service executable has no parent directory"))?;
        if let Err(error) = sigil_agent::secure_path::ensure_protected_dir(executable_directory) {
            if allow_unprotected_path {
                eprintln!(
                    "DANGER: installing a LocalSystem service from an unprotected directory ({}): {error:#}. This is for development only; any user able to replace the binary can obtain SYSTEM.",
                    executable_directory.display()
                );
            } else {
                return Err(error).context(format!(
                    "refusing to install a LocalSystem service from unprotected executable directory {}; pass --allow-unprotected-path only for development",
                    executable_directory.display()
                ));
            }
        }
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("service installation requires an elevated administrator session")?;
        let mut arguments = vec![OsString::from("service")];
        if let Some(path) = config_path {
            arguments.push(OsString::from("--config"));
            arguments.push(path.as_os_str().to_owned());
        }
        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("Sigil Agent"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: executable,
            launch_arguments: arguments,
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        manager
            .create_service(&service_info, ServiceAccess::CHANGE_CONFIG)
            .context("could not install Sigil Agent; run as administrator")?;
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("service removal requires an elevated administrator session")?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )?;
        service.delete()?;
        if service.query_status()?.current_state != ServiceState::Stopped {
            service.stop()?;
        }
        Ok(())
    }

    fn init_file_logging(path: &Path) -> Result<()> {
        let file = sigil_agent::secure_path::open_service_log(path)?;
        tracing_subscriber::fmt()
            .with_env_filter(super::log_filter())
            .with_ansi(false)
            .with_writer(move || file.try_clone().expect("agent log writer clone"))
            .try_init()
            .map_err(|error| anyhow!("could not initialize service log: {error}"))
    }
}
