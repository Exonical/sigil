use std::{ops::Deref, sync::Arc};

use anyhow::Result;
use clap::{Parser, Subcommand};
use sigil_app::CredentialService;
use sigil_client::AgentClient;
use sigil_core::{DeviceId, DeviceInfo};

mod piv;

#[derive(Parser)]
#[command(name = "cms", about = "Sigil credential manager")]
struct Args {
    #[arg(long, global = true)]
    agent: Option<String>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Fido {
        #[command(subcommand)]
        command: FidoCommand,
    },
    Piv {
        #[command(subcommand)]
        command: piv::PivCommand,
    },
}

#[derive(Subcommand)]
enum FidoCommand {
    Info {
        device: String,
    },
    Credentials {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    Fingerprints {
        #[command(subcommand)]
        command: FingerprintCommand,
    },
}

#[derive(Subcommand)]
enum FingerprintCommand {
    List {
        device: String,
    },
    Enroll {
        device: String,
    },
    Remove {
        device: String,
        fingerprint_id: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum CredentialCommand {
    List { device: String },
}

#[derive(Subcommand)]
enum DeviceCommand {
    List,
    Info { device: String },
}

struct Services {
    credentials: CredentialService,
    agent: Arc<AgentClient>,
}

impl Deref for Services {
    type Target = CredentialService;

    fn deref(&self) -> &Self::Target {
        &self.credentials
    }
}

fn service(endpoint: Option<&str>) -> Result<Services> {
    let agent = Arc::new(AgentClient::connect(endpoint)?);
    let discovery: Arc<dyn sigil_core::DeviceDiscovery> = agent.clone();
    Ok(Services {
        credentials: CredentialService::new(discovery),
        agent,
    })
}

fn render_list(devices: &[DeviceInfo], json: bool) -> Result<String> {
    if json {
        return Ok(serde_json::to_string_pretty(devices)?);
    }
    if devices.is_empty() {
        return Ok("No credential devices found.".into());
    }
    let mut lines = vec![format!("{:<30}  {:<28}  SERIAL", "ID", "MODEL")];
    for device in devices {
        lines.push(format!(
            "{:<30}  {:<28}  {}",
            device.id.0,
            device.model,
            device.serial.as_deref().unwrap_or("unknown")
        ));
    }
    Ok(lines.join("\n"))
}

fn run(args: Args) -> Result<String> {
    let service = service(args.agent.as_deref())?;
    match args.command {
        Command::Device {
            command: DeviceCommand::List,
        } => render_list(&service.devices()?, args.json),
        Command::Device {
            command: DeviceCommand::Info { device },
        } => {
            let info = service.device(&DeviceId(device))?;
            if args.json {
                Ok(serde_json::to_string_pretty(&info)?)
            } else {
                Ok(format!(
                    "{}\nID: {}\nVendor: {}\nConnection: {}\nSerial: {}\nFirmware: {}\nForm factor: {}\nEnabled applications: {}\nSupported applications: {}\nSimulated: {}",
                    info.model,
                    info.id.0,
                    info.vendor,
                    info.connection
                        .as_ref()
                        .map(|connection| format!("{connection:?}"))
                        .unwrap_or_else(|| "unknown".into()),
                    info.serial.as_deref().unwrap_or("unknown"),
                    info.firmware
                        .as_ref()
                        .map(|v| format!("{}.{}.{}", v.major, v.minor, v.patch))
                        .unwrap_or_else(|| "unknown".into()),
                    info.form_factor.as_deref().unwrap_or("unknown"),
                    info.applications
                        .iter()
                        .map(|app| format!("{app:?}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    info.supported_applications
                        .iter()
                        .map(|app| format!("{app:?}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    info.simulated
                ))
            }
        }
        Command::Piv { command } => {
            piv::handle(&service.credentials, &service.agent, command, args.json)
        }
        Command::Fido {
            command: FidoCommand::Info { device },
        } => {
            let status = service.fido_status(&DeviceId(device))?;
            if args.json {
                Ok(serde_json::to_string_pretty(&status)?)
            } else {
                Ok(format!(
                    "Versions: {}\nPIN set: {:?}\nPIN retries: {:?}\nCredential management: {}",
                    status.versions.join(", "),
                    status.pin_set,
                    status.pin_retries,
                    status.credential_management
                ))
            }
        }
        Command::Fido {
            command:
                FidoCommand::Credentials {
                    command: CredentialCommand::List { device },
                },
        } => {
            let id = DeviceId(device);
            let status = service.fido_status(&id)?;
            if !status.credential_management {
                anyhow::bail!("this key does not support discoverable credential management");
            }
            let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
            eprintln!();
            let credentials = service.discoverable_credentials(&id, &pin)?;
            if args.json {
                Ok(serde_json::to_string_pretty(&credentials)?)
            } else if credentials.is_empty() {
                Ok("No discoverable credentials found.".into())
            } else {
                Ok(credentials
                    .iter()
                    .map(|entry| {
                        format!(
                            "{}  {}  {}",
                            entry.rp_id, entry.user_name, entry.credential_id
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
        }
        Command::Fido {
            command: FidoCommand::Fingerprints { command },
        } => {
            let (device, action) = match command {
                FingerprintCommand::List { device } => (device, (None, false)),
                FingerprintCommand::Enroll { device } => (device, (None, true)),
                FingerprintCommand::Remove {
                    device,
                    fingerprint_id,
                    yes,
                } => {
                    if !yes {
                        anyhow::bail!(
                            "fingerprint deletion is permanent; repeat with --yes to confirm"
                        );
                    }
                    (device, (Some(fingerprint_id), false))
                }
            };
            let id = DeviceId(device);
            let status = service.fido_status(&id)?;
            if !status.fingerprint_enrollment {
                anyhow::bail!("this key does not support FIDO fingerprint enrollment");
            }
            let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
            eprintln!();
            match action {
                (Some(fingerprint_id), _) => {
                    service.remove_fingerprint(&id, &pin, &fingerprint_id)?;
                    Ok(if args.json {
                        "{\"removed\":true}".into()
                    } else {
                        "Fingerprint removed.".into()
                    })
                }
                (_, true) => {
                    let fingerprint = service.enroll_fingerprint(&id, &pin, &mut |progress| {
                        eprintln!(
                            "{} (remaining samples: {})",
                            progress.message, progress.remaining_samples
                        );
                    })?;
                    if args.json {
                        Ok(serde_json::to_string_pretty(&fingerprint)?)
                    } else {
                        Ok(format!("Fingerprint enrolled: {}", fingerprint.id))
                    }
                }
                _ => {
                    let fingerprints = service.fingerprints(&id, &pin)?;
                    if args.json {
                        Ok(serde_json::to_string_pretty(&fingerprints)?)
                    } else if fingerprints.is_empty() {
                        Ok("No fingerprints enrolled.".into())
                    } else {
                        Ok(fingerprints
                            .into_iter()
                            .map(|fingerprint| {
                                format!(
                                    "{}  {}",
                                    fingerprint.id,
                                    fingerprint.name.unwrap_or_default()
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n"))
                    }
                }
            }
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let output = run(Args::parse())?;
    println!("{output}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use sigil_agent::test_support::TestAgent;
    use sigil_core::{DeviceDiscovery, DeviceEvent, FidoInspection};

    use super::*;

    fn parse_for_agent(agent: &TestAgent, command: &[&str]) -> Result<Args> {
        let mut args = vec![
            "cms".to_owned(),
            "--agent".to_owned(),
            agent.endpoint().to_owned(),
        ];
        args.extend(command.iter().map(|value| (*value).to_owned()));
        Ok(Args::try_parse_from(args)?)
    }

    fn start_mock_agent() -> Result<TestAgent> {
        TestAgent::spawn_mock()
    }

    #[test]
    fn json_list_is_parseable_and_clearly_simulated() -> Result<()> {
        let agent = start_mock_agent()?;
        let args = parse_for_agent(&agent, &["device", "list", "--json"])?;
        let result: Vec<DeviceInfo> = serde_json::from_str(&run(args)?)?;
        assert_eq!(result.len(), 1);
        assert!(result[0].simulated);
        assert_eq!(result[0].id.0, "mock-yubikey-12345678");
        Ok(())
    }

    #[test]
    fn explicit_device_selection() -> Result<()> {
        let agent = start_mock_agent()?;
        let args = parse_for_agent(
            &agent,
            &["device", "info", "mock-yubikey-12345678", "--json"],
        )?;
        let output: serde_json::Value = serde_json::from_str(&run(args)?)?;
        assert_eq!(output["connection"], "usb_smart_card");
        let value: DeviceInfo = serde_json::from_value(output)?;
        assert_eq!(value.serial.as_deref(), Some("12345678"));
        Ok(())
    }

    #[test]
    fn fido_status_is_structured_for_selected_device() -> Result<()> {
        let agent = start_mock_agent()?;
        let args = parse_for_agent(&agent, &["fido", "info", "mock-yubikey-12345678", "--json"])?;
        let value: sigil_core::FidoStatus = serde_json::from_str(&run(args)?)?;
        assert!(value.credential_management);
        assert_eq!(value.pin_retries, Some(8));
        Ok(())
    }

    #[test]
    fn piv_slots_json_includes_fixture_and_absent_standard_slot() -> Result<()> {
        let agent = start_mock_agent()?;
        let args = parse_for_agent(&agent, &["piv", "slots", "mock-yubikey-12345678", "--json"])?;
        let slots: Vec<sigil_core::PivSlotInfo> = serde_json::from_str(&run(args)?)?;
        assert_eq!(slots.len(), 4);
        let signature = slots
            .iter()
            .find(|slot| slot.slot == sigil_core::PivSlot::SIGNATURE)
            .unwrap();
        assert_eq!(signature.key, sigil_core::KeyStatus::Absent);
        let authentication = slots
            .iter()
            .find(|slot| slot.slot == sigil_core::PivSlot::AUTHENTICATION)
            .unwrap();
        assert!(
            authentication
                .certificate
                .as_ref()
                .unwrap()
                .subject
                .contains("Simulated PIV Authentication")
        );
        Ok(())
    }

    #[test]
    fn piv_info_json_reports_retry_status() -> Result<()> {
        let agent = start_mock_agent()?;
        let args = parse_for_agent(&agent, &["piv", "info", "mock-yubikey-12345678", "--json"])?;
        let info: sigil_core::PivInfo = serde_json::from_str(&run(args)?)?;
        assert_eq!(info.pin.unwrap().remaining, 3);
        Ok(())
    }

    #[test]
    fn piv_certificate_show_and_export_handle_missing_and_existing_paths() -> Result<()> {
        let agent = start_mock_agent()?;
        let missing = parse_for_agent(
            &agent,
            &["piv", "certificate", "show", "mock-yubikey-12345678", "9c"],
        )?;
        assert!(run(missing).is_err());

        let path = std::env::temp_dir().join(format!(
            "sigil-piv-{}.pem",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path_argument = path.to_string_lossy().to_string();
        let export_args = || {
            parse_for_agent(
                &agent,
                &[
                    "piv",
                    "certificate",
                    "export",
                    "mock-yubikey-12345678",
                    "9a",
                    "--output",
                    &path_argument,
                ],
            )
        };
        run(export_args()?)?;
        let pem = std::fs::read(&path)?;
        assert!(pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(run(export_args()?).is_err());
        std::fs::remove_file(path)?;

        let der = parse_for_agent(
            &agent,
            &[
                "piv",
                "certificate",
                "export",
                "mock-yubikey-12345678",
                "9a",
                "--format",
                "der",
            ],
        )?;
        assert!(
            run(der)
                .unwrap_err()
                .to_string()
                .contains("DER output requires --output")
        );
        Ok(())
    }

    #[test]
    fn watch_devices_receives_mock_connection_events_over_ipc() -> Result<()> {
        let agent = start_mock_agent()?;
        let client = AgentClient::connect(Some(agent.endpoint()))?;
        let events = client.subscribe()?;
        let mock = agent.mock().expect("mock backend");
        let mut device = mock.list()?.remove(0);
        device.id = DeviceId("mock-connected-2".into());
        mock.connect(device.clone())?;
        assert_eq!(
            events.recv_timeout(std::time::Duration::from_secs(5))?,
            DeviceEvent::Connected(device)
        );
        Ok(())
    }

    #[test]
    fn named_pipe_accepts_concurrent_clients_and_a_later_client() -> Result<()> {
        let agent = start_mock_agent()?;
        let endpoint = agent.endpoint().to_owned();
        let barrier = Arc::new(Barrier::new(3));
        let clients: Vec<_> = (0..2)
            .map(|_| {
                let endpoint = endpoint.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let client = AgentClient::connect(Some(&endpoint)).expect("test agent client");
                    client.list().expect("mock device list").len()
                })
            })
            .collect();
        barrier.wait();
        for client in clients {
            assert_eq!(client.join().expect("client thread"), 1);
        }
        let client = AgentClient::connect(Some(&endpoint))?;
        assert_eq!(client.list()?.len(), 1);
        Ok(())
    }

    #[test]
    fn fingerprint_requests_do_not_require_backend_grants() -> Result<()> {
        let agent = start_mock_agent()?;
        let client = AgentClient::connect(Some(agent.endpoint()))?;
        let id = DeviceId("mock-yubikey-12345678".into());
        assert!(matches!(
            client.remove_fingerprint(&id, "1234", "0102"),
            Err(sigil_core::CredentialError::UnsupportedOperation(_))
        ));
        assert!(matches!(
            client.enroll_fingerprint(&id, "1234", &mut |_| {}),
            Err(sigil_core::CredentialError::UnsupportedOperation(_))
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_agent_info_reports_the_sid_and_current_pid() -> Result<()> {
        let agent = start_mock_agent()?;
        let client = AgentClient::connect(Some(agent.endpoint()))?;
        let caller = client.agent_info().caller.as_ref().expect("caller info");
        assert!(caller.os_user.starts_with("S-1-5-"));
        assert_eq!(caller.pid, std::process::id());
        Ok(())
    }
}
