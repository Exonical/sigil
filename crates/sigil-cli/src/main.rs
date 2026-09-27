use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sigil_app::CredentialService;
use sigil_core::{DeviceDiscovery, DeviceId, DeviceInfo};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Backend {
    Mock,
    Native,
}

impl Default for Backend {
    fn default() -> Self {
        if cfg!(target_os = "windows") {
            Self::Native
        } else {
            Self::Mock
        }
    }
}

#[derive(Parser)]
#[command(name = "cms", about = "Sigil credential manager")]
struct Args {
    #[arg(long, global = true, value_enum, default_value_t = Backend::default())]
    backend: Backend,
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

fn service(backend: Backend) -> CredentialService {
    let discovery: Arc<dyn DeviceDiscovery> = match backend {
        Backend::Mock => Arc::new(sigil_mock::MockDiscovery::with_example()),
        Backend::Native => Arc::new(sigil_platform::NativeDiscovery),
    };
    CredentialService::new(discovery)
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
    let service = service(args.backend);
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
                    "{}\nID: {}\nVendor: {}\nSerial: {}\nFirmware: {}\nForm factor: {}\nEnabled applications: {}\nSupported applications: {}\nSimulated: {}",
                    info.model,
                    info.id.0,
                    info.vendor,
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
            eprint!("FIDO2 PIN: ");
            let pin = rpassword::read_password()?;
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
    use super::*;

    #[test]
    fn json_list_is_parseable_and_clearly_simulated() -> Result<()> {
        let args = Args::try_parse_from(["cms", "--backend", "mock", "device", "list", "--json"])?;
        let result: Vec<DeviceInfo> = serde_json::from_str(&run(args)?)?;
        assert_eq!(result.len(), 1);
        assert!(result[0].simulated);
        assert_eq!(result[0].id.0, "mock-yubikey-12345678");
        Ok(())
    }

    #[test]
    fn explicit_device_selection() -> Result<()> {
        let args = Args::try_parse_from([
            "cms",
            "--backend",
            "mock",
            "device",
            "info",
            "mock-yubikey-12345678",
            "--json",
        ])?;
        let value: DeviceInfo = serde_json::from_str(&run(args)?)?;
        assert_eq!(value.serial.as_deref(), Some("12345678"));
        Ok(())
    }

    #[test]
    fn fido_status_is_structured_for_selected_device() -> Result<()> {
        let args = Args::try_parse_from([
            "cms",
            "--backend",
            "mock",
            "fido",
            "info",
            "mock-yubikey-12345678",
            "--json",
        ])?;
        let value: sigil_core::FidoStatus = serde_json::from_str(&run(args)?)?;
        assert!(value.credential_management);
        assert_eq!(value.pin_retries, Some(8));
        Ok(())
    }
}
