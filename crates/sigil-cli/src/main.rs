use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sigil_app::CredentialService;
use sigil_core::{DeviceDiscovery, DeviceId, DeviceInfo};

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum Backend {
    #[default]
    Mock,
    Native,
}

#[derive(Parser)]
#[command(
    name = "cms",
    about = "Sigil credential manager (milestone 1 prototype)"
)]
struct Args {
    #[arg(long, global = true, value_enum, default_value_t = Backend::Mock)]
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
                    "{}\nID: {}\nVendor: {}\nSerial: {}\nFirmware: {}\nApplications: {}\nSimulated: {}",
                    info.model,
                    info.id.0,
                    info.vendor,
                    info.serial.as_deref().unwrap_or("unknown"),
                    info.firmware
                        .as_ref()
                        .map(|v| format!("{}.{}.{}", v.major, v.minor, v.patch))
                        .unwrap_or_else(|| "unknown".into()),
                    info.applications
                        .iter()
                        .map(|app| format!("{app:?}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    info.simulated
                ))
            }
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
        let args = Args::try_parse_from(["cms", "device", "list", "--json"])?;
        let result: Vec<DeviceInfo> = serde_json::from_str(&run(args)?)?;
        assert_eq!(result.len(), 1);
        assert!(result[0].simulated);
        assert_eq!(result[0].id.0, "mock-yubikey-12345678");
        Ok(())
    }

    #[test]
    fn explicit_device_selection() -> Result<()> {
        let args =
            Args::try_parse_from(["cms", "device", "info", "mock-yubikey-12345678", "--json"])?;
        let value: DeviceInfo = serde_json::from_str(&run(args)?)?;
        assert_eq!(value.serial.as_deref(), Some("12345678"));
        Ok(())
    }
}
