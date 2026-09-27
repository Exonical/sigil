use std::{fs::OpenOptions, io::Write, path::PathBuf, str::FromStr};

use anyhow::{Result, bail};
use clap::{Subcommand, ValueEnum};
use sigil_app::CredentialService;
use sigil_core::{CertificateFormat, DeviceId, KeyStatus, PivInfo, PivSlot, PivSlotInfo};

#[derive(Subcommand)]
pub enum PivCommand {
    Info {
        device: String,
    },
    Slots {
        device: String,
    },
    Certificate {
        #[command(subcommand)]
        command: CertificateCommand,
    },
}

#[derive(Subcommand)]
pub enum CertificateCommand {
    Show {
        device: String,
        slot: String,
    },
    Export {
        device: String,
        slot: String,
        #[arg(long, value_enum, default_value_t = ExportFormat::Pem)]
        format: ExportFormat,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    #[default]
    Pem,
    Der,
}

impl ExportFormat {
    fn certificate_format(self) -> CertificateFormat {
        match self {
            Self::Pem => CertificateFormat::Pem,
            Self::Der => CertificateFormat::Der,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Pem => "pem",
            Self::Der => "der",
        }
    }
}

pub fn handle(service: &CredentialService, command: PivCommand, json: bool) -> Result<String> {
    match command {
        PivCommand::Info { device } => {
            let info = service.piv_info(&DeviceId(device))?;
            render_info(&info, json)
        }
        PivCommand::Slots { device } => {
            let slots = service.piv_slots(&DeviceId(device))?;
            render_slots(&slots, json)
        }
        PivCommand::Certificate { command } => match command {
            CertificateCommand::Show { device, slot } => {
                let slot = PivSlot::from_str(&slot)?;
                let certificate = service
                    .piv_certificate(&DeviceId(device), slot)?
                    .ok_or_else(|| {
                        sigil_core::CredentialError::CertificateNotFound(slot.to_string())
                    })?;
                if json {
                    Ok(serde_json::to_string_pretty(&certificate.summary)?)
                } else {
                    let summary = certificate.summary;
                    Ok(format!(
                        "Slot: {slot}\nSubject: {}\nIssuer: {}\nSerial: {}\nNot before: {}\nNot after: {}\nPublic key algorithm: {}\nSHA-256 fingerprint: {}",
                        summary.subject,
                        summary.issuer,
                        summary.serial,
                        summary.not_before,
                        summary.not_after,
                        summary
                            .public_key_algorithm
                            .map(|algorithm| algorithm.to_string())
                            .unwrap_or_else(|| "unknown".into()),
                        summary.sha256_fingerprint
                    ))
                }
            }
            CertificateCommand::Export {
                device,
                slot,
                format,
                output,
            } => {
                let slot = PivSlot::from_str(&slot)?;
                if output.is_none() && format == ExportFormat::Der {
                    bail!("DER output requires --output")
                }
                let certificate_format = format.certificate_format();
                let bytes =
                    service.export_certificate(&DeviceId(device), slot, certificate_format)?;
                if let Some(path) = output {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)?;
                    file.write_all(&bytes)?;
                    let path_display = path.display().to_string();
                    if json {
                        Ok(serde_json::to_string_pretty(&serde_json::json!({
                            "slot": slot,
                            "format": format.as_str(),
                            "path": path_display,
                            "bytes": bytes.len(),
                        }))?)
                    } else {
                        Ok(format!(
                            "Exported {} certificate for slot {slot} to {path_display} ({} bytes).",
                            format.as_str(),
                            bytes.len()
                        ))
                    }
                } else {
                    let pem = String::from_utf8(bytes)?;
                    if json {
                        Ok(serde_json::to_string_pretty(&serde_json::json!({
                            "slot": slot,
                            "format": "pem",
                            "pem": pem,
                        }))?)
                    } else {
                        Ok(pem)
                    }
                }
            }
        },
    }
}

fn render_info(info: &PivInfo, json: bool) -> Result<String> {
    if json {
        return Ok(serde_json::to_string_pretty(info)?);
    }
    let version = info
        .version
        .as_ref()
        .map(|version| format!("{}.{}.{}", version.major, version.minor, version.patch))
        .unwrap_or_else(|| "unknown".into());
    Ok(format!(
        "Version: {version}\nPIN retries: {}\nPUK retries: {}\nManagement key: {}",
        render_retries(info.pin.as_ref()),
        render_retries(info.puk.as_ref()),
        info.management_key
            .as_ref()
            .map(|key| format!(
                "{} (default: {:?}, touch: {:?})",
                key.algorithm, key.default_value, key.touch_policy
            ))
            .unwrap_or_else(|| "unknown".into())
    ))
}

fn render_retries(status: Option<&sigil_core::RetryStatus>) -> String {
    status
        .map(|status| match status.total {
            Some(total) => format!(
                "{}/{} remaining (default: {:?})",
                status.remaining, total, status.default_value
            ),
            None => format!("{} remaining", status.remaining),
        })
        .unwrap_or_else(|| "unknown".into())
}

fn render_slots(slots: &[PivSlotInfo], json: bool) -> Result<String> {
    if json {
        return Ok(serde_json::to_string_pretty(slots)?);
    }
    let mut lines = vec![format!(
        "{:<4}  {:<28}  {:<14}  {:<11}  {:<8}  {:<42}  NOT AFTER",
        "SLOT", "NAME", "KEY", "PIN", "TOUCH", "SUBJECT"
    )];
    for info in slots {
        let (key, pin, touch) = match &info.key {
            KeyStatus::Present(metadata) => (
                metadata.algorithm.to_string(),
                format!("{:?}", metadata.pin_policy),
                format!("{:?}", metadata.touch_policy),
            ),
            KeyStatus::Absent => ("absent".into(), "-".into(), "-".into()),
            KeyStatus::Unknown => ("unknown".into(), "-".into(), "-".into()),
        };
        lines.push(format!(
            "{:<4}  {:<28}  {:<14}  {:<11}  {:<8}  {:<42}  {}",
            info.slot,
            info.slot.name(),
            key,
            pin,
            touch,
            info.certificate
                .as_ref()
                .map(|cert| cert.subject.as_str())
                .unwrap_or("-"),
            info.certificate
                .as_ref()
                .map(|cert| cert.not_after.as_str())
                .unwrap_or("-"),
        ));
    }
    Ok(lines.join("\n"))
}
