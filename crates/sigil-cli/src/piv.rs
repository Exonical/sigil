use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{Result, bail, ensure};
use clap::{Subcommand, ValueEnum};
use sigil_app::CredentialService;
use sigil_core::{
    CertificateFormat, CredentialError, DeviceId, KeyStatus, ManagementKey, ManagementKeyAlgorithm,
    PinPolicy, PivInfo, PivKeyAlgorithm, PivKeyConfiguration, PivPin, PivPuk, PivSlot, PivSlotInfo,
    TouchPolicy,
};
use zeroize::{Zeroize, Zeroizing};

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
    Pin {
        #[command(subcommand)]
        command: PinCommand,
    },
    Puk {
        #[command(subcommand)]
        command: PukCommand,
    },
    #[command(name = "management-key")]
    ManagementKey {
        #[command(subcommand)]
        command: ManagementKeyCommand,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Attest {
        device: String,
        #[arg(long)]
        slot: PivSlot,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Csr {
        device: String,
        #[arg(long)]
        slot: PivSlot,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        output: PathBuf,
    },
    Reset {
        device: String,
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
    Import {
        device: String,
        #[arg(long)]
        slot: PivSlot,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        current_default: bool,
    },
    Delete {
        device: String,
        #[arg(long)]
        slot: PivSlot,
        #[arg(long)]
        current_default: bool,
    },
}

#[derive(Subcommand)]
pub enum PinCommand {
    Change { device: String },
    Unblock { device: String },
}

#[derive(Subcommand)]
pub enum PukCommand {
    Change { device: String },
}

#[derive(Subcommand)]
pub enum ManagementKeyCommand {
    Change {
        device: String,
        #[arg(long)]
        current_default: bool,
        #[arg(long, value_enum, default_value_t = ManagementKeyArg::Aes256)]
        algorithm: ManagementKeyArg,
    },
}

#[derive(Subcommand)]
pub enum KeyCommand {
    Generate {
        device: String,
        #[arg(long)]
        slot: PivSlot,
        #[arg(long, value_enum)]
        algorithm: KeyAlgorithmArg,
        #[arg(long, value_enum, default_value_t = PinPolicyArg::Default)]
        pin_policy: PinPolicyArg,
        #[arg(long, value_enum, default_value_t = TouchPolicyArg::Default)]
        touch_policy: TouchPolicyArg,
        #[arg(long)]
        current_default: bool,
    },
    Delete {
        device: String,
        #[arg(long)]
        slot: PivSlot,
        #[arg(long)]
        current_default: bool,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum KeyAlgorithmArg {
    #[default]
    P256,
    P384,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum PinPolicyArg {
    #[default]
    Default,
    Never,
    Once,
    Always,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum TouchPolicyArg {
    #[default]
    Default,
    Never,
    Always,
    Cached,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ManagementKeyArg {
    Aes128,
    Aes192,
    #[default]
    Aes256,
}

impl From<KeyAlgorithmArg> for PivKeyAlgorithm {
    fn from(value: KeyAlgorithmArg) -> Self {
        match value {
            KeyAlgorithmArg::P256 => Self::EccP256,
            KeyAlgorithmArg::P384 => Self::EccP384,
        }
    }
}

impl From<PinPolicyArg> for PinPolicy {
    fn from(value: PinPolicyArg) -> Self {
        match value {
            PinPolicyArg::Default => Self::Default,
            PinPolicyArg::Never => Self::Never,
            PinPolicyArg::Once => Self::Once,
            PinPolicyArg::Always => Self::Always,
        }
    }
}

impl From<TouchPolicyArg> for TouchPolicy {
    fn from(value: TouchPolicyArg) -> Self {
        match value {
            TouchPolicyArg::Default => Self::Default,
            TouchPolicyArg::Never => Self::Never,
            TouchPolicyArg::Always => Self::Always,
            TouchPolicyArg::Cached => Self::Cached,
        }
    }
}

impl From<ManagementKeyArg> for ManagementKeyAlgorithm {
    fn from(value: ManagementKeyArg) -> Self {
        match value {
            ManagementKeyArg::Aes128 => Self::Aes128,
            ManagementKeyArg::Aes192 => Self::Aes192,
            ManagementKeyArg::Aes256 => Self::Aes256,
        }
    }
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
            CertificateCommand::Import {
                device,
                slot,
                file,
                current_default,
            } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                let key = management_key(service, &id, current_default)?;
                let certificate = fs::read(&file)?;
                service.import_certificate(&id, &serial, &key, slot, &certificate)?;
                mutation_output(
                    json,
                    serde_json::json!({ "operation": "import_certificate", "slot": slot }),
                    format!("Imported certificate for slot {slot}."),
                )
            }
            CertificateCommand::Delete {
                device,
                slot,
                current_default,
            } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                let key = management_key(service, &id, current_default)?;
                service.delete_certificate(&id, &serial, &key, slot)?;
                mutation_output(
                    json,
                    serde_json::json!({ "operation": "delete_certificate", "slot": slot }),
                    format!("Deleted certificate for slot {slot}."),
                )
            }
        },
        PivCommand::Pin { command } => match command {
            PinCommand::Change { device } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                let old_pin = prompt_pin("Current PIV PIN: ")?;
                let new_pin = prompt_new_pin()?;
                service.change_pin(&id, &serial, &old_pin, &new_pin)?;
                mutation_output(
                    json,
                    serde_json::json!({ "operation": "change_pin" }),
                    "Changed PIV PIN.".into(),
                )
            }
            PinCommand::Unblock { device } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                let puk = prompt_puk("PIV PUK: ")?;
                let new_pin = prompt_new_pin()?;
                service.unblock_pin(&id, &serial, &puk, &new_pin)?;
                mutation_output(
                    json,
                    serde_json::json!({ "operation": "unblock_pin" }),
                    "Unblocked PIV PIN.".into(),
                )
            }
        },
        PivCommand::Puk {
            command: PukCommand::Change { device },
        } => {
            let id = DeviceId(device);
            let serial = device_serial(service, &id)?;
            let old_puk = prompt_puk("Current PIV PUK: ")?;
            let new_puk = prompt_new_puk()?;
            service.change_puk(&id, &serial, &old_puk, &new_puk)?;
            mutation_output(
                json,
                serde_json::json!({ "operation": "change_puk" }),
                "Changed PIV PUK.".into(),
            )
        }
        PivCommand::ManagementKey {
            command:
                ManagementKeyCommand::Change {
                    device,
                    current_default,
                    algorithm,
                },
        } => {
            let id = DeviceId(device);
            let serial = device_serial(service, &id)?;
            let current = management_key(service, &id, current_default)?;
            let new_algorithm = algorithm.into();
            let new = CredentialService::generate_management_key(new_algorithm)?;
            service.change_management_key(&id, &serial, &current, &new)?;
            eprintln!("WARNING: the new management key is shown once; store it securely.");
            Ok(encode_hex(new.as_bytes()))
        }
        PivCommand::Key { command } => match command {
            KeyCommand::Generate {
                device,
                slot,
                algorithm,
                pin_policy,
                touch_policy,
                current_default,
            } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                let key = management_key(service, &id, current_default)?;
                let spki = service.generate_key(
                    &id,
                    &serial,
                    &key,
                    PivKeyConfiguration {
                        slot,
                        algorithm: algorithm.into(),
                        pin_policy: pin_policy.into(),
                        touch_policy: touch_policy.into(),
                    },
                )?;
                mutation_output(
                    json,
                    serde_json::json!({
                        "operation": "generate_key",
                        "slot": slot,
                        "subject_public_key_info": encode_hex(&spki),
                    }),
                    format!("Generated key in slot {slot}."),
                )
            }
            KeyCommand::Delete {
                device,
                slot,
                current_default,
            } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                let key = management_key(service, &id, current_default)?;
                service.delete_key(&id, &serial, &key, slot)?;
                mutation_output(
                    json,
                    serde_json::json!({ "operation": "delete_key", "slot": slot }),
                    format!("Deleted key in slot {slot}."),
                )
            }
        },
        PivCommand::Attest {
            device,
            slot,
            output,
        } => {
            let id = DeviceId(device);
            let serial = device_serial(service, &id)?;
            let attestation = service.attest(&id, &serial, slot)?;
            if let Some(directory) = output {
                fs::create_dir_all(&directory)?;
                write_new(
                    &directory.join("attestation.der"),
                    &attestation.attestation_der,
                )?;
                write_new(
                    &directory.join("intermediate.der"),
                    &attestation.intermediate_der,
                )?;
                mutation_output(
                    json,
                    serde_json::json!({
                        "operation": "attest",
                        "slot": slot,
                        "output": directory,
                    }),
                    format!("Wrote attestation for slot {slot}."),
                )
            } else {
                Ok(serde_json::to_string_pretty(&serde_json::json!({
                    "attestation_der": attestation.attestation_der,
                    "intermediate_der": attestation.intermediate_der,
                }))?)
            }
        }
        PivCommand::Csr {
            device,
            slot,
            subject,
            output,
        } => {
            let id = DeviceId(device);
            let serial = device_serial(service, &id)?;
            let pin = prompt_pin("PIV PIN: ")?;
            let csr = service.sign_csr(&id, &serial, &pin, slot, &subject)?;
            write_new(&output, &csr)?;
            mutation_output(
                json,
                serde_json::json!({
                    "operation": "sign_csr",
                    "slot": slot,
                    "output": output,
                }),
                format!("Wrote CSR for slot {slot}."),
            )
        }
        PivCommand::Reset { device } => {
            let id = DeviceId(device);
            let serial = device_serial(service, &id)?;
            println!("Reset PIV on device serial {serial}.");
            ensure!(
                read_line("Type the serial to confirm: ")?.trim() == serial,
                "serial confirmation did not match"
            );
            ensure!(
                read_line("This erases PIV keys and certificates. Continue? [y/N]: ")?
                    .trim()
                    .eq_ignore_ascii_case("y"),
                "PIV reset canceled"
            );
            service.reset(&id, &serial)?;
            mutation_output(
                json,
                serde_json::json!({ "operation": "reset_piv", "serial": serial }),
                format!("Reset PIV on device serial {serial}."),
            )
        }
    }
}

const DEFAULT_MANAGEMENT_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

fn device_serial(service: &CredentialService, id: &DeviceId) -> Result<String> {
    service
        .device(id)?
        .serial
        .ok_or_else(|| CredentialError::DeviceMismatch.into())
}

fn management_key(
    service: &CredentialService,
    id: &DeviceId,
    current_default: bool,
) -> Result<ManagementKey> {
    let (algorithm, key) = if current_default {
        (
            ManagementKeyAlgorithm::Aes192,
            DEFAULT_MANAGEMENT_KEY.to_vec(),
        )
    } else {
        let info = service.piv_info(id)?;
        let algorithm = sigil_core::ManagementKeyAlgorithm::from_piv_algorithm(
            info.management_key
                .ok_or(CredentialError::PivUnavailable)?
                .algorithm,
        )?;
        let mut value = Zeroizing::new(rpassword::prompt_password(
            "Current PIV management key (hex): ",
        )?);
        let mut key = parse_hex(&value)?;
        value.zeroize();
        (algorithm, std::mem::take(&mut *key))
    };
    Ok(ManagementKey::new(algorithm, key)?)
}

fn prompt_pin(prompt: &str) -> Result<PivPin> {
    let mut value = Zeroizing::new(rpassword::prompt_password(prompt)?);
    let bytes = std::mem::take(&mut *value).into_bytes();
    Ok(PivPin::new(bytes)?)
}

fn prompt_puk(prompt: &str) -> Result<PivPuk> {
    let mut value = Zeroizing::new(rpassword::prompt_password(prompt)?);
    let bytes = std::mem::take(&mut *value).into_bytes();
    Ok(PivPuk::new(bytes)?)
}

fn prompt_new_pin() -> Result<PivPin> {
    let mut first = Zeroizing::new(rpassword::prompt_password("New PIV PIN: ")?);
    let mut confirmation = Zeroizing::new(rpassword::prompt_password("Confirm new PIV PIN: ")?);
    ensure!(*first == *confirmation, "PIV PINs did not match");
    let bytes = std::mem::take(&mut *first).into_bytes();
    confirmation.zeroize();
    Ok(PivPin::new(bytes)?)
}

fn prompt_new_puk() -> Result<PivPuk> {
    let mut first = Zeroizing::new(rpassword::prompt_password("New PIV PUK: ")?);
    let mut confirmation = Zeroizing::new(rpassword::prompt_password("Confirm new PIV PUK: ")?);
    ensure!(*first == *confirmation, "PIV PUKs did not match");
    let bytes = std::mem::take(&mut *first).into_bytes();
    confirmation.zeroize();
    Ok(PivPuk::new(bytes)?)
}

fn parse_hex(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let value = value.trim();
    ensure!(
        !value.is_empty() && value.len().is_multiple_of(2),
        "management key must be even-length hexadecimal"
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        let digits = std::str::from_utf8(pair)?;
        bytes.push(
            u8::from_str_radix(digits, 16)
                .map_err(|_| anyhow::anyhow!("management key must be hexadecimal"))?,
        );
    }
    Ok(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn mutation_output(json: bool, json_value: serde_json::Value, plain: String) -> Result<String> {
    if json {
        Ok(serde_json::to_string_pretty(&json_value)?)
    } else {
        Ok(plain)
    }
}

fn write_new(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn read_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value)
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
