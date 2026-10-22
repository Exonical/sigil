use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{Result, bail, ensure};
use clap::{Subcommand, ValueEnum};
use sigil_app::CredentialService;
use sigil_connect::{ManagedPivAgent, ManagedSecret};
use sigil_core::{
    CertificateFormat, CredentialError, DeviceId, HexError, KeyStatus, ManagementKey,
    ManagementKeyAlgorithm, PinPolicy, PivInfo, PivKeyAlgorithm, PivKeyConfiguration, PivPin,
    PivPuk, PivSlot, PivSlotInfo, TouchPolicy, encode_hex,
};
use zeroize::{Zeroize, Zeroizing};

use crate::auth;

#[derive(Subcommand)]
pub enum PivCommand {
    /// Escrow-backed operations that the agent performs with backend-released secrets.
    Managed {
        #[command(subcommand)]
        command: ManagedCommand,
    },
    /// List certificate profiles the backend allows for this token (agent only).
    Profiles {
        device: String,
    },
    /// Enroll a certificate for a profile: generate the key, attest it, get it signed, and install it (agent only).
    Enroll {
        device: String,
        #[arg(long)]
        profile: String,
    },
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
pub enum ManagedCommand {
    /// Replace the factory PUK and management key with backend-escrowed secrets (agent only).
    Init { device: String },
    /// Rotate the PUK or management key to a new backend-escrowed secret (agent only).
    Rotate {
        device: String,
        #[arg(long, value_enum)]
        secret: ManagedSecretArg,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ManagedSecretArg {
    Puk,
    ManagementKey,
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
        #[arg(long, conflicts_with = "current_default")]
        managed: bool,
        #[arg(long)]
        current_default: bool,
    },
    Delete {
        device: String,
        #[arg(long)]
        slot: PivSlot,
        #[arg(long, conflicts_with = "current_default")]
        managed: bool,
        #[arg(long)]
        current_default: bool,
    },
}

#[derive(Subcommand)]
pub enum PinCommand {
    Change {
        device: String,
    },
    Unblock {
        device: String,
        #[arg(long)]
        managed: bool,
    },
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
        #[arg(long, conflicts_with = "current_default")]
        managed: bool,
        #[arg(long)]
        current_default: bool,
    },
    Delete {
        device: String,
        #[arg(long)]
        slot: PivSlot,
        #[arg(long, conflicts_with = "current_default")]
        managed: bool,
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

trait SecretPrompter {
    fn password(&mut self, prompt: &str) -> Result<String>;
}

struct TerminalSecretPrompter;

impl SecretPrompter for TerminalSecretPrompter {
    fn password(&mut self, prompt: &str) -> Result<String> {
        Ok(rpassword::prompt_password(prompt)?)
    }
}

pub fn handle(
    service: &CredentialService,
    agent: Option<&dyn ManagedPivAgent>,
    command: PivCommand,
    json: bool,
) -> Result<String> {
    handle_with_prompter(service, agent, command, json, &mut TerminalSecretPrompter)
}

fn managed_agent(agent: Option<&dyn ManagedPivAgent>) -> Result<&dyn ManagedPivAgent> {
    agent.ok_or_else(|| {
        anyhow::anyhow!(
            "managed operations need the Sigil agent; use --agent or start the agent service"
        )
    })
}

fn managed_error(error: CredentialError) -> anyhow::Error {
    match error {
        CredentialError::BackendRejected(detail) => {
            anyhow::anyhow!("the backend rejected the operation: {detail}")
        }
        CredentialError::BackendUnavailable(_) => {
            anyhow::anyhow!("the Sigil backend is unavailable; try again later")
        }
        CredentialError::PivNotFactoryDefault => anyhow::anyhow!(
            "this key is not at factory defaults; reset PIV before managed initialization"
        ),
        CredentialError::ManagedRotationIncomplete(rotation) => {
            anyhow::anyhow!("rotation {rotation} is incomplete; an administrator must recover it")
        }
        other => other.into(),
    }
}

fn handle_with_prompter<P: SecretPrompter>(
    service: &CredentialService,
    agent: Option<&dyn ManagedPivAgent>,
    command: PivCommand,
    json: bool,
    prompter: &mut P,
) -> Result<String> {
    match command {
        PivCommand::Profiles { device } => {
            let agent = managed_agent(agent)?;
            let token = auth::managed_access_token()?;
            let id = DeviceId(device);
            let profiles = agent
                .certificate_profiles(&id, &token)
                .map_err(managed_error)?;
            if json {
                Ok(serde_json::to_string_pretty(
                    &profiles
                        .iter()
                        .map(|profile| {
                            serde_json::json!({
                                "name": profile.name,
                                "display_name": profile.display_name,
                                "slot": profile.slot,
                                "algorithm": profile.algorithm,
                                "pin_policy": profile.pin_policy,
                                "touch_policy": profile.touch_policy,
                                "subject": profile.expected_subject,
                            })
                        })
                        .collect::<Vec<_>>(),
                )?)
            } else if profiles.is_empty() {
                Ok("No certificate profiles are available for this token.".into())
            } else {
                Ok(profiles
                    .iter()
                    .map(|profile| {
                        format!(
                            "{}: {} (slot {}, {}, PIN {}, touch {}, subject CN={})",
                            profile.name,
                            profile.display_name,
                            profile.slot,
                            profile.algorithm,
                            profile.pin_policy,
                            profile.touch_policy,
                            profile.expected_subject
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
        }
        PivCommand::Enroll { device, profile } => {
            let agent = managed_agent(agent)?;
            let token = auth::managed_access_token()?;
            let id = DeviceId(device);
            let serial = device_serial(service, &id)?;
            let fips = service.device(&id)?.fips == Some(true);
            let pin = prompt_pin("PIV PIN: ", fips, prompter)?;
            let enrolled = agent
                .enroll_certificate(&id, &serial, &profile, &pin, &token)
                .map_err(managed_error)?;
            mutation_output(
                json,
                serde_json::json!({
                    "operation": "enroll",
                    "profile": profile,
                    "subject": enrolled.subject,
                    "serial_number": enrolled.serial_number,
                    "not_after_unix": enrolled.not_after_unix,
                }),
                format!(
                    "Enrolled {profile}: subject {}, certificate serial {}, valid until unix time {}.",
                    enrolled.subject, enrolled.serial_number, enrolled.not_after_unix
                ),
            )
        }
        PivCommand::Managed { command } => {
            let agent = managed_agent(agent)?;
            let token = auth::managed_access_token()?;
            match command {
                ManagedCommand::Init { device } => {
                    let id = DeviceId(device);
                    let serial = device_serial(service, &id)?;
                    agent
                        .initialize(&id, &serial, &token)
                        .map_err(managed_error)?;
                    mutation_output(
                        json,
                        serde_json::json!({ "operation": "managed_initialize" }),
                        "Initialized managed PIV: the PUK and management key are now backend-escrowed."
                            .into(),
                    )
                }
                ManagedCommand::Rotate { device, secret } => {
                    let id = DeviceId(device);
                    let serial = device_serial(service, &id)?;
                    let (kind, label) = match secret {
                        ManagedSecretArg::Puk => (ManagedSecret::Puk, "PUK"),
                        ManagedSecretArg::ManagementKey => {
                            (ManagedSecret::ManagementKey, "management key")
                        }
                    };
                    agent
                        .rotate_secret(&id, &serial, kind, &token)
                        .map_err(managed_error)?;
                    mutation_output(
                        json,
                        serde_json::json!({ "operation": "managed_rotate", "secret": label }),
                        format!("Rotated the managed PIV {label}."),
                    )
                }
            }
        }
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
                managed,
                current_default,
            } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                let certificate = fs::read(&file)?;
                if managed {
                    let agent = managed_agent(agent)?;
                    let token = auth::managed_access_token()?;
                    agent
                        .import_certificate(&id, &serial, slot, &certificate, None, &token)
                        .map_err(managed_error)?;
                    return mutation_output(
                        json,
                        serde_json::json!({ "operation": "import_certificate", "slot": slot, "managed": true }),
                        format!("Imported certificate for slot {slot}."),
                    );
                }
                let key = management_key(service, &id, current_default, prompter)?;
                service.import_certificate(&id, &serial, &key, slot, &certificate, None)?;
                mutation_output(
                    json,
                    serde_json::json!({ "operation": "import_certificate", "slot": slot }),
                    format!("Imported certificate for slot {slot}."),
                )
            }
            CertificateCommand::Delete {
                device,
                slot,
                managed,
                current_default,
            } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                if managed {
                    let agent = managed_agent(agent)?;
                    let token = auth::managed_access_token()?;
                    agent
                        .delete_certificate(&id, &serial, slot, &token)
                        .map_err(managed_error)?;
                    return mutation_output(
                        json,
                        serde_json::json!({ "operation": "delete_certificate", "slot": slot, "managed": true }),
                        format!("Deleted certificate for slot {slot}."),
                    );
                }
                let key = management_key(service, &id, current_default, prompter)?;
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
                let old_pin = current_pin(service, &id, "Current PIV PIN: ", prompter)?;
                let new_pin = prompt_new_pin(service, &id, prompter)?;
                service.change_pin(&id, &serial, &old_pin, &new_pin)?;
                mutation_output(
                    json,
                    serde_json::json!({ "operation": "change_pin" }),
                    "Changed PIV PIN.".into(),
                )
            }
            PinCommand::Unblock { device, managed } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                if managed {
                    let agent = managed_agent(agent)?;
                    let token = auth::managed_access_token()?;
                    let new_pin = prompt_new_pin(service, &id, prompter)?;
                    agent
                        .unblock_pin(&id, &serial, &new_pin, &token)
                        .map_err(managed_error)?;
                    return mutation_output(
                        json,
                        serde_json::json!({ "operation": "unblock_pin", "managed": true }),
                        "Unblocked PIV PIN.".into(),
                    );
                }
                let puk = current_puk(service, &id, "PIV PUK: ", prompter)?;
                let new_pin = prompt_new_pin(service, &id, prompter)?;
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
            let old_puk = current_puk(service, &id, "Current PIV PUK: ", prompter)?;
            let new_puk = prompt_new_puk(service, &id, prompter)?;
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
            let current = management_key(service, &id, current_default, prompter)?;
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
                managed,
                current_default,
            } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                if managed {
                    let agent = managed_agent(agent)?;
                    let token = auth::managed_access_token()?;
                    let spki = agent
                        .generate_key(
                            &id,
                            &serial,
                            PivKeyConfiguration {
                                slot,
                                algorithm: algorithm.into(),
                                pin_policy: pin_policy.into(),
                                touch_policy: touch_policy.into(),
                            },
                            &token,
                        )
                        .map_err(managed_error)?;
                    return mutation_output(
                        json,
                        serde_json::json!({
                            "operation": "generate_key",
                            "slot": slot,
                            "managed": true,
                            "subject_public_key_info": encode_hex(&spki),
                        }),
                        format!("Generated key in slot {slot}."),
                    );
                }
                let key = management_key(service, &id, current_default, prompter)?;
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
                managed,
                current_default,
            } => {
                let id = DeviceId(device);
                let serial = device_serial(service, &id)?;
                if managed {
                    let agent = managed_agent(agent)?;
                    let token = auth::managed_access_token()?;
                    agent
                        .delete_key(&id, &serial, slot, &token)
                        .map_err(managed_error)?;
                    return mutation_output(
                        json,
                        serde_json::json!({ "operation": "delete_key", "slot": slot, "managed": true }),
                        format!("Deleted key in slot {slot}."),
                    );
                }
                let key = management_key(service, &id, current_default, prompter)?;
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
            let verification = attestation_verification_line(&attestation.inspection);
            let details = attestation_details(&attestation);
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
                        "attestation": details,
                    }),
                    format!("{verification}\nWrote attestation for slot {slot}."),
                )
            } else if json {
                Ok(serde_json::to_string_pretty(&details)?)
            } else {
                Ok(format!(
                    "{verification}\n{}",
                    attestation_fields_text(&attestation.inspection)
                ))
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
            let pin = current_pin(service, &id, "PIV PIN: ", prompter)?;
            let csr = service.sign_csr(&id, &serial, &pin, slot, &subject, None)?;
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
const DEFAULT_PIN: &[u8] = b"123456";
const DEFAULT_PUK: &[u8] = b"12345678";

fn device_serial(service: &CredentialService, id: &DeviceId) -> Result<String> {
    service
        .device(id)?
        .serial
        .ok_or_else(|| CredentialError::DeviceMismatch.into())
}

fn current_pin<P: SecretPrompter>(
    service: &CredentialService,
    id: &DeviceId,
    prompt: &str,
    prompter: &mut P,
) -> Result<PivPin> {
    let info = service.piv_info(id)?;
    if info.pin.as_ref().and_then(|status| status.default_value) == Some(true) {
        eprintln!("The PIN is still the factory default; using it.");
        return Ok(PivPin::new(DEFAULT_PIN.to_vec())?);
    }
    prompt_pin(prompt, false, prompter)
}

fn current_puk<P: SecretPrompter>(
    service: &CredentialService,
    id: &DeviceId,
    prompt: &str,
    prompter: &mut P,
) -> Result<PivPuk> {
    let info = service.piv_info(id)?;
    if info.puk.as_ref().and_then(|status| status.default_value) == Some(true) {
        eprintln!("The PUK is still the factory default; using it.");
        return Ok(PivPuk::new(DEFAULT_PUK.to_vec())?);
    }
    prompt_puk(prompt, prompter)
}

fn management_key<P: SecretPrompter>(
    service: &CredentialService,
    id: &DeviceId,
    current_default: bool,
    prompter: &mut P,
) -> Result<ManagementKey> {
    if current_default {
        return Ok(ManagementKey::new(
            ManagementKeyAlgorithm::Aes192,
            DEFAULT_MANAGEMENT_KEY.to_vec(),
        )?);
    }

    let info = service.piv_info(id)?;
    let status = info.management_key.ok_or(CredentialError::PivUnavailable)?;
    let algorithm = sigil_core::ManagementKeyAlgorithm::from_piv_algorithm(status.algorithm)?;
    if status.default_value == Some(true) {
        eprintln!("The management key is still the factory default; using it.");
        return Ok(ManagementKey::new(
            algorithm,
            DEFAULT_MANAGEMENT_KEY.to_vec(),
        )?);
    }
    let mut value = Zeroizing::new(prompter.password("Current PIV management key (hex): ")?);
    let mut key = parse_management_key_hex(&value)?;
    value.zeroize();
    Ok(ManagementKey::new(algorithm, std::mem::take(&mut *key))?)
}

fn prompt_pin<P: SecretPrompter>(prompt: &str, fips: bool, prompter: &mut P) -> Result<PivPin> {
    let mut value = Zeroizing::new(prompter.password(prompt)?);
    validate_code_length(&value, "PIN", fips)?;
    let bytes = std::mem::take(&mut *value).into_bytes();
    Ok(PivPin::new(bytes)?)
}

fn prompt_puk<P: SecretPrompter>(prompt: &str, prompter: &mut P) -> Result<PivPuk> {
    let mut value = Zeroizing::new(prompter.password(prompt)?);
    validate_code_length(&value, "PUK", false)?;
    let bytes = std::mem::take(&mut *value).into_bytes();
    Ok(PivPuk::new(bytes)?)
}

fn prompt_new_pin<P: SecretPrompter>(
    service: &CredentialService,
    id: &DeviceId,
    prompter: &mut P,
) -> Result<PivPin> {
    let fips = service.device(id)?.fips == Some(true);
    let mut first = Zeroizing::new(prompter.password("New PIV PIN: ")?);
    validate_code_length(&first, "PIN", fips)?;
    let mut confirmation = Zeroizing::new(prompter.password("Confirm new PIV PIN: ")?);
    validate_code_length(&confirmation, "PIN", fips)?;
    ensure!(*first == *confirmation, "PIV PINs did not match");
    let bytes = std::mem::take(&mut *first).into_bytes();
    confirmation.zeroize();
    Ok(PivPin::new(bytes)?)
}

fn prompt_new_puk<P: SecretPrompter>(
    service: &CredentialService,
    id: &DeviceId,
    prompter: &mut P,
) -> Result<PivPuk> {
    let fips = service.device(id)?.fips == Some(true);
    let mut first = Zeroizing::new(prompter.password("New PIV PUK: ")?);
    validate_code_length(&first, "PUK", fips)?;
    let mut confirmation = Zeroizing::new(prompter.password("Confirm new PIV PUK: ")?);
    validate_code_length(&confirmation, "PUK", fips)?;
    ensure!(*first == *confirmation, "PIV PUKs did not match");
    let bytes = std::mem::take(&mut *first).into_bytes();
    confirmation.zeroize();
    Ok(PivPuk::new(bytes)?)
}

fn validate_code_length(value: &str, kind: &str, fips: bool) -> Result<()> {
    let characters = value.chars().count();
    if fips && characters != 8 {
        bail!("This FIPS key requires an 8-character {kind}");
    }
    if !(6..=8).contains(&characters) {
        bail!("{kind} must be 6–8 characters; you entered {characters}");
    }
    ensure!(
        value.is_ascii(),
        "{kind} must contain only ASCII characters"
    );
    Ok(())
}

fn parse_management_key_hex(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    sigil_core::parse_hex(value).map_err(|error| match error {
        HexError::InvalidLength => {
            anyhow::anyhow!("management key must be even-length hexadecimal")
        }
        HexError::NonAscii | HexError::InvalidDigit => {
            anyhow::anyhow!("management key must be hexadecimal")
        }
    })
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

/// The verification result as the first line of output: "Verified: chains to <root>" or "NOT VERIFIED: <reason>".
fn attestation_verification_line(inspection: &sigil_core::AttestationInspection) -> String {
    if inspection.verified {
        format!(
            "Verified: chains to {}",
            inspection
                .attestation_root
                .as_deref()
                .unwrap_or("a Yubico root")
        )
    } else {
        format!(
            "NOT VERIFIED: {}",
            inspection
                .verification_error
                .as_deref()
                .unwrap_or("unknown reason")
        )
    }
}

fn attestation_details(attestation: &sigil_core::PivAttestation) -> serde_json::Value {
    let inspection = &attestation.inspection;
    serde_json::json!({
        "verified": inspection.verified,
        "verification_error": inspection.verification_error,
        "attestation_root": inspection.attestation_root,
        "attested_serial": inspection.attested_serial,
        "attested_slot": inspection.attested_slot,
        "firmware": inspection.firmware,
        "pin_policy": inspection.pin_policy,
        "touch_policy": inspection.touch_policy,
        "attestation_der": attestation.attestation_der,
        "intermediate_der": attestation.intermediate_der,
    })
}

fn attestation_fields_text(inspection: &sigil_core::AttestationInspection) -> String {
    let show = |value: Option<String>| value.unwrap_or_else(|| "unavailable".to_owned());
    format!(
        "Serial: {}\nFirmware: {}\nSlot: {}\nPIN policy: {}\nTouch policy: {}",
        show(inspection.attested_serial.map(|serial| serial.to_string())),
        show(inspection.firmware.clone()),
        show(inspection.attested_slot.map(|slot| format!("{slot:02x}"))),
        show(inspection.pin_policy.map(|policy| format!("{policy:02x}"))),
        show(
            inspection
                .touch_policy
                .map(|policy| format!("{policy:02x}"))
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Arc};

    use sigil_core::{DeviceDiscovery, PivManagement};
    use sigil_mock::MockDiscovery;

    use super::*;

    const DEVICE_ID: &str = "mock-yubikey-12345678";
    const SERIAL: &str = "12345678";

    #[derive(Default)]
    struct QueuedPrompter {
        answers: VecDeque<String>,
        prompts: Vec<String>,
    }

    impl QueuedPrompter {
        fn new(answers: impl IntoIterator<Item = &'static str>) -> Self {
            Self {
                answers: answers.into_iter().map(str::to_owned).collect(),
                prompts: Vec::new(),
            }
        }
    }

    impl SecretPrompter for QueuedPrompter {
        fn password(&mut self, prompt: &str) -> Result<String> {
            self.prompts.push(prompt.to_owned());
            self.answers
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("unexpected password prompt"))
        }
    }

    fn credential_service(mock: Arc<MockDiscovery>) -> CredentialService {
        let discovery: Arc<dyn DeviceDiscovery> = mock.clone();
        let management: Arc<dyn PivManagement> = mock;
        CredentialService::new_with_piv_management(discovery, management)
    }

    #[test]
    fn factory_default_pin_is_used_without_prompting() -> Result<()> {
        let service = credential_service(Arc::new(MockDiscovery::with_example()));
        let id = DeviceId(DEVICE_ID.into());
        let mut prompter = QueuedPrompter::default();

        let pin = current_pin(&service, &id, "Current PIV PIN: ", &mut prompter)?;

        assert_eq!(pin.as_bytes(), DEFAULT_PIN);
        assert!(prompter.prompts.is_empty());
        Ok(())
    }

    #[test]
    fn nondefault_pin_is_prompted() -> Result<()> {
        let mock = Arc::new(MockDiscovery::with_example());
        let id = DeviceId(DEVICE_ID.into());
        let factory_pin = PivPin::new(DEFAULT_PIN.to_vec())?;
        let changed_pin = PivPin::new(b"654321".to_vec())?;
        mock.change_pin(&id, SERIAL, &factory_pin, &changed_pin)?;
        let service = credential_service(mock);
        let mut prompter = QueuedPrompter::new(["654321"]);

        let pin = current_pin(&service, &id, "Current PIV PIN: ", &mut prompter)?;

        assert_eq!(pin.as_bytes(), b"654321");
        assert_eq!(prompter.prompts, ["Current PIV PIN: "]);
        Ok(())
    }

    #[test]
    fn factory_default_puk_is_used_without_prompting() -> Result<()> {
        let service = credential_service(Arc::new(MockDiscovery::with_example()));
        let id = DeviceId(DEVICE_ID.into());
        let mut prompter = QueuedPrompter::default();

        let puk = current_puk(&service, &id, "Current PIV PUK: ", &mut prompter)?;

        assert_eq!(puk.as_bytes(), DEFAULT_PUK);
        assert!(prompter.prompts.is_empty());
        Ok(())
    }

    #[test]
    fn factory_default_management_key_is_used_without_prompting() -> Result<()> {
        let service = credential_service(Arc::new(MockDiscovery::with_example()));
        let id = DeviceId(DEVICE_ID.into());
        let mut prompter = QueuedPrompter::default();

        let key = management_key(&service, &id, false, &mut prompter)?;

        assert_eq!(key.algorithm(), ManagementKeyAlgorithm::Aes192);
        assert!(prompter.prompts.is_empty());
        Ok(())
    }

    #[test]
    fn current_default_flag_forces_factory_management_key() -> Result<()> {
        let mock = Arc::new(MockDiscovery::with_example());
        let id = DeviceId(DEVICE_ID.into());
        let factory_key = ManagementKey::new(
            ManagementKeyAlgorithm::Aes192,
            DEFAULT_MANAGEMENT_KEY.to_vec(),
        )?;
        let nondefault_key = ManagementKey::new(ManagementKeyAlgorithm::Aes256, vec![0x55; 32])?;
        mock.change_management_key(&id, SERIAL, &factory_key, &nondefault_key)?;
        let service = credential_service(mock);
        let mut prompter = QueuedPrompter::default();

        let key = management_key(&service, &id, true, &mut prompter)?;

        assert_eq!(key.algorithm(), ManagementKeyAlgorithm::Aes192);
        assert!(prompter.prompts.is_empty());
        Ok(())
    }

    #[test]
    fn short_pin_input_reports_character_count_without_echoing_it() {
        let service = credential_service(Arc::new(MockDiscovery::with_example()));
        let id = DeviceId(DEVICE_ID.into());
        let mut prompter = QueuedPrompter::new(["123"]);

        let error = prompt_new_pin(&service, &id, &mut prompter).unwrap_err();

        assert_eq!(
            error.to_string(),
            "PIN must be 6–8 characters; you entered 3"
        );
        assert_eq!(prompter.prompts, ["New PIV PIN: "]);
    }

    #[test]
    fn fips_pin_input_requires_eight_characters() {
        let service = credential_service(Arc::new(MockDiscovery::with_example_fips()));
        let id = DeviceId(DEVICE_ID.into());
        let mut prompter = QueuedPrompter::new(["1234567"]);

        let error = prompt_new_pin(&service, &id, &mut prompter).unwrap_err();

        assert_eq!(
            error.to_string(),
            "This FIPS key requires an 8-character PIN"
        );
        assert_eq!(prompter.prompts, ["New PIV PIN: "]);
    }

    #[test]
    fn fips_puk_input_requires_eight_characters() {
        let service = credential_service(Arc::new(MockDiscovery::with_example_fips()));
        let id = DeviceId(DEVICE_ID.into());
        let mut prompter = QueuedPrompter::new(["1234567"]);

        let error = prompt_new_puk(&service, &id, &mut prompter).unwrap_err();

        assert_eq!(
            error.to_string(),
            "This FIPS key requires an 8-character PUK"
        );
        assert_eq!(prompter.prompts, ["New PIV PUK: "]);
    }

    #[test]
    fn management_key_hex_errors_use_management_key_messages() {
        assert_eq!(
            parse_management_key_hex(" 0a1B ").unwrap().as_slice(),
            [0x0a, 0x1b]
        );
        for (value, message) in [
            ("abc", "management key must be even-length hexadecimal"),
            ("zz", "management key must be hexadecimal"),
            ("é", "management key must be hexadecimal"),
        ] {
            assert_eq!(
                parse_management_key_hex(value).unwrap_err().to_string(),
                message
            );
        }
    }
}
