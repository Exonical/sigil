use crate::state::SetLive;
use std::path::PathBuf;

use dioxus::prelude::*;
use sigil_app::CredentialService;
use sigil_core::{
    CertificateFormat, DeviceInfo, HexError, ManagementKey, ManagementKeyAlgorithm, PinPolicy,
    PivKeyAlgorithm, PivKeyConfiguration, PivPin, PivPuk, PivSlot, TouchPolicy, encode_hex,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    icons::Icon,
    managed::{self, SlotOperation},
    state::{AppState, PivAction},
};

use super::managed_dialog::{pin_length_check, pin_length_hint};

const DEFAULT_PIN: &[u8] = b"123456";
const DEFAULT_PUK: &[u8] = b"12345678";
const DEFAULT_MANAGEMENT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

#[component]
pub fn PivDialog(device: DeviceInfo, action: PivAction) -> Element {
    let state = use_context::<AppState>();
    let mut dialog_signal = state.dialog;
    let service = state.credentials.clone();
    let toast_signal = state.toast;
    let piv_info_signal = state.piv_info;
    let piv_slots_signal = state.piv_slots;
    let generated_spki_signal = state.generated_piv_spki;
    let info = state
        .piv_info
        .read()
        .as_ref()
        .filter(|(id, _)| id == &device.id)
        .map(|(_, info)| info.clone());
    let pin_default = info
        .as_ref()
        .and_then(|info| info.pin.as_ref())
        .and_then(|status| status.default_value)
        == Some(true);
    let puk_default = info
        .as_ref()
        .and_then(|info| info.puk.as_ref())
        .and_then(|status| status.default_value)
        == Some(true);
    let management_key_default = info
        .as_ref()
        .and_then(|info| info.management_key.as_ref())
        .and_then(|status| status.default_value)
        == Some(true);
    let capabilities = device.piv_capabilities.unwrap_or_default();
    let fips = device.fips == Some(true);
    let current = use_signal(|| Zeroizing::new(String::new()));
    let new_secret = use_signal(|| Zeroizing::new(String::new()));
    let confirmation = use_signal(|| Zeroizing::new(String::new()));
    let mut subject = use_signal(String::new);
    let mut input_path = use_signal(|| None::<PathBuf>);
    let mut output_path = use_signal(|| None::<PathBuf>);
    let mut format = use_signal(|| CertificateFormat::Pem);
    let mut algorithm = use_signal(|| PivKeyAlgorithm::EccP256);
    let mut pin_policy = use_signal(|| {
        if capabilities.pin_touch_policy {
            PinPolicy::Once
        } else {
            PinPolicy::Default
        }
    });
    let mut touch_policy = use_signal(|| TouchPolicy::Default);
    let generated_key = use_signal(|| Zeroizing::new(String::new()));
    let key_generation_error = use_signal(|| None::<String>);
    let have_stored_key = use_signal(|| false);
    let destructive_confirmed = use_signal(|| false);
    let error = use_signal_sync(|| None::<String>);
    let busy = use_signal_sync(|| false);
    let managed_capable = managed::slot_action(action).is_some() && managed::ready(&state);
    let own_key = use_signal(|| false);
    let managed_mode = managed_capable && !own_key();
    let should_generate_key = action == PivAction::ChangeManagementKey;
    let mut generated_key_signal = generated_key;
    let mut key_error_signal = key_generation_error;
    use_hook(move || {
        if should_generate_key {
            match generated_aes256_key() {
                Ok(key) => generated_key_signal.set(key),
                Err(message) => key_error_signal.set(Some(message)),
            }
        }
    });

    let title = action_title(action);
    let description = action_description(action);
    let needs_management_key = action_needs_management_key(action);
    let needs_current_pin = matches!(action, PivAction::ChangePin | PivAction::CreateCsr(_));
    let needs_current_puk = matches!(action, PivAction::ChangePuk | PivAction::UnblockPin);
    let current_secret_default = if needs_current_pin {
        pin_default
    } else if needs_current_puk {
        puk_default
    } else {
        management_key_default
    };
    let pin_policy_valid = !fips || *pin_policy.read() != PinPolicy::Never;

    let body = match action {
        PivAction::ChangePin => rsx! {
            if pin_default {
                p { class: "modal-help", "The factory-default PIN will be used as the current PIN." }
            } else {
                {secret_field("Current PIV PIN", "Current PIN", current)}
            }
            {new_code_fields("New PIV PIN", "Confirm new PIV PIN", pin_length_hint(fips), new_secret, confirmation)}
            {fips_code_note(fips, "PIN")}
        },
        PivAction::ChangePuk => rsx! {
            if puk_default {
                p { class: "modal-help", "The factory-default PUK will be used as the current PUK." }
            } else {
                {secret_field("Current PIV PUK", "Current PUK", current)}
            }
            {new_code_fields("New PIV PUK", "Confirm new PIV PUK", pin_length_hint(fips), new_secret, confirmation)}
            {fips_code_note(fips, "PUK")}
        },
        PivAction::UnblockPin => rsx! {
            if puk_default {
                p { class: "modal-help", "The factory-default PUK will be used." }
            } else {
                {secret_field("PIV PUK", "Current PUK", current)}
            }
            {new_code_fields("New PIV PIN", "Confirm new PIV PIN", pin_length_hint(fips), new_secret, confirmation)}
            {fips_code_note(fips, "PIN")}
        },
        PivAction::ChangeManagementKey => rsx! {
            if management_key_default {
                p { class: "modal-help", "The factory-default management key will be used." }
            } else {
                {secret_field("Current management key (hex)", "Hex-encoded current key", current)}
            }
            {generated_key_view(generated_key, have_stored_key, key_generation_error, toast_signal)}
        },
        PivAction::GenerateKey(_) => rsx! {
            {slot_key_section(managed_capable, own_key, management_key_default, current)}
            div { class: "modal-field",
                label { r#for: "key-algorithm", "Algorithm" }
                select {
                    id: "key-algorithm",
                    value: if *algorithm.read() == PivKeyAlgorithm::EccP256 { "p256" } else { "p384" },
                    onchange: move |event| algorithm.set(if event.value() == "p384" { PivKeyAlgorithm::EccP384 } else { PivKeyAlgorithm::EccP256 }),
                    option { value: "p256", "ECC P-256" }
                    if capabilities.p384_generation {
                        option { value: "p384", "ECC P-384" }
                    }
                }
            }
            if capabilities.pin_touch_policy {
                div { class: "form-pair",
                    div { class: "modal-field",
                        label { r#for: "pin-policy", "PIN policy" }
                        select {
                            id: "pin-policy",
                            value: format!("{:?}", pin_policy.read()).to_ascii_lowercase(),
                            onchange: move |event| pin_policy.set(parse_pin_policy(&event.value())),
                            option { value: "default", "Default" }
                            option { value: "once", "Once" }
                            option { value: "always", "Always" }
                            option { value: "never", disabled: fips, "Never" }
                        }
                    }
                    div { class: "modal-field",
                        label { r#for: "touch-policy", "Touch policy" }
                        select {
                            id: "touch-policy",
                            value: format!("{:?}", touch_policy.read()).to_ascii_lowercase(),
                            onchange: move |event| touch_policy.set(parse_touch_policy(&event.value())),
                            option { value: "default", "Default" }
                            option { value: "never", "Never" }
                            option { value: "always", "Always" }
                            option { value: "cached", "Cached" }
                        }
                    }
                }
            }
            if fips {
                div { class: "warning-callout",
                    Icon { name: "shield", size: 16 }
                    span { "FIPS keys require a PIN policy that is not Never and an 8-character PIN." }
                }
            }
            {destructive_confirmation(destructive_confirmed, "Generating a key may replace the private key in this slot.")}
        },
        PivAction::ImportCertificate(_) => rsx! {
            {slot_key_section(managed_capable, own_key, management_key_default, current)}
            div { class: "modal-field",
                label { "Certificate file" }
                button { class: "secondary-button", onclick: move |_| {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Certificate", &["der", "cer", "crt", "pem"])
                        .pick_file()
                    {
                        input_path.set(Some(path));
                    }
                }, Icon { name: "upload", size: 16 } "Choose certificate" }
                p { class: "modal-help", "{input_path.read().as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| \"No file selected\".into())}" }
            }
            {destructive_confirmation(destructive_confirmed, "Importing a certificate replaces any certificate currently stored in this slot.")}
        },
        PivAction::ExportCertificate(_) => rsx! {
            div { class: "form-pair",
                div { class: "modal-field",
                    label { r#for: "export-format", "Format" }
                    select {
                        id: "export-format",
                        value: if *format.read() == CertificateFormat::Pem { "pem" } else { "der" },
                        onchange: move |event| format.set(if event.value() == "der" { CertificateFormat::Der } else { CertificateFormat::Pem }),
                        option { value: "pem", "PEM" }
                        option { value: "der", "DER" }
                    }
                }
                div { class: "modal-field",
                    label { "Save to" }
                    button { class: "secondary-button", onclick: move |_| {
                        let extension = if *format.read() == CertificateFormat::Pem { "pem" } else { "der" };
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Certificate", &[extension])
                            .set_file_name(format!("piv-certificate.{extension}"))
                            .save_file()
                        {
                            output_path.set(Some(path));
                        }
                    }, Icon { name: "download", size: 16 } "Choose file" }
                    p { class: "modal-help", "{output_path.read().as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| \"No file selected\".into())}" }
                }
            }
        },
        PivAction::CreateCsr(_) => rsx! {
            if pin_default {
                p { class: "modal-help", "The factory-default PIN will be used." }
            } else {
                {secret_field("PIV PIN", "Current PIN", current)}
            }
            div { class: "modal-field",
                label { r#for: "csr-subject", "Subject" }
                input {
                    id: "csr-subject",
                    r#type: "text",
                    placeholder: "CN=Example User,O=Example",
                    value: "{subject}",
                    oninput: move |event| subject.set(event.value()),
                }
            }
            div { class: "modal-field",
                label { "Save CSR to" }
                button { class: "secondary-button", onclick: move |_| {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Certificate request", &["csr", "pem"])
                        .set_file_name("piv-request.csr")
                        .save_file()
                    {
                        output_path.set(Some(path));
                    }
                }, Icon { name: "download", size: 16 } "Choose file" }
                p { class: "modal-help", "{output_path.read().as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| \"No file selected\".into())}" }
            }
        },
        PivAction::Attest(_) => rsx! {
            p { class: "modal-help", "Export the signed attestation and vendor attestation certificate." }
            div { class: "modal-field",
                label { "Save attestation to" }
                button { class: "secondary-button", onclick: move |_| {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("DER certificate", &["der"])
                        .set_file_name("piv-attestation.der")
                        .save_file()
                    {
                        output_path.set(Some(path));
                    }
                }, Icon { name: "download", size: 16 } "Choose file" }
                p { class: "modal-help", "{output_path.read().as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| \"No file selected\".into())}" }
            }
        },
        PivAction::DeleteCertificate(_) => rsx! {
            {slot_key_section(managed_capable, own_key, management_key_default, current)}
            {destructive_confirmation(destructive_confirmed, "Delete this certificate from the selected PIV slot?")}
        },
        PivAction::DeleteKey(_) => rsx! {
            {slot_key_section(managed_capable, own_key, management_key_default, current)}
            {destructive_confirmation(destructive_confirmed, "Permanently delete the private key in this slot?")}
        },
    };
    let action_capability_supported = match action {
        PivAction::ChangePin
        | PivAction::ChangePuk
        | PivAction::UnblockPin
        | PivAction::GenerateKey(_)
        | PivAction::ImportCertificate(_)
        | PivAction::CreateCsr(_)
        | PivAction::DeleteCertificate(_) => capabilities.piv_writes,
        PivAction::ChangeManagementKey => capabilities.set_management_key,
        PivAction::Attest(_) => capabilities.attestation,
        PivAction::DeleteKey(_) => capabilities.delete_key,
        PivAction::ExportCertificate(_) => true,
    };
    let algorithm_capability_supported = match action {
        PivAction::GenerateKey(_) => {
            *algorithm.read() != PivKeyAlgorithm::EccP384 || capabilities.p384_generation
        }
        _ => true,
    };
    let slot_capability_supported = match action {
        PivAction::GenerateKey(slot) if (0x82..=0x95).contains(&slot.byte()) => {
            capabilities.retired_slot_generation
        }
        _ => true,
    };
    let form = PivForm {
        action,
        fips,
        current_secret_known: current_secret_default || managed_mode,
        current: Zeroizing::new(current.read().to_string()),
        new_secret: Zeroizing::new(new_secret.read().to_string()),
        confirmation: Zeroizing::new(confirmation.read().to_string()),
        subject: subject.read().clone(),
        input_path: input_path.read().clone(),
        output_path: output_path.read().clone(),
        format: *format.read(),
        algorithm: *algorithm.read(),
        pin_policy: if capabilities.pin_touch_policy {
            *pin_policy.read()
        } else {
            PinPolicy::Default
        },
        touch_policy: if capabilities.pin_touch_policy {
            *touch_policy.read()
        } else {
            TouchPolicy::Default
        },
        generated_key: Zeroizing::new(generated_key.read().to_string()),
        have_stored_key: have_stored_key(),
        destructive_confirmed: destructive_confirmed(),
    };
    let can_submit = action_capability_supported
        && algorithm_capability_supported
        && slot_capability_supported
        && form.check().is_ok();
    let label = action_button(action);
    let live_validation = code_validation(
        new_secret.read().as_str(),
        confirmation.read().as_str(),
        if matches!(action, PivAction::ChangePuk) {
            "PUK"
        } else {
            "PIN"
        },
        fips,
    )
    .or_else(|| {
        if current_secret_default || current.read().is_empty() {
            return None;
        }
        if needs_current_pin {
            pin_length_check(current.read().as_str(), "PIN", false).err()
        } else if needs_current_puk {
            pin_length_check(current.read().as_str(), "PUK", false).err()
        } else if needs_management_key {
            parse_hex(current.read().as_str()).err()
        } else {
            None
        }
    });

    rsx! {
        div {
            class: "modal-backdrop",
            tabindex: "-1",
            autofocus: true,
            onkeydown: move |event| {
                if event.key() == Key::Escape {
                    dialog_signal.set(None);
                }
            },
            section { class: "modal", role: "dialog", aria_modal: "true",
                header { class: "modal-header",
                    div {
                        p { class: "eyebrow", "PIV · SLOT {action_slot(action)}" }
                        h2 { "{title}" }
                        p { class: "modal-description", "{description}" }
                    }
                    button { class: "icon-button", title: "Close dialog", onclick: move |_| dialog_signal.set(None), Icon { name: "x", size: 17 } }
                }
                div { class: "modal-content",
                    {body}
                    if !pin_policy_valid {
                        div { class: "modal-error", "FIPS keys cannot use PIN policy Never." }
                    }
                    if let Some(message) = live_validation {
                        div { class: "modal-error", "{message}" }
                    }
                    if let Some(message) = error.read().as_ref() {
                        div { class: "modal-error", "{message}" }
                    }
                }
                footer { class: "modal-footer",
                    button { class: "text-button", disabled: busy(), onclick: move |_| dialog_signal.set(None), "Cancel" }
                    button {
                        class: if action_destructive(action) { "danger-button" } else { "primary-button" },
                        disabled: !can_submit || busy() || key_generation_error.read().is_some(),
                        onclick: {
                            let service = service.clone();
                            let id = device.id.clone();
                            let serial = device.serial.clone().unwrap_or_default();
                            let info = info.clone();
                            let mut form = form;
                            let mut busy = busy;
                            let mut error = error;
                            let mut toast = toast_signal;
                            let mut dialog = dialog_signal;
                            let mut piv_info = piv_info_signal;
                            let mut piv_slots = piv_slots_signal;
                            let mut generated_piv_spki = generated_spki_signal;
                            let managed_agent = state.managed.clone();
                            let managed_session = state.session.read().clone();
                            let managed_sessions = state.session;
                            let managed_auth = state.auth;
                            move |_| {
                                if busy() { return; }
                                if managed_mode {
                                    let (Some(agent), Some(session), Some(slot)) = (
                                        managed_agent.clone(),
                                        managed_session.clone(),
                                        managed::slot_action(action),
                                    ) else {
                                        error.set_live(Some("Sign in first to use managed PIV.".into()));
                                        return;
                                    };
                                    let operation = match action {
                                        PivAction::GenerateKey(_) => SlotOperation::GenerateKey(PivKeyConfiguration {
                                            slot,
                                            algorithm: form.algorithm,
                                            pin_policy: form.pin_policy,
                                            touch_policy: form.touch_policy,
                                        }),
                                        PivAction::ImportCertificate(_) => match form.input_path.as_ref().map(std::fs::read) {
                                            Some(Ok(der)) => SlotOperation::ImportCertificate(
                                                der,
                                                generated_piv_spki
                                                    .read()
                                                    .get(&(id.clone(), slot))
                                                    .cloned(),
                                            ),
                                            Some(Err(value)) => {
                                                error.set_live(Some(value.to_string()));
                                                return;
                                            }
                                            None => {
                                                error.set_live(Some("Choose a certificate file first.".into()));
                                                return;
                                            }
                                        },
                                        PivAction::DeleteCertificate(_) => SlotOperation::DeleteCertificate,
                                        PivAction::DeleteKey(_) => SlotOperation::DeleteKey,
                                        _ => return,
                                    };
                                    busy.set_live(true);
                                    error.set_live(None);
                                    let id = id.clone();
                                    let serial = serial.clone();
                                    let service = service.clone();
                                    let mut piv_info = piv_info;
                                    let mut piv_slots = piv_slots;
                                    let mut toast = toast;
                                    let mut dialog = dialog;
                                    let mut error = error;
                                    let mut busy = busy;
                                    let mut managed_generated_piv_spki = generated_piv_spki;
                                    std::thread::spawn(move || {
                                        let operation = match operation {
                                            SlotOperation::ImportCertificate(der, None) => {
                                                let expected = service
                                                    .piv_certificate(&id, slot)
                                                    .ok()
                                                    .flatten()
                                                    .and_then(|certificate| {
                                                        sigil_piv::management::certificate_spki(
                                                            &certificate.der,
                                                        )
                                                        .ok()
                                                    });
                                                SlotOperation::ImportCertificate(der, expected)
                                            }
                                            operation => operation,
                                        };
                                        let outcome = managed::fresh_token(&session, managed_sessions, managed_auth)
                                            .and_then(|token| {
                                                managed::run_slot_operation(agent.as_ref(), token.as_str(), &id, &serial, slot, operation)
                                                    .map_err(|value| managed::error_message(&value))
                                            });
                                        match outcome {
                                            Ok(generated) => {
                                                if let Some(spki) = generated
                                                    && let Ok(mut keys) = managed_generated_piv_spki.try_write()
                                                {
                                                    keys.insert((id.clone(), slot), spki);
                                                }
                                                managed::reload_piv(&service, &id, &mut piv_info, &mut piv_slots);
                                                toast.set_live(Some(format!("Managed PIV operation completed for slot {slot}.")));
                                                dialog.set_live(None);
                                            }
                                            Err(message) => error.set_live(Some(message)),
                                        }
                                        busy.set_live(false);
                                    });
                                    return;
                                }
                                let operation = match prepare_operation(&form, info.as_ref()) {
                                    Ok(operation) => operation,
                                    Err(message) => {
                                        error.set_live(Some(message));
                                        return;
                                    }
                                };
                                let key_slot = match &operation {
                                    PivOperation::ImportCertificate(_, _, slot)
                                    | PivOperation::CreateCsr(_, slot, _, _) => Some(*slot),
                                    _ => None,
                                };
                                let expected_public_key = key_slot.and_then(|slot| {
                                    generated_piv_spki
                                        .read()
                                        .get(&(id.clone(), slot))
                                        .cloned()
                                });
                                if let PivOperation::GenerateKey(_, configuration) = &operation
                                    && let Ok(mut keys) = generated_piv_spki.try_write()
                                {
                                    keys.remove(&(id.clone(), configuration.slot));
                                }
                                form.zeroize_secrets();
                                busy.set_live(true);
                                error.set_live(None);
                                let service = service.clone();
                                let id = id.clone();
                                let serial = serial.clone();
                                std::thread::spawn(move || {
                                    let mut generated_key = None;
                                    let result = execute_operation(
                                        &service,
                                        &id,
                                        &serial,
                                        operation,
                                        expected_public_key,
                                        &mut generated_key,
                                    );
                                    match result {
                                        Ok(message) => {
                                            if let Some((slot, spki)) = generated_key
                                                && let Ok(mut keys) = generated_piv_spki.try_write()
                                            {
                                                keys.insert((id.clone(), slot), spki);
                                            }
                                            if let Ok(info) = service.piv_info(&id) {
                                                piv_info.set_live(Some((id.clone(), info)));
                                            }
                                            if let Ok(slots) = service.piv_slots(&id) {
                                                piv_slots.set_live(Some((id.clone(), slots)));
                                            }
                                            toast.set_live(Some(message));
                                            dialog.set_live(None);
                                        }
                                        Err(message) => error.set_live(Some(message)),
                                    }
                                    busy.set_live(false);
                                });
                            }
                        },
                        if busy() { "Working…" } else { "{label}" }
                    }
                }
            }
        }
    }
}

#[component]
pub fn FipsSetupDialog(device: DeviceInfo) -> Element {
    let state = use_context::<AppState>();
    let mut dialog_signal = state.dialog;
    let service = state.credentials.clone();
    let toast_signal = state.toast;
    let piv_info_signal = state.piv_info;
    let piv_slots_signal = state.piv_slots;
    let info = state
        .piv_info
        .read()
        .as_ref()
        .filter(|(id, _)| id == &device.id)
        .map(|(_, info)| info.clone());
    let pin_default = info
        .as_ref()
        .and_then(|info| info.pin.as_ref())
        .is_some_and(|status| status.default_value == Some(true));
    let puk_default = info
        .as_ref()
        .and_then(|info| info.puk.as_ref())
        .is_some_and(|status| status.default_value == Some(true));
    let management_key_default = info
        .as_ref()
        .and_then(|info| info.management_key.as_ref())
        .is_some_and(|status| status.default_value == Some(true));
    let current_pin = use_signal(|| Zeroizing::new(String::new()));
    let current_puk = use_signal(|| Zeroizing::new(String::new()));
    let current_management_input = use_signal(|| Zeroizing::new(String::new()));
    let pin = use_signal(|| Zeroizing::new(String::new()));
    let pin_confirmation = use_signal(|| Zeroizing::new(String::new()));
    let puk = use_signal(|| Zeroizing::new(String::new()));
    let puk_confirmation = use_signal(|| Zeroizing::new(String::new()));
    let management_key = use_signal(|| Zeroizing::new(String::new()));
    let generation_error = use_signal(|| None::<String>);
    let have_stored_key = use_signal(|| false);
    let error = use_signal_sync(|| None::<String>);
    let busy = use_signal_sync(|| false);
    let results = use_signal_sync(Vec::<(String, String)>::new);
    let mut generated_key = management_key;
    let mut generated_error = generation_error;
    use_hook(move || match generated_aes256_key() {
        Ok(key) => generated_key.set(key),
        Err(message) => generated_error.set(Some(message)),
    });
    let current_pin_error = (!pin_default)
        .then(|| pin_length_check(current_pin.read().as_str(), "PIN", false).err())
        .flatten();
    let current_puk_error = (!puk_default)
        .then(|| pin_length_check(current_puk.read().as_str(), "PUK", false).err())
        .flatten();
    let current_management_key_error = (!management_key_default)
        .then(|| {
            current_management_key(info.as_ref(), current_management_input.read().as_str()).err()
        })
        .flatten();
    let valid = pin_length_check(pin.read().as_str(), "PIN", true).is_ok()
        && pin.read().as_str() == pin_confirmation.read().as_str()
        && pin_length_check(puk.read().as_str(), "PUK", true).is_ok()
        && puk.read().as_str() == puk_confirmation.read().as_str()
        && (pin_default || current_pin_error.is_none())
        && (puk_default || current_puk_error.is_none())
        && (management_key_default || current_management_key_error.is_none())
        && !management_key.read().is_empty()
        && have_stored_key();
    let pin_error = code_validation(
        pin.read().as_str(),
        pin_confirmation.read().as_str(),
        "PIN",
        true,
    );
    let puk_error = code_validation(
        puk.read().as_str(),
        puk_confirmation.read().as_str(),
        "PUK",
        true,
    );

    rsx! {
        div {
            class: "modal-backdrop",
            tabindex: "-1",
            autofocus: true,
            onkeydown: move |event| if event.key() == Key::Escape && !busy() { dialog_signal.set(None); },
            section { class: "modal", role: "dialog", aria_modal: "true",
                header { class: "modal-header",
                    div {
                        p { class: "eyebrow", "FIPS INITIALIZATION" }
                        h2 { "Set up FIPS" }
                        p { class: "modal-description", "Change the PIN, PUK and management key in order. The key will reboot after each change." }
                    }
                    button { class: "icon-button", disabled: busy(), title: "Close dialog", onclick: move |_| dialog_signal.set(None), Icon { name: "x", size: 17 } }
                }
                div { class: "modal-content",
                    if !pin_default { {secret_field("Current PIV PIN", "Current PIN", current_pin)} }
                    if !puk_default { {secret_field("Current PIV PUK", "Current PUK", current_puk)} }
                    if !management_key_default { {secret_field("Current management key (hex)", "Current key in hex", current_management_input)} }
                    {new_code_fields("New 8-character PIN", "Confirm new PIN", pin_length_hint(true), pin, pin_confirmation)}
                    {new_code_fields("New 8-character PUK", "Confirm new PUK", pin_length_hint(true), puk, puk_confirmation)}
                    {generated_key_view(management_key, have_stored_key, generation_error, toast_signal)}
                    if let Some(message) = current_pin_error { div { class: "modal-error", "{message}" } }
                    if let Some(message) = current_puk_error { div { class: "modal-error", "{message}" } }
                    if let Some(message) = current_management_key_error { div { class: "modal-error", "{message}" } }
                    if let Some(message) = pin_error { div { class: "modal-error", "{message}" } }
                    if let Some(message) = puk_error { div { class: "modal-error", "{message}" } }
                    if !results.read().is_empty() {
                        div { class: "fips-step-list",
                            for (step, result) in results.read().iter() {
                                div { key: "{step}", class: "fips-step",
                                    strong { "{step}" }
                                    span { "{result}" }
                                }
                            }
                        }
                    }
                    if let Some(message) = generation_error.read().as_ref() {
                        div { class: "modal-error", "{message}" }
                    }
                    if let Some(message) = error.read().as_ref() {
                        div { class: "modal-error", "{message}" }
                    }
                }
                footer { class: "modal-footer",
                    button { class: "text-button", disabled: busy(), onclick: move |_| dialog_signal.set(None), "Cancel" }
                    button {
                        class: "primary-button",
                        disabled: !valid || busy() || !results.read().is_empty(),
                        onclick: {
                            let service = service.clone();
                            let id = device.id.clone();
                            let serial = device.serial.clone().unwrap_or_default();
                            let info = info.clone();
                            let mut form = FipsSetupForm {
                                pin_default,
                                puk_default,
                                management_key_default,
                                current_pin: Zeroizing::new(current_pin.read().to_string()),
                                current_puk: Zeroizing::new(current_puk.read().to_string()),
                                current_management_key: Zeroizing::new(current_management_input.read().to_string()),
                                new_pin: Zeroizing::new(pin.read().to_string()),
                                pin_confirmation: Zeroizing::new(pin_confirmation.read().to_string()),
                                new_puk: Zeroizing::new(puk.read().to_string()),
                                puk_confirmation: Zeroizing::new(puk_confirmation.read().to_string()),
                                new_management_key: Zeroizing::new(management_key.read().to_string()),
                            };
                            let mut busy = busy;
                            let mut error = error;
                            let mut results = results;
                            let mut toast = toast_signal;
                            let mut piv_info = piv_info_signal;
                            let mut piv_slots = piv_slots_signal;
                            move |_| {
                                if busy() { return; }
                                let secrets = match prepare_fips_setup(&form, info.as_ref()) {
                                    Ok(secrets) => secrets,
                                    Err(message) => {
                                        error.set_live(Some(message));
                                        return;
                                    }
                                };
                                form.zeroize_secrets();
                                busy.set_live(true);
                                error.set_live(None);
                                let service = service.clone();
                                let id = id.clone();
                                let serial = serial.clone();
                                std::thread::spawn(move || {
                                    let mut outcomes = Vec::new();
                                    let pin_result = service.change_pin(&id, &serial, &secrets.current_pin, &secrets.new_pin);
                                    outcomes.push(("Change PIN".to_owned(), step_result(&pin_result)));
                                    if pin_result.is_ok() {
                                        let puk_result = service.change_puk(&id, &serial, &secrets.current_puk, &secrets.new_puk);
                                        outcomes.push(("Change PUK".to_owned(), step_result(&puk_result)));
                                        if puk_result.is_ok() {
                                            let management_result = service.change_management_key(
                                                &id,
                                                &serial,
                                                &secrets.current_management_key,
                                                &secrets.new_management_key,
                                            );
                                            outcomes.push(("Change management key".to_owned(), step_result(&management_result)));
                                        } else {
                                            outcomes.push(("Change management key".into(), "Not run".into()));
                                        }
                                    } else {
                                        outcomes.push(("Change PUK".into(), "Not run".into()));
                                        outcomes.push(("Change management key".into(), "Not run".into()));
                                    }
                                    results.set_live(outcomes);
                                    if let Ok(info) = service.piv_info(&id) {
                                        piv_info.set_live(Some((id.clone(), info)));
                                    }
                                    if let Ok(slots) = service.piv_slots(&id) {
                                        piv_slots.set_live(Some((id.clone(), slots)));
                                    }
                                    toast.set_live(Some("FIPS initialization sequence finished. Review each step.".into()));
                                    busy.set_live(false);
                                });
                            }
                        },
                        if busy() { "Setting up…" } else { "Set up FIPS" }
                    }
                    if !results.read().is_empty() {
                        button { class: "primary-button", onclick: move |_| dialog_signal.set(None), "Close" }
                    }
                }
            }
        }
    }
}

enum PivOperation {
    ChangePin(PivPin, PivPin),
    ChangePuk(PivPuk, PivPuk),
    UnblockPin(PivPuk, PivPin),
    ChangeManagementKey(ManagementKey, ManagementKey),
    GenerateKey(ManagementKey, PivKeyConfiguration),
    ImportCertificate(ManagementKey, PathBuf, PivSlot),
    ExportCertificate(PivSlot, PathBuf, CertificateFormat),
    CreateCsr(PivPin, PivSlot, String, PathBuf),
    Attest(PivSlot, PathBuf),
    DeleteCertificate(ManagementKey, PivSlot),
    DeleteKey(ManagementKey, PivSlot),
}

struct FipsSetupSecrets {
    current_pin: PivPin,
    new_pin: PivPin,
    current_puk: PivPuk,
    new_puk: PivPuk,
    current_management_key: ManagementKey,
    new_management_key: ManagementKey,
}

fn secret_field(
    label: &'static str,
    placeholder: &'static str,
    mut value: Signal<Zeroizing<String>>,
) -> Element {
    rsx! {
        div { class: "modal-field",
            label { "{label}" }
            input {
                r#type: "password",
                autocomplete: "off",
                placeholder,
                value: "{value.read().as_str()}",
                oninput: move |event| value.set(Zeroizing::new(event.value())),
            }
        }
    }
}

fn new_code_fields(
    label: &'static str,
    confirmation_label: &'static str,
    placeholder: &'static str,
    value: Signal<Zeroizing<String>>,
    confirmation: Signal<Zeroizing<String>>,
) -> Element {
    rsx! {
        {secret_field(label, placeholder, value)}
        {secret_field(confirmation_label, "Enter it again", confirmation)}
    }
}

fn fips_code_note(fips: bool, kind: &'static str) -> Element {
    if fips {
        rsx! {
            div { class: "warning-callout",
                Icon { name: "shield", size: 16 }
                span { "This FIPS key requires an 8-character {kind}." }
            }
        }
    } else {
        rsx! {}
    }
}

fn expected_slot_spki(
    service: &CredentialService,
    id: &sigil_core::DeviceId,
    slot: PivSlot,
    known: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, String> {
    if known.is_some() {
        return Ok(known);
    }
    service
        .piv_certificate(id, slot)
        .map_err(|error| error.to_string())?
        .map(|certificate| {
            sigil_piv::management::certificate_spki(&certificate.der)
                .map_err(|error| error.to_string())
        })
        .transpose()
}

fn slot_key_section(
    managed_capable: bool,
    mut own_key: Signal<bool>,
    default_key: bool,
    current: Signal<Zeroizing<String>>,
) -> Element {
    if !managed_capable {
        return management_key_field(default_key, current);
    }
    if own_key() {
        rsx! {
            {management_key_field(default_key, current)}
            button { class: "text-button", onclick: move |_| own_key.set(false), "Use the Sigil-managed key instead" }
        }
    } else {
        rsx! {
            p { class: "modal-help", "Sigil uses the management key it holds for this key, so you do not enter one." }
            button { class: "text-button", onclick: move |_| own_key.set(true), "Use my own management key" }
        }
    }
}

fn management_key_field(default_key: bool, current: Signal<Zeroizing<String>>) -> Element {
    if default_key {
        rsx! {
            p { class: "modal-help", "The factory-default management key will be used automatically." }
        }
    } else {
        secret_field(
            "Current management key (hex)",
            "Enter the current key in hexadecimal",
            current,
        )
    }
}

fn destructive_confirmation(mut confirmed: Signal<bool>, description: &'static str) -> Element {
    rsx! {
        div { class: "warning-callout danger-callout",
            Icon { name: "warning", size: 16 }
            span { "{description}" }
        }
        label { class: "dialog-checkbox",
            input {
                r#type: "checkbox",
                checked: confirmed(),
                onchange: move |event| confirmed.set(event.checked()),
            }
            span { "I understand this cannot be undone." }
        }
    }
}

fn generated_key_view(
    key: Signal<Zeroizing<String>>,
    mut stored: Signal<bool>,
    generation_error: Signal<Option<String>>,
    mut toast: SyncSignal<Option<String>>,
) -> Element {
    if let Some(message) = generation_error.read().as_ref() {
        return rsx! { div { class: "modal-error", "{message}" } };
    }
    rsx! {
        div { class: "modal-field",
            label { "New AES-256 management key" }
            div { class: "stored-key",
                code { "{key.read().as_str()}" }
                button {
                    class: "icon-button",
                    title: "Copy management key",
                    onclick: move |_| {
                        let mut value = Zeroizing::new(key.read().to_string());
                        match crate::windows::copy_to_clipboard(&value) {
                            Ok(()) => toast.set_live(Some("Management key copied to clipboard.".into())),
                            Err(error) => toast.set_live(Some(error)),
                        }
                        value.zeroize();
                    },
                    Icon { name: "copy", size: 16 }
                }
            }
            label { class: "dialog-checkbox",
                input {
                    r#type: "checkbox",
                    checked: stored(),
                    onchange: move |event| stored.set(event.checked()),
                }
                span { "I have stored it somewhere safe." }
            }
        }
    }
}

fn generated_aes256_key() -> Result<Zeroizing<String>, String> {
    let key = CredentialService::generate_management_key(ManagementKeyAlgorithm::Aes256)
        .map_err(|error| error.to_string())?;
    Ok(Zeroizing::new(encode_hex(key.as_bytes())))
}

fn parse_hex(value: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    sigil_core::parse_hex(value).map_err(|error| match error {
        HexError::InvalidLength | HexError::NonAscii => {
            "Enter an even-length hexadecimal value.".into()
        }
        HexError::InvalidDigit => "Invalid hexadecimal value".into(),
    })
}

fn current_management_key(
    info: Option<&sigil_core::PivInfo>,
    entered: &str,
) -> Result<ManagementKey, String> {
    let status = info
        .and_then(|info| info.management_key.as_ref())
        .ok_or_else(|| "PIV management-key metadata is unavailable.".to_owned())?;
    let algorithm = ManagementKeyAlgorithm::from_piv_algorithm(status.algorithm)
        .map_err(|error| error.to_string())?;
    if status.default_value == Some(true) {
        return ManagementKey::new(algorithm, DEFAULT_MANAGEMENT_KEY.to_vec())
            .map_err(|error| error.to_string());
    }
    let mut bytes = parse_hex(entered)?;
    ManagementKey::new(algorithm, std::mem::take(&mut *bytes)).map_err(|error| error.to_string())
}

fn current_pin(info: Option<&sigil_core::PivInfo>, entered: &str) -> Result<PivPin, String> {
    if info
        .and_then(|info| info.pin.as_ref())
        .is_some_and(|status| status.default_value == Some(true))
    {
        return PivPin::new(DEFAULT_PIN.to_vec()).map_err(|error| error.to_string());
    }
    make_pin(entered, false)
}

fn current_puk(info: Option<&sigil_core::PivInfo>, entered: &str) -> Result<PivPuk, String> {
    if info
        .and_then(|info| info.puk.as_ref())
        .is_some_and(|status| status.default_value == Some(true))
    {
        return PivPuk::new(DEFAULT_PUK.to_vec()).map_err(|error| error.to_string());
    }
    make_puk(entered, false)
}

fn code_validation(value: &str, confirmation: &str, kind: &str, fips: bool) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if let Err(message) = pin_length_check(value, kind, fips) {
        return Some(message);
    }
    if !confirmation.is_empty() && value != confirmation {
        return Some(format!("{kind} entries do not match."));
    }
    None
}

fn make_pin(value: &str, fips: bool) -> Result<PivPin, String> {
    pin_length_check(value, "PIN", fips)?;
    PivPin::new(value.as_bytes().to_vec()).map_err(|error| error.to_string())
}

fn make_puk(value: &str, fips: bool) -> Result<PivPuk, String> {
    pin_length_check(value, "PUK", fips)?;
    PivPuk::new(value.as_bytes().to_vec()).map_err(|error| error.to_string())
}

fn parse_pin_policy(value: &str) -> PinPolicy {
    match value {
        "never" => PinPolicy::Never,
        "once" => PinPolicy::Once,
        "always" => PinPolicy::Always,
        "match_once" => PinPolicy::MatchOnce,
        "match_always" => PinPolicy::MatchAlways,
        _ => PinPolicy::Default,
    }
}

fn parse_touch_policy(value: &str) -> TouchPolicy {
    match value {
        "never" => TouchPolicy::Never,
        "always" => TouchPolicy::Always,
        "cached" => TouchPolicy::Cached,
        _ => TouchPolicy::Default,
    }
}

fn action_slot(action: PivAction) -> String {
    match action {
        PivAction::GenerateKey(slot)
        | PivAction::ImportCertificate(slot)
        | PivAction::ExportCertificate(slot)
        | PivAction::CreateCsr(slot)
        | PivAction::Attest(slot)
        | PivAction::DeleteCertificate(slot)
        | PivAction::DeleteKey(slot) => slot.to_string(),
        _ => "PIV".into(),
    }
}

fn action_title(action: PivAction) -> &'static str {
    match action {
        PivAction::ChangePin => "Change PIV PIN",
        PivAction::ChangePuk => "Change PIV PUK",
        PivAction::UnblockPin => "Unblock PIV PIN",
        PivAction::ChangeManagementKey => "Change management key",
        PivAction::GenerateKey(_) => "Generate key",
        PivAction::ImportCertificate(_) => "Import certificate",
        PivAction::ExportCertificate(_) => "Export certificate",
        PivAction::CreateCsr(_) => "Create CSR",
        PivAction::Attest(_) => "Attest key",
        PivAction::DeleteCertificate(_) => "Delete certificate",
        PivAction::DeleteKey(_) => "Delete key",
    }
}

fn action_description(action: PivAction) -> &'static str {
    match action {
        PivAction::ChangePin => "Choose a new PIV PIN for this key.",
        PivAction::ChangePuk => "Choose a new PIV PUK for this key.",
        PivAction::UnblockPin => "Use the PIV PUK to set a new PIN.",
        PivAction::ChangeManagementKey => "A new random AES-256 key will be generated.",
        PivAction::GenerateKey(_) => "Generate the private key inside the selected PIV slot.",
        PivAction::ImportCertificate(_) => "Import a certificate matching the key in this slot.",
        PivAction::ExportCertificate(_) => "Save the selected certificate to a file.",
        PivAction::CreateCsr(_) => "Sign a certificate signing request using the selected slot.",
        PivAction::Attest(_) => "Export the signed key attestation and attestation certificate.",
        PivAction::DeleteCertificate(_) => "Remove the certificate from this PIV slot.",
        PivAction::DeleteKey(_) => "Permanently delete the private key in this PIV slot.",
    }
}

fn action_button(action: PivAction) -> &'static str {
    match action {
        PivAction::ChangePin => "Change PIN",
        PivAction::ChangePuk => "Change PUK",
        PivAction::UnblockPin => "Unblock PIN",
        PivAction::ChangeManagementKey => "Change management key",
        PivAction::GenerateKey(_) => "Generate key",
        PivAction::ImportCertificate(_) => "Import certificate",
        PivAction::ExportCertificate(_) => "Export certificate",
        PivAction::CreateCsr(_) => "Create CSR",
        PivAction::Attest(_) => "Attest key",
        PivAction::DeleteCertificate(_) => "Delete certificate",
        PivAction::DeleteKey(_) => "Delete key",
    }
}

fn action_needs_management_key(action: PivAction) -> bool {
    matches!(
        action,
        PivAction::ChangeManagementKey
            | PivAction::GenerateKey(_)
            | PivAction::ImportCertificate(_)
            | PivAction::DeleteCertificate(_)
            | PivAction::DeleteKey(_)
    )
}

fn action_destructive(action: PivAction) -> bool {
    matches!(
        action,
        PivAction::GenerateKey(_)
            | PivAction::ImportCertificate(_)
            | PivAction::DeleteCertificate(_)
            | PivAction::DeleteKey(_)
    )
}

/// Snapshot of the PIV dialog inputs. `check` holds the per-action rules
/// that gate the submit button, and `prepare_operation` runs them again
/// before it builds the operation, so the two cannot disagree.
struct PivForm {
    action: PivAction,
    fips: bool,
    /// The current secret is the factory default or held by Sigil, so the
    /// user does not have to enter it.
    current_secret_known: bool,
    current: Zeroizing<String>,
    new_secret: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    subject: String,
    input_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    format: CertificateFormat,
    algorithm: PivKeyAlgorithm,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    generated_key: Zeroizing<String>,
    have_stored_key: bool,
    destructive_confirmed: bool,
}

impl PivForm {
    fn check(&self) -> Result<(), String> {
        if action_destructive(self.action) && !self.destructive_confirmed {
            return Err(match self.action {
                PivAction::GenerateKey(_) => "Confirm key generation for this slot.",
                PivAction::ImportCertificate(_) => "Confirm certificate import for this slot.",
                PivAction::DeleteCertificate(_) => "Confirm certificate deletion.",
                _ => "Confirm key deletion.",
            }
            .into());
        }
        match self.action {
            PivAction::ChangePin | PivAction::UnblockPin => {
                self.check_new_code("PIN", "PIV PINs do not match.")?;
            }
            PivAction::ChangePuk => self.check_new_code("PUK", "PIV PUKs do not match.")?,
            PivAction::ChangeManagementKey => {
                if self.generated_key.is_empty() || !self.have_stored_key {
                    return Err("Store the new management key somewhere safe.".into());
                }
            }
            PivAction::ImportCertificate(_) => {
                self.certificate_file()?;
            }
            PivAction::ExportCertificate(_) | PivAction::Attest(_) => {
                self.output_file()?;
            }
            PivAction::CreateCsr(_) => {
                self.output_file()?;
                self.csr_subject()?;
            }
            PivAction::GenerateKey(_)
            | PivAction::DeleteCertificate(_)
            | PivAction::DeleteKey(_) => {}
        }
        if let Some(kind) = current_secret_kind(self.action)
            && !self.current_secret_known
            && self.current.is_empty()
        {
            return Err(format!("Enter the current {kind}."));
        }
        if self.fips && self.pin_policy == PinPolicy::Never {
            return Err("This FIPS key does not allow PIN policy Never.".into());
        }
        Ok(())
    }

    fn check_new_code(&self, kind: &str, mismatch: &str) -> Result<(), String> {
        if *self.new_secret != *self.confirmation {
            return Err(mismatch.into());
        }
        pin_length_check(&self.new_secret, kind, self.fips)
    }

    fn certificate_file(&self) -> Result<PathBuf, String> {
        self.input_path
            .clone()
            .ok_or_else(|| "Choose a certificate file.".to_owned())
    }

    fn output_file(&self) -> Result<PathBuf, String> {
        self.output_path.clone().ok_or_else(|| {
            match self.action {
                PivAction::CreateCsr(_) => "Choose a file to save the CSR.",
                PivAction::Attest(_) => "Choose a file to save the attestation.",
                _ => "Choose a file to save the certificate.",
            }
            .to_owned()
        })
    }

    fn csr_subject(&self) -> Result<String, String> {
        let subject = self.subject.trim();
        if subject.is_empty() {
            return Err("Enter a CSR subject.".into());
        }
        Ok(subject.to_owned())
    }

    fn zeroize_secrets(&mut self) {
        self.current.zeroize();
        self.new_secret.zeroize();
        self.confirmation.zeroize();
        self.generated_key.zeroize();
    }
}

/// The secret the user enters as the "current" value for `action`, if any.
fn current_secret_kind(action: PivAction) -> Option<&'static str> {
    match action {
        PivAction::ChangePin | PivAction::CreateCsr(_) => Some("PIV PIN"),
        PivAction::ChangePuk | PivAction::UnblockPin => Some("PIV PUK"),
        action if action_needs_management_key(action) => Some("management key"),
        _ => None,
    }
}

fn prepare_operation(
    form: &PivForm,
    info: Option<&sigil_core::PivInfo>,
) -> Result<PivOperation, String> {
    form.check()?;
    let current = form.current.as_str();
    match form.action {
        PivAction::ChangePin => Ok(PivOperation::ChangePin(
            current_pin(info, current)?,
            make_pin(&form.new_secret, form.fips)?,
        )),
        PivAction::ChangePuk => Ok(PivOperation::ChangePuk(
            current_puk(info, current)?,
            make_puk(&form.new_secret, form.fips)?,
        )),
        PivAction::UnblockPin => Ok(PivOperation::UnblockPin(
            current_puk(info, current)?,
            make_pin(&form.new_secret, form.fips)?,
        )),
        PivAction::ChangeManagementKey => {
            let current = current_management_key(info, current)?;
            let mut new_bytes = parse_hex(&form.generated_key)?;
            let new = ManagementKey::new(
                ManagementKeyAlgorithm::Aes256,
                std::mem::take(&mut *new_bytes),
            )
            .map_err(|error| error.to_string())?;
            Ok(PivOperation::ChangeManagementKey(current, new))
        }
        PivAction::GenerateKey(slot) => Ok(PivOperation::GenerateKey(
            current_management_key(info, current)?,
            PivKeyConfiguration {
                slot,
                algorithm: form.algorithm,
                pin_policy: form.pin_policy,
                touch_policy: form.touch_policy,
            },
        )),
        PivAction::ImportCertificate(slot) => Ok(PivOperation::ImportCertificate(
            current_management_key(info, current)?,
            form.certificate_file()?,
            slot,
        )),
        PivAction::ExportCertificate(slot) => Ok(PivOperation::ExportCertificate(
            slot,
            form.output_file()?,
            form.format,
        )),
        PivAction::CreateCsr(slot) => Ok(PivOperation::CreateCsr(
            current_pin(info, current)?,
            slot,
            form.csr_subject()?,
            form.output_file()?,
        )),
        PivAction::Attest(slot) => Ok(PivOperation::Attest(slot, form.output_file()?)),
        PivAction::DeleteCertificate(slot) => Ok(PivOperation::DeleteCertificate(
            current_management_key(info, current)?,
            slot,
        )),
        PivAction::DeleteKey(slot) => Ok(PivOperation::DeleteKey(
            current_management_key(info, current)?,
            slot,
        )),
    }
}

fn execute_operation(
    service: &CredentialService,
    id: &sigil_core::DeviceId,
    serial: &str,
    operation: PivOperation,
    expected_public_key: Option<Vec<u8>>,
    generated_spki: &mut Option<(PivSlot, Vec<u8>)>,
) -> Result<String, String> {
    match operation {
        PivOperation::ChangePin(old, new) => service
            .change_pin(id, serial, &old, &new)
            .map(|()| "PIV PIN changed.".into())
            .map_err(|error| error.to_string()),
        PivOperation::ChangePuk(old, new) => service
            .change_puk(id, serial, &old, &new)
            .map(|()| "PIV PUK changed.".into())
            .map_err(|error| error.to_string()),
        PivOperation::UnblockPin(puk, new_pin) => service
            .unblock_pin(id, serial, &puk, &new_pin)
            .map(|()| "PIV PIN unblocked.".into())
            .map_err(|error| error.to_string()),
        PivOperation::ChangeManagementKey(current, new) => service
            .change_management_key(id, serial, &current, &new)
            .map(|()| "PIV management key changed. Store the displayed key securely.".into())
            .map_err(|error| error.to_string()),
        PivOperation::GenerateKey(management_key, configuration) => service
            .generate_key(id, serial, &management_key, configuration)
            .map(|spki| {
                *generated_spki = Some((configuration.slot, spki));
                format!("Key generated in slot {}.", configuration.slot)
            })
            .map_err(|error| error.to_string()),
        PivOperation::ImportCertificate(management_key, path, slot) => {
            let encoded = std::fs::read(&path).map_err(|error| error.to_string())?;
            let der = sigil_piv::decode_certificate(&encoded).map_err(|error| error.to_string())?;
            let expected_public_key = expected_slot_spki(service, id, slot, expected_public_key)?;
            service
                .import_certificate(
                    id,
                    serial,
                    &management_key,
                    slot,
                    &der,
                    expected_public_key.as_deref(),
                )
                .map(|()| format!("Certificate imported into slot {slot}."))
                .map_err(|error| error.to_string())
        }
        PivOperation::ExportCertificate(slot, path, format) => service
            .export_certificate(id, slot, format)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                std::fs::write(&path, bytes).map_err(|error| error.to_string())?;
                Ok(format!("Certificate exported to {}.", path.display()))
            }),
        PivOperation::CreateCsr(pin, slot, subject, path) => {
            let expected_public_key = expected_slot_spki(service, id, slot, expected_public_key)?;
            service
                .sign_csr(
                    id,
                    serial,
                    &pin,
                    slot,
                    &subject,
                    expected_public_key.as_deref(),
                )
                .map_err(|error| error.to_string())
                .and_then(|csr| {
                    std::fs::write(&path, csr).map_err(|error| error.to_string())?;
                    Ok(format!("CSR saved to {}.", path.display()))
                })
        }
        PivOperation::Attest(slot, path) => service
            .attest(id, serial, slot)
            .map_err(|error| error.to_string())
            .and_then(|attestation| {
                let verification = if attestation.inspection.verified {
                    format!(
                        "Verified: chains to {}",
                        attestation
                            .inspection
                            .attestation_root
                            .as_deref()
                            .unwrap_or("the vendor root")
                    )
                } else {
                    format!(
                        "NOT VERIFIED: {}",
                        attestation
                            .inspection
                            .verification_error
                            .as_deref()
                            .unwrap_or("unknown reason")
                    )
                };
                std::fs::write(&path, attestation.attestation_der)
                    .map_err(|error| error.to_string())?;
                let intermediate = path.with_file_name(format!(
                    "{}-intermediate.der",
                    path.file_stem()
                        .and_then(|stem| stem.to_str())
                        .unwrap_or("piv-attestation")
                ));
                std::fs::write(&intermediate, attestation.intermediate_der)
                    .map_err(|error| error.to_string())?;
                Ok(format!(
                    "{verification}. Attestation and intermediate saved to {}.",
                    path.display()
                ))
            }),
        PivOperation::DeleteCertificate(management_key, slot) => service
            .delete_certificate(id, serial, &management_key, slot)
            .map(|()| format!("Certificate deleted from slot {slot}."))
            .map_err(|error| error.to_string()),
        PivOperation::DeleteKey(management_key, slot) => service
            .delete_key(id, serial, &management_key, slot)
            .map(|()| format!("Key deleted from slot {slot}."))
            .map_err(|error| error.to_string()),
    }
}

struct FipsSetupForm {
    pin_default: bool,
    puk_default: bool,
    management_key_default: bool,
    current_pin: Zeroizing<String>,
    current_puk: Zeroizing<String>,
    current_management_key: Zeroizing<String>,
    new_pin: Zeroizing<String>,
    pin_confirmation: Zeroizing<String>,
    new_puk: Zeroizing<String>,
    puk_confirmation: Zeroizing<String>,
    new_management_key: Zeroizing<String>,
}

impl FipsSetupForm {
    fn zeroize_secrets(&mut self) {
        self.current_pin.zeroize();
        self.current_puk.zeroize();
        self.current_management_key.zeroize();
        self.new_pin.zeroize();
        self.pin_confirmation.zeroize();
        self.new_puk.zeroize();
        self.puk_confirmation.zeroize();
        self.new_management_key.zeroize();
    }
}

fn prepare_fips_setup(
    form: &FipsSetupForm,
    info: Option<&sigil_core::PivInfo>,
) -> Result<FipsSetupSecrets, String> {
    if *form.new_pin != *form.pin_confirmation {
        return Err("PIV PINs do not match.".into());
    }
    if *form.new_puk != *form.puk_confirmation {
        return Err("PIV PUKs do not match.".into());
    }
    let current_pin = if form.pin_default {
        PivPin::new(DEFAULT_PIN.to_vec()).map_err(|error| error.to_string())?
    } else {
        make_pin(&form.current_pin, false)?
    };
    let current_puk = if form.puk_default {
        PivPuk::new(DEFAULT_PUK.to_vec()).map_err(|error| error.to_string())?
    } else {
        make_puk(&form.current_puk, false)?
    };
    let current_management_key = if form.management_key_default {
        let algorithm = info
            .and_then(|info| info.management_key.as_ref())
            .map_or(Ok(ManagementKeyAlgorithm::Aes192), |status| {
                ManagementKeyAlgorithm::from_piv_algorithm(status.algorithm)
            })
            .map_err(|error| error.to_string())?;
        ManagementKey::new(algorithm, DEFAULT_MANAGEMENT_KEY.to_vec())
            .map_err(|error| error.to_string())?
    } else {
        current_management_key(info, &form.current_management_key)?
    };
    let new_pin = make_pin(&form.new_pin, true)?;
    let new_puk = make_puk(&form.new_puk, true)?;
    let mut new_management_key = parse_hex(&form.new_management_key)?;
    let new_management_key = ManagementKey::new(
        ManagementKeyAlgorithm::Aes256,
        std::mem::take(&mut *new_management_key),
    )
    .map_err(|error| error.to_string())?;
    Ok(FipsSetupSecrets {
        current_pin,
        new_pin,
        current_puk,
        new_puk,
        current_management_key,
        new_management_key,
    })
}

fn step_result(result: &sigil_core::Result<()>) -> String {
    match result {
        Ok(()) => "Complete".into(),
        Err(error) => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(action: PivAction) -> PivForm {
        PivForm {
            action,
            fips: false,
            current_secret_known: false,
            current: Zeroizing::new("123456".into()),
            new_secret: Zeroizing::new("654321".into()),
            confirmation: Zeroizing::new("654321".into()),
            subject: "CN=Example".into(),
            input_path: Some(PathBuf::from("in.pem")),
            output_path: Some(PathBuf::from("out.pem")),
            format: CertificateFormat::Pem,
            algorithm: PivKeyAlgorithm::EccP256,
            pin_policy: PinPolicy::Once,
            touch_policy: TouchPolicy::Default,
            generated_key: Zeroizing::new("00".into()),
            have_stored_key: true,
            destructive_confirmed: true,
        }
    }

    fn error(form: &PivForm) -> String {
        form.check().expect_err("form should be rejected")
    }

    #[test]
    fn complete_forms_pass_for_every_action() {
        let slot = PivSlot::AUTHENTICATION;
        for action in [
            PivAction::ChangePin,
            PivAction::ChangePuk,
            PivAction::UnblockPin,
            PivAction::ChangeManagementKey,
            PivAction::GenerateKey(slot),
            PivAction::ImportCertificate(slot),
            PivAction::ExportCertificate(slot),
            PivAction::CreateCsr(slot),
            PivAction::Attest(slot),
            PivAction::DeleteCertificate(slot),
            PivAction::DeleteKey(slot),
        ] {
            assert_eq!(form(action).check(), Ok(()), "{action:?}");
        }
    }

    #[test]
    fn new_codes_must_match_and_be_valid() {
        let mut change = form(PivAction::ChangePuk);
        change.confirmation = Zeroizing::new("654320".into());
        assert_eq!(error(&change), "PIV PUKs do not match.");

        let mut unblock = form(PivAction::UnblockPin);
        unblock.confirmation = Zeroizing::new("654320".into());
        assert_eq!(error(&unblock), "PIV PINs do not match.");

        let mut fips = form(PivAction::ChangePin);
        fips.fips = true;
        assert_eq!(error(&fips), "This FIPS key requires an 8-character PIN.");
    }

    #[test]
    fn current_secret_is_required_unless_known() {
        let slot = PivSlot::SIGNATURE;
        for (action, message) in [
            (PivAction::ChangePin, "Enter the current PIV PIN."),
            (PivAction::CreateCsr(slot), "Enter the current PIV PIN."),
            (PivAction::UnblockPin, "Enter the current PIV PUK."),
            (
                PivAction::DeleteKey(slot),
                "Enter the current management key.",
            ),
        ] {
            let mut empty = form(action);
            empty.current = Zeroizing::new(String::new());
            assert_eq!(error(&empty), message, "{action:?}");
            empty.current_secret_known = true;
            assert_eq!(empty.check(), Ok(()), "{action:?}");
        }
        let mut export = form(PivAction::ExportCertificate(slot));
        export.current = Zeroizing::new(String::new());
        assert_eq!(export.check(), Ok(()));
    }

    #[test]
    fn destructive_actions_need_confirmation() {
        let slot = PivSlot::KEY_MANAGEMENT;
        for (action, message) in [
            (
                PivAction::GenerateKey(slot),
                "Confirm key generation for this slot.",
            ),
            (
                PivAction::ImportCertificate(slot),
                "Confirm certificate import for this slot.",
            ),
            (
                PivAction::DeleteCertificate(slot),
                "Confirm certificate deletion.",
            ),
            (PivAction::DeleteKey(slot), "Confirm key deletion."),
        ] {
            let mut unconfirmed = form(action);
            unconfirmed.destructive_confirmed = false;
            assert_eq!(error(&unconfirmed), message, "{action:?}");
        }
        let mut export = form(PivAction::ExportCertificate(slot));
        export.destructive_confirmed = false;
        assert_eq!(export.check(), Ok(()));
    }

    #[test]
    fn files_subject_and_stored_key_are_required() {
        let slot = PivSlot::CARD_AUTHENTICATION;
        let mut import = form(PivAction::ImportCertificate(slot));
        import.input_path = None;
        assert_eq!(error(&import), "Choose a certificate file.");

        for (action, message) in [
            (
                PivAction::ExportCertificate(slot),
                "Choose a file to save the certificate.",
            ),
            (PivAction::CreateCsr(slot), "Choose a file to save the CSR."),
            (
                PivAction::Attest(slot),
                "Choose a file to save the attestation.",
            ),
        ] {
            let mut missing = form(action);
            missing.output_path = None;
            assert_eq!(error(&missing), message, "{action:?}");
        }

        let mut csr = form(PivAction::CreateCsr(slot));
        csr.subject = "  ".into();
        assert_eq!(error(&csr), "Enter a CSR subject.");

        let mut unstored = form(PivAction::ChangeManagementKey);
        unstored.have_stored_key = false;
        assert!(unstored.check().is_err());
        let mut ungenerated = form(PivAction::ChangeManagementKey);
        ungenerated.generated_key = Zeroizing::new(String::new());
        assert!(ungenerated.check().is_err());
    }

    #[test]
    fn fips_keys_reject_pin_policy_never() {
        let mut generate = form(PivAction::GenerateKey(PivSlot::AUTHENTICATION));
        generate.pin_policy = PinPolicy::Never;
        assert_eq!(generate.check(), Ok(()));
        generate.fips = true;
        assert_eq!(
            error(&generate),
            "This FIPS key does not allow PIN policy Never."
        );
    }

    #[test]
    fn prepare_operation_runs_the_same_checks() {
        let mut unconfirmed = form(PivAction::DeleteKey(PivSlot::AUTHENTICATION));
        unconfirmed.destructive_confirmed = false;
        assert_eq!(
            prepare_operation(&unconfirmed, None).err().as_deref(),
            Some("Confirm key deletion.")
        );

        let mut csr = form(PivAction::CreateCsr(PivSlot::SIGNATURE));
        csr.subject = "  CN=Example User  ".into();
        match prepare_operation(&csr, None) {
            Ok(PivOperation::CreateCsr(_, slot, subject, path)) => {
                assert_eq!(slot, PivSlot::SIGNATURE);
                assert_eq!(subject, "CN=Example User");
                assert_eq!(path, PathBuf::from("out.pem"));
            }
            _ => panic!("expected a CSR operation"),
        }
    }
}
