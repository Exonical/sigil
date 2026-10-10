use std::path::PathBuf;

use dioxus::prelude::*;
use sigil_app::CredentialService;
use sigil_core::{
    CertificateFormat, DeviceInfo, ManagementKey, ManagementKeyAlgorithm, PinPolicy,
    PivKeyAlgorithm, PivKeyConfiguration, PivPin, PivPuk, PivSlot, TouchPolicy,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    icons::Icon,
    state::{AppState, PivAction},
};

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
    let fips = device.fips == Some(true);
    let current = use_signal(|| Zeroizing::new(String::new()));
    let new_secret = use_signal(|| Zeroizing::new(String::new()));
    let confirmation = use_signal(|| Zeroizing::new(String::new()));
    let mut subject = use_signal(String::new);
    let mut input_path = use_signal(|| None::<PathBuf>);
    let mut output_path = use_signal(|| None::<PathBuf>);
    let mut format = use_signal(|| CertificateFormat::Pem);
    let mut algorithm = use_signal(|| PivKeyAlgorithm::EccP256);
    let mut pin_policy = use_signal(|| PinPolicy::Once);
    let mut touch_policy = use_signal(|| TouchPolicy::Default);
    let generated_key = use_signal(|| Zeroizing::new(String::new()));
    let key_generation_error = use_signal(|| None::<String>);
    let have_stored_key = use_signal(|| false);
    let destructive_confirmed = use_signal(|| false);
    let error = use_signal_sync(|| None::<String>);
    let busy = use_signal_sync(|| false);
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
            {new_code_fields("New PIV PIN", "Confirm new PIV PIN", if fips { "8 characters" } else { "6-8 characters" }, new_secret, confirmation)}
            {fips_code_note(fips, "PIN")}
        },
        PivAction::ChangePuk => rsx! {
            if puk_default {
                p { class: "modal-help", "The factory-default PUK will be used as the current PUK." }
            } else {
                {secret_field("Current PIV PUK", "Current PUK", current)}
            }
            {new_code_fields("New PIV PUK", "Confirm new PIV PUK", if fips { "8 characters" } else { "6-8 characters" }, new_secret, confirmation)}
            {fips_code_note(fips, "PUK")}
        },
        PivAction::UnblockPin => rsx! {
            if puk_default {
                p { class: "modal-help", "The factory-default PUK will be used." }
            } else {
                {secret_field("PIV PUK", "Current PUK", current)}
            }
            {new_code_fields("New PIV PIN", "Confirm new PIV PIN", if fips { "8 characters" } else { "6-8 characters" }, new_secret, confirmation)}
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
            {management_key_field(management_key_default, current)}
            div { class: "modal-field",
                label { r#for: "key-algorithm", "Algorithm" }
                select {
                    id: "key-algorithm",
                    value: if *algorithm.read() == PivKeyAlgorithm::EccP256 { "p256" } else { "p384" },
                    onchange: move |event| algorithm.set(if event.value() == "p384" { PivKeyAlgorithm::EccP384 } else { PivKeyAlgorithm::EccP256 }),
                    option { value: "p256", "ECC P-256" }
                    option { value: "p384", "ECC P-384" }
                }
            }
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
            if fips {
                div { class: "warning-callout",
                    Icon { name: "shield", size: 16 }
                    span { "FIPS keys require a PIN policy that is not Never and an 8-character PIN." }
                }
            }
            {destructive_confirmation(destructive_confirmed, "Generating a key may replace the private key in this slot.")}
        },
        PivAction::ImportCertificate(_) => rsx! {
            {management_key_field(management_key_default, current)}
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
            p { class: "modal-help", "Export the signed attestation and the YubiKey attestation certificate." }
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
            {management_key_field(management_key_default, current)}
            {destructive_confirmation(destructive_confirmed, "Delete this certificate from the selected PIV slot?")}
        },
        PivAction::DeleteKey(_) => rsx! {
            {management_key_field(management_key_default, current)}
            {destructive_confirmation(destructive_confirmed, "Permanently delete the private key in this slot?")}
        },
    };
    let can_submit = validate_form(
        action,
        fips,
        current_secret_default,
        current.read().as_str(),
        new_secret.read().as_str(),
        confirmation.read().as_str(),
        subject.read().as_str(),
        input_path.read().as_ref(),
        output_path.read().as_ref(),
        *pin_policy.read(),
        have_stored_key(),
        !generated_key.read().is_empty(),
        destructive_confirmed(),
    );
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
            validate_code(current.read().as_str(), "PIN", false).err()
        } else if needs_current_puk {
            validate_code(current.read().as_str(), "PUK", false).err()
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
                            let mut current = Zeroizing::new(current.read().to_string());
                            let mut new_secret = Zeroizing::new(new_secret.read().to_string());
                            let mut confirmation = Zeroizing::new(confirmation.read().to_string());
                            let subject = subject.read().clone();
                            let input_path = input_path.read().clone();
                            let output_path = output_path.read().clone();
                            let mut generated_key = Zeroizing::new(generated_key.read().to_string());
                            let current_format = *format.read();
                            let current_algorithm = *algorithm.read();
                            let current_pin_policy = *pin_policy.read();
                            let current_touch_policy = *touch_policy.read();
                            let destructive_confirmed = destructive_confirmed();
                            let mut busy = busy;
                            let mut error = error;
                            let mut toast = toast_signal;
                            let mut dialog = dialog_signal;
                            let mut piv_info = piv_info_signal;
                            let mut piv_slots = piv_slots_signal;
                            move |_| {
                                if busy() { return; }
                                let operation = prepare_operation(
                                    action,
                                    info.as_ref(),
                                    fips,
                                    &current,
                                    &new_secret,
                                    &confirmation,
                                    &subject,
                                    input_path.as_ref(),
                                    output_path.as_ref(),
                                    current_format,
                                    current_algorithm,
                                    current_pin_policy,
                                    current_touch_policy,
                                    &generated_key,
                                    destructive_confirmed,
                                );
                                let operation = match operation {
                                    Ok(operation) => operation,
                                    Err(message) => {
                                        error.set(Some(message));
                                        return;
                                    }
                                };
                                current.zeroize();
                                new_secret.zeroize();
                                confirmation.zeroize();
                                generated_key.zeroize();
                                busy.set(true);
                                error.set(None);
                                let service = service.clone();
                                let id = id.clone();
                                let serial = serial.clone();
                                std::thread::spawn(move || {
                                    let result = execute_operation(&service, &id, &serial, operation);
                                    match result {
                                        Ok(message) => {
                                            if let Ok(info) = service.piv_info(&id) {
                                                piv_info.set(Some((id.clone(), info)));
                                            }
                                            if let Ok(slots) = service.piv_slots(&id) {
                                                piv_slots.set(Some((id.clone(), slots)));
                                            }
                                            toast.set(Some(message));
                                            dialog.set(None);
                                        }
                                        Err(message) => error.set(Some(message)),
                                    }
                                    busy.set(false);
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
        .then(|| validate_code(current_pin.read().as_str(), "PIN", false).err())
        .flatten();
    let current_puk_error = (!puk_default)
        .then(|| validate_code(current_puk.read().as_str(), "PUK", false).err())
        .flatten();
    let current_management_key_error = (!management_key_default)
        .then(|| {
            current_management_key(info.as_ref(), current_management_input.read().as_str()).err()
        })
        .flatten();
    let valid = validate_code(pin.read().as_str(), "PIN", true).is_ok()
        && pin.read().as_str() == pin_confirmation.read().as_str()
        && validate_code(puk.read().as_str(), "PUK", true).is_ok()
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
                    {new_code_fields("New 8-character PIN", "Confirm new PIN", "8 characters", pin, pin_confirmation)}
                    {new_code_fields("New 8-character PUK", "Confirm new PUK", "8 characters", puk, puk_confirmation)}
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
                            let mut current_pin = Zeroizing::new(current_pin.read().to_string());
                            let mut current_puk = Zeroizing::new(current_puk.read().to_string());
                            let mut current_management_key = Zeroizing::new(current_management_input.read().to_string());
                            let mut pin = Zeroizing::new(pin.read().to_string());
                            let mut pin_confirmation = Zeroizing::new(pin_confirmation.read().to_string());
                            let mut puk = Zeroizing::new(puk.read().to_string());
                            let mut puk_confirmation = Zeroizing::new(puk_confirmation.read().to_string());
                            let mut management_key = Zeroizing::new(management_key.read().to_string());
                            let mut busy = busy;
                            let mut error = error;
                            let mut results = results;
                            let mut toast = toast_signal;
                            let mut piv_info = piv_info_signal;
                            let mut piv_slots = piv_slots_signal;
                            move |_| {
                                if busy() { return; }
                                let secrets = match prepare_fips_setup(
                                    info.as_ref(),
                                    pin_default,
                                    puk_default,
                                    management_key_default,
                                    &current_pin,
                                    &current_puk,
                                    &current_management_key,
                                    &pin,
                                    &pin_confirmation,
                                    &puk,
                                    &puk_confirmation,
                                    &management_key,
                                ) {
                                    Ok(secrets) => secrets,
                                    Err(message) => {
                                        error.set(Some(message));
                                        return;
                                    }
                                };
                                pin.zeroize();
                                pin_confirmation.zeroize();
                                puk.zeroize();
                                puk_confirmation.zeroize();
                                current_pin.zeroize();
                                current_puk.zeroize();
                                current_management_key.zeroize();
                                management_key.zeroize();
                                busy.set(true);
                                error.set(None);
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
                                    results.set(outcomes);
                                    if let Ok(info) = service.piv_info(&id) {
                                        piv_info.set(Some((id.clone(), info)));
                                    }
                                    if let Ok(slots) = service.piv_slots(&id) {
                                        piv_slots.set(Some((id.clone(), slots)));
                                    }
                                    toast.set(Some("FIPS initialization sequence finished. Review each step.".into()));
                                    busy.set(false);
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
                            Ok(()) => toast.set(Some("Management key copied to clipboard.".into())),
                            Err(error) => toast.set(Some(error)),
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

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex(value: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let value = value.trim();
    if value.is_empty() || !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err("Enter an even-length hexadecimal value.".into());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).map_err(|_| "Invalid hexadecimal value")?;
        bytes.push(u8::from_str_radix(pair, 16).map_err(|_| "Invalid hexadecimal value")?);
    }
    Ok(bytes)
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

fn validate_code(value: &str, kind: &str, fips: bool) -> Result<(), String> {
    let characters = value.chars().count();
    if fips && characters != 8 {
        return Err(format!("This FIPS key requires an 8-character {kind}."));
    }
    if !(6..=8).contains(&characters) {
        return Err(format!(
            "{kind} must be 6–8 characters; you entered {characters}"
        ));
    }
    if !value.is_ascii() {
        return Err(format!("{kind} must use ASCII characters."));
    }
    Ok(())
}

fn code_validation(value: &str, confirmation: &str, kind: &str, fips: bool) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if let Err(message) = validate_code(value, kind, fips) {
        return Some(message);
    }
    if !confirmation.is_empty() && value != confirmation {
        return Some(format!("{kind} entries do not match."));
    }
    None
}

fn make_pin(value: &str, fips: bool) -> Result<PivPin, String> {
    validate_code(value, "PIN", fips)?;
    PivPin::new(value.as_bytes().to_vec()).map_err(|error| error.to_string())
}

fn make_puk(value: &str, fips: bool) -> Result<PivPuk, String> {
    validate_code(value, "PUK", fips)?;
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

#[allow(clippy::too_many_arguments)]
fn validate_form(
    action: PivAction,
    fips: bool,
    current_secret_default: bool,
    current: &str,
    new_secret: &str,
    confirmation: &str,
    subject: &str,
    input_path: Option<&PathBuf>,
    output_path: Option<&PathBuf>,
    pin_policy: PinPolicy,
    have_stored_key: bool,
    generated_key: bool,
    destructive_confirmed: bool,
) -> bool {
    let management_entry_valid =
        !action_needs_management_key(action) || current_secret_default || !current.is_empty();
    let current_code_valid = match action {
        PivAction::ChangePin | PivAction::CreateCsr(_) => {
            current_secret_default || !current.is_empty()
        }
        PivAction::ChangePuk | PivAction::UnblockPin => {
            current_secret_default || !current.is_empty()
        }
        _ => true,
    };
    let code_valid = match action {
        PivAction::ChangePin | PivAction::UnblockPin => {
            validate_code(new_secret, "PIN", fips).is_ok() && new_secret == confirmation
        }
        PivAction::ChangePuk => {
            validate_code(new_secret, "PUK", fips).is_ok() && new_secret == confirmation
        }
        PivAction::CreateCsr(_) => !subject.trim().is_empty(),
        _ => true,
    };
    let output_valid = match action {
        PivAction::ImportCertificate(_) => input_path.is_some(),
        PivAction::ExportCertificate(_) | PivAction::CreateCsr(_) | PivAction::Attest(_) => {
            output_path.is_some()
        }
        _ => true,
    };
    let new_key_valid =
        action != PivAction::ChangeManagementKey || (generated_key && have_stored_key);
    let destructive_valid = !action_destructive(action) || destructive_confirmed;
    management_entry_valid
        && current_code_valid
        && code_valid
        && output_valid
        && new_key_valid
        && destructive_valid
        && (!fips || pin_policy != PinPolicy::Never)
}

#[allow(clippy::too_many_arguments)]
fn prepare_operation(
    action: PivAction,
    info: Option<&sigil_core::PivInfo>,
    fips: bool,
    current: &str,
    new_secret: &str,
    confirmation: &str,
    subject: &str,
    input_path: Option<&PathBuf>,
    output_path: Option<&PathBuf>,
    format: CertificateFormat,
    algorithm: PivKeyAlgorithm,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    generated_key: &str,
    destructive_confirmed: bool,
) -> Result<PivOperation, String> {
    match action {
        PivAction::ChangePin => {
            if new_secret != confirmation {
                return Err("PIV PINs do not match.".into());
            }
            Ok(PivOperation::ChangePin(
                current_pin(info, current)?,
                make_pin(new_secret, fips)?,
            ))
        }
        PivAction::ChangePuk => {
            if new_secret != confirmation {
                return Err("PIV PUKs do not match.".into());
            }
            Ok(PivOperation::ChangePuk(
                current_puk(info, current)?,
                make_puk(new_secret, fips)?,
            ))
        }
        PivAction::UnblockPin => {
            if new_secret != confirmation {
                return Err("PIV PINs do not match.".into());
            }
            Ok(PivOperation::UnblockPin(
                current_puk(info, current)?,
                make_pin(new_secret, fips)?,
            ))
        }
        PivAction::ChangeManagementKey => {
            let current = current_management_key(info, current)?;
            let mut new_bytes = parse_hex(generated_key)?;
            let new = ManagementKey::new(
                ManagementKeyAlgorithm::Aes256,
                std::mem::take(&mut *new_bytes),
            )
            .map_err(|error| error.to_string())?;
            Ok(PivOperation::ChangeManagementKey(current, new))
        }
        PivAction::GenerateKey(slot) => {
            if !destructive_confirmed {
                return Err("Confirm key generation for this slot.".into());
            }
            if fips && pin_policy == PinPolicy::Never {
                return Err("This FIPS key does not allow PIN policy Never.".into());
            }
            Ok(PivOperation::GenerateKey(
                current_management_key(info, current)?,
                PivKeyConfiguration {
                    slot,
                    algorithm,
                    pin_policy,
                    touch_policy,
                },
            ))
        }
        PivAction::ImportCertificate(slot) => {
            if !destructive_confirmed {
                return Err("Confirm certificate import for this slot.".into());
            }
            Ok(PivOperation::ImportCertificate(
                current_management_key(info, current)?,
                input_path
                    .cloned()
                    .ok_or_else(|| "Choose a certificate file.".to_owned())?,
                slot,
            ))
        }
        PivAction::ExportCertificate(slot) => Ok(PivOperation::ExportCertificate(
            slot,
            output_path
                .cloned()
                .ok_or_else(|| "Choose a file to save the certificate.".to_owned())?,
            format,
        )),
        PivAction::CreateCsr(slot) => {
            let path = output_path
                .cloned()
                .ok_or_else(|| "Choose a file to save the CSR.".to_owned())?;
            if subject.trim().is_empty() {
                return Err("Enter a CSR subject.".into());
            }
            Ok(PivOperation::CreateCsr(
                current_pin(info, current)?,
                slot,
                subject.trim().to_owned(),
                path,
            ))
        }
        PivAction::Attest(slot) => Ok(PivOperation::Attest(
            slot,
            output_path
                .cloned()
                .ok_or_else(|| "Choose a file to save the attestation.".to_owned())?,
        )),
        PivAction::DeleteCertificate(slot) => {
            if !destructive_confirmed {
                return Err("Confirm certificate deletion.".into());
            }
            Ok(PivOperation::DeleteCertificate(
                current_management_key(info, current)?,
                slot,
            ))
        }
        PivAction::DeleteKey(slot) => {
            if !destructive_confirmed {
                return Err("Confirm key deletion.".into());
            }
            Ok(PivOperation::DeleteKey(
                current_management_key(info, current)?,
                slot,
            ))
        }
    }
}

fn execute_operation(
    service: &CredentialService,
    id: &sigil_core::DeviceId,
    serial: &str,
    operation: PivOperation,
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
            .map(|_| format!("Key generated in slot {}.", configuration.slot))
            .map_err(|error| error.to_string()),
        PivOperation::ImportCertificate(management_key, path, slot) => {
            let encoded = std::fs::read(&path).map_err(|error| error.to_string())?;
            let der = sigil_piv::decode_certificate(&encoded).map_err(|error| error.to_string())?;
            service
                .import_certificate(id, serial, &management_key, slot, &der)
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
        PivOperation::CreateCsr(pin, slot, subject, path) => service
            .sign_csr(id, serial, &pin, slot, &subject)
            .map_err(|error| error.to_string())
            .and_then(|csr| {
                std::fs::write(&path, csr).map_err(|error| error.to_string())?;
                Ok(format!("CSR saved to {}.", path.display()))
            }),
        PivOperation::Attest(slot, path) => service
            .attest(id, serial, slot)
            .map_err(|error| error.to_string())
            .and_then(|attestation| {
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
                    "Attestation and intermediate saved to {}.",
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

#[allow(clippy::too_many_arguments)]
fn prepare_fips_setup(
    info: Option<&sigil_core::PivInfo>,
    pin_default: bool,
    puk_default: bool,
    management_key_default: bool,
    current_pin_text: &str,
    current_puk_text: &str,
    current_management_text: &str,
    new_pin_text: &str,
    pin_confirmation: &str,
    new_puk_text: &str,
    puk_confirmation: &str,
    new_management_text: &str,
) -> Result<FipsSetupSecrets, String> {
    if new_pin_text != pin_confirmation {
        return Err("PIV PINs do not match.".into());
    }
    if new_puk_text != puk_confirmation {
        return Err("PIV PUKs do not match.".into());
    }
    let current_pin = if pin_default {
        PivPin::new(DEFAULT_PIN.to_vec()).map_err(|error| error.to_string())?
    } else {
        make_pin(current_pin_text, false)?
    };
    let current_puk = if puk_default {
        PivPuk::new(DEFAULT_PUK.to_vec()).map_err(|error| error.to_string())?
    } else {
        make_puk(current_puk_text, false)?
    };
    let current_management_key = if management_key_default {
        let algorithm = info
            .and_then(|info| info.management_key.as_ref())
            .map_or(Ok(ManagementKeyAlgorithm::Aes192), |status| {
                ManagementKeyAlgorithm::from_piv_algorithm(status.algorithm)
            })
            .map_err(|error| error.to_string())?;
        ManagementKey::new(algorithm, DEFAULT_MANAGEMENT_KEY.to_vec())
            .map_err(|error| error.to_string())?
    } else {
        current_management_key(info, current_management_text)?
    };
    let new_pin = make_pin(new_pin_text, true)?;
    let new_puk = make_puk(new_puk_text, true)?;
    let mut new_management_key = parse_hex(new_management_text)?;
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
