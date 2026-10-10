use dioxus::prelude::*;
use sigil_core::{Application, DeviceInfo, Secret};
use zeroize::Zeroizing;

use crate::{
    icons::Icon,
    pages::home::{app_icon, application_name},
    state::AppState,
};

#[component]
pub fn ToggleApplicationsDialog(device: DeviceInfo) -> Element {
    let state = use_context::<AppState>();
    let mut dialog_signal = state.dialog;
    let service = state.credentials.clone();
    let toast = state.toast;
    let mut usb = use_signal(|| device.usb_enabled.clone());
    let mut nfc = use_signal(|| device.nfc_enabled.clone());
    let mut lock_code = use_signal(|| Zeroizing::new(String::new()));
    let error = use_signal_sync(|| None::<String>);
    let saving = use_signal_sync(|| false);
    let usb_apps = device.usb_supported.clone();
    let nfc_apps = device.nfc_supported.clone();
    let locked = device.config_locked == Some(true);
    let has_changes = *usb.read() != device.usb_enabled
        || (!nfc_apps.is_empty() && *nfc.read() != device.nfc_enabled);
    let keeps_sigil_path = usb.read().iter().any(is_usb_sigil_path);
    let lock_valid = !locked || parse_lock_code(lock_code.read().as_str()).is_ok();
    let valid = !usb.read().is_empty()
        && keeps_sigil_path
        && lock_valid
        && usb
            .read()
            .iter()
            .all(|application| usb_apps.contains(application))
        && nfc
            .read()
            .iter()
            .all(|application| nfc_apps.contains(application));
    let save_disabled = !has_changes || !valid || saving();

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
            section { class: "modal modal-wide", role: "dialog", aria_modal: "true",
                header { class: "modal-header",
                    div {
                        p { class: "eyebrow", "DEVICE CONFIGURATION" }
                        h2 { "Toggle applications" }
                        p { class: "modal-description", "Choose which YubiKey applications are enabled on each interface." }
                    }
                    button { class: "icon-button", title: "Close dialog", onclick: move |_| dialog_signal.set(None), Icon { name: "x", size: 17 } }
                }
                div { class: "modal-content",
                    div { class: "application-grid",
                        ApplicationGroup {
                            title: "USB",
                            applications: usb_apps.clone(),
                            selected: usb.read().clone(),
                            onchange: move |application| toggle_application(&mut usb, application),
                        }
                        ApplicationGroup {
                            title: "NFC",
                            applications: nfc_apps.clone(),
                            selected: nfc.read().clone(),
                            onchange: move |application| toggle_application(&mut nfc, application),
                            disabled: nfc_apps.is_empty(),
                        }
                    }
                    if usb.read().is_empty() {
                        div { class: "modal-error", "At least one USB application must remain enabled." }
                    } else if !keeps_sigil_path {
                        div { class: "modal-error", "Keep PIV, OATH, OpenPGP, or YubiHSM Auth enabled over USB so Sigil can still reach the key." }
                    }
                    if locked {
                        div { class: "modal-field",
                            label { r#for: "configuration-lock", "Configuration lock code (32 hex characters)" }
                            input {
                                id: "configuration-lock",
                                r#type: "password",
                                autocomplete: "off",
                                placeholder: "Enter the 32-character lock code",
                                value: "{lock_code.read().as_str()}",
                                oninput: move |event| lock_code.set(Zeroizing::new(event.value())),
                            }
                            p { class: "modal-help", "The configuration lock code is required to change a locked YubiKey." }
                            if !lock_valid {
                                div { class: "modal-error", "Enter exactly 32 hexadecimal characters." }
                            }
                        }
                    }
                    p { class: "modal-help", "The YubiKey will restart to apply the change." }
                    if let Some(message) = error.read().as_ref() {
                        div { class: "modal-error", "{message}" }
                    }
                }
                footer { class: "modal-footer",
                    button { class: "text-button", disabled: saving(), onclick: move |_| dialog_signal.set(None), "Cancel" }
                    button {
                        class: "primary-button",
                        disabled: save_disabled,
                        onclick: {
                            let service = service.clone();
                            let id = device.id.clone();
                            let expected_serial = device.serial.clone().unwrap_or_default();
                            let usb = usb.read().clone();
                            let nfc = if nfc_apps.is_empty() { None } else { Some(nfc.read().clone()) };
                            let lock_code_input = Zeroizing::new(lock_code.read().to_string());
                            let mut saving = saving;
                            let mut error = error;
                            let mut toast = toast;
                            let mut dialog = dialog_signal;
                            move |_| {
                                if saving() { return; }
                                let lock_code = if locked {
                                    match parse_lock_code(&lock_code_input) {
                                        Ok(code) => Some(code),
                                        Err(message) => {
                                            error.set(Some(message));
                                            return;
                                        }
                                    }
                                } else {
                                    None
                                };
                                saving.set(true);
                                error.set(None);
                                let service = service.clone();
                                let id = id.clone();
                                let serial = expected_serial.clone();
                                let usb = usb.clone();
                                let nfc = nfc.clone();
                                std::thread::spawn(move || {
                                    let result = service.set_enabled_applications(
                                        &id,
                                        &serial,
                                        &usb,
                                        nfc.as_deref(),
                                        lock_code.as_ref(),
                                    );
                                    match result {
                                        Ok(()) => {
                                            toast.set(Some("The YubiKey will restart to apply the change.".into()));
                                            dialog.set(None);
                                        }
                                        Err(value) => error.set(Some(value.to_string())),
                                    }
                                    saving.set(false);
                                });
                            }
                        },
                        if saving() { "Saving…" } else { "Save" }
                    }
                }
            }
        }
    }
}

#[component]
fn ApplicationGroup(
    title: &'static str,
    applications: Vec<Application>,
    selected: Vec<Application>,
    onchange: EventHandler<Application>,
    #[props(default = false)] disabled: bool,
) -> Element {
    rsx! {
        section { class: "application-group",
            h3 { "{title}" }
            if applications.is_empty() {
                p { class: "modal-help", "No NFC applications are supported." }
            } else {
                for application in applications.iter() {
                    {
                        let application = application.clone();
                        let checked = selected.contains(&application);
                        rsx! {
                            label { key: "{title}-{application:?}", class: "app-toggle-row",
                                span { class: "app-toggle-label",
                                    {app_icon(&application)}
                                    "{application_name(&application)}"
                                }
                                input {
                                    r#type: "checkbox",
                                    checked,
                                    disabled,
                                    onchange: {
                                        let application = application.clone();
                                        move |_| onchange.call(application.clone())
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn toggle_application(selected: &mut Signal<Vec<Application>>, application: Application) {
    let mut values = selected.read().clone();
    if values.contains(&application) {
        values.retain(|item| item != &application);
    } else {
        values.push(application);
    }
    selected.set(values);
}

fn is_usb_sigil_path(application: &Application) -> bool {
    matches!(
        application,
        Application::Piv | Application::Oath | Application::OpenPgp | Application::YubiHsmAuth
    )
}

fn parse_lock_code(value: &str) -> Result<Secret, String> {
    if value.len() != 32 || !value.is_ascii() {
        return Err("Enter exactly 32 hexadecimal characters.".into());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(16));
    for pair in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).map_err(|_| "Invalid hexadecimal lock code")?;
        bytes.push(u8::from_str_radix(pair, 16).map_err(|_| "Invalid hexadecimal lock code")?);
    }
    Ok(Secret::new(std::mem::take(&mut *bytes)))
}
