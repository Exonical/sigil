use crate::state::SetLive;
use dioxus::prelude::*;
use sigil_core::{CredentialError, DeviceInfo, Fingerprint};
use zeroize::Zeroizing;

use crate::{icons::Icon, state::AppState};

#[component]
pub fn PasskeysPage(device: Option<DeviceInfo>) -> Element {
    let state = use_context::<AppState>();
    let device = match device {
        Some(device) => device,
        None => {
            return rsx! {
                div { class: "empty-state",
                    div { class: "empty-icon", Icon { name: "key", size: 28 } }
                    h2 { "No security key connected" }
                    p { "Connect a YubiKey to manage passkeys." }
                }
            };
        }
    };
    let id = device.id.clone();
    let mut pin = use_signal(|| Zeroizing::new(String::new()));
    let mut error = use_signal_sync(|| None::<String>);
    let mut message = use_signal_sync(|| None::<String>);
    let busy = use_signal_sync(|| false);
    let pending_delete = use_signal_sync(|| None::<String>);
    let current_status = state
        .fido_status
        .read()
        .as_ref()
        .filter(|(device_id, _)| device_id == &id)
        .map(|(_, status)| status.clone());
    let current_passkeys = state
        .passkeys
        .read()
        .as_ref()
        .filter(|(device_id, _)| device_id == &id)
        .map(|(_, credentials)| credentials.clone());
    let current_fingerprints = state
        .fingerprints
        .read()
        .as_ref()
        .filter(|(device_id, _)| device_id == &id)
        .map(|(_, fingerprints)| fingerprints.clone());
    let direct_mode = matches!(&state.mode, sigil_connect::ConnectionMode::Direct { .. });

    let service = state.credentials.clone();
    let mut status_signal = state.fido_status;
    let id_for_load = id.clone();
    use_hook(move || {
        let service = service.clone();
        std::thread::spawn(move || match service.fido_status(&id_for_load) {
            Ok(value) => status_signal.set_live(Some((id_for_load, value))),
            Err(value) => error.set_live(Some(value.to_string())),
        });
    });

    let pin_not_set = current_status
        .as_ref()
        .is_some_and(|status| status.pin_set == Some(false));
    let access_error = error
        .read()
        .as_ref()
        .is_some_and(|value| value == &CredentialError::FidoAccessRestricted.to_string());

    rsx! {
        div { class: "passkeys-page page-scroll",
            if device.simulated {
                div { class: "simulation-banner",
                    Icon { name: "info", size: 17 }
                    span { "Simulated FIDO data. No physical security key is connected to this fixture." }
                }
            }
            if access_error && direct_mode {
                section { class: "access-card",
                    div { class: "access-icon", Icon { name: "lock", size: 24 } }
                    div {
                        p { class: "eyebrow", "FIDO2 ACCESS" }
                        h2 { "Administrator privileges required" }
                        p { class: "muted", "Windows restricts direct FIDO operations in a standard user session. Restart Sigil as administrator or open Windows sign-in settings." }
                    }
                    div { class: "access-actions",
                        button { class: "primary-button", onclick: move |_| match crate::windows::restart_as_administrator() {
                            Ok(()) => std::process::exit(0),
                            Err(reason) => message.set_live(Some(reason)),
                        }, "Request access" }
                        button { class: "text-button", onclick: move |_| match crate::windows::open_signin_options() {
                            Ok(()) => message.set_live(Some("Windows sign-in settings opened.".into())),
                            Err(reason) => message.set_live(Some(reason)),
                        }, "Open Windows settings" }
                    }
                }
            } else if let Some(error) = error.read().as_ref() {
                section { class: "error-card",
                    p { class: "eyebrow", "FIDO2" }
                    h2 { "Could not inspect passkeys" }
                    p { class: "error-text", "{error}" }
                }
            } else if current_status.is_none() {
                section { class: "loading-card",
                    div { class: "spinner" }
                    span { "Checking FIDO2…" }
                }
            } else if pin_not_set {
                section { class: "empty-state passkey-empty",
                    div { class: "empty-icon", Icon { name: "key", size: 28 } }
                    h2 { "No passkeys stored" }
                    p { "A new PIN must be set before you can use this application." }
                }
            } else if let Some(status) = current_status {
                section { class: "fido-summary-card",
                    div {
                        p { class: "eyebrow", "SECURITY KEY" }
                        h2 { "Passkey management" }
                        p { class: "muted", "PIN retries remaining: {status.pin_retries.map(|value| value.to_string()).unwrap_or_else(|| \"unknown\".into())}" }
                    }
                    div { class: "status-badges",
                        span { class: "status-badge", if status.credential_management { "Passkey management available" } else { "Passkey management unavailable" } }
                        if status.fingerprint_enrollment {
                            span { class: "status-badge", "Fingerprint sensor available" }
                        }
                    }
                }

                section { class: "fido-content-card",
                    div { class: "section-heading",
                        div {
                            p { class: "eyebrow", "FIDO2" }
                            h2 { "Passkeys" }
                        }
                        button { class: "icon-button", title: "Refresh FIDO status", onclick: {
                            let service = state.credentials.clone();
                            let id = id.clone();
                            let mut status_signal = state.fido_status;
                            let mut error = error;
                            move |_| {
                                error.set_live(None);
                                let service = service.clone();
                                let id = id.clone();
                                std::thread::spawn(move || match service.fido_status(&id) {
                                    Ok(value) => status_signal.set_live(Some((id, value))),
                                    Err(value) => error.set_live(Some(value.to_string())),
                                });
                            }
                        }, Icon { name: "refresh", size: 17 } }
                    }
                    if status.credential_management {
                        div { class: "form-row",
                            label { r#for: "passkey-pin", "Unlock with FIDO2 PIN" }
                            input {
                                id: "passkey-pin",
                                r#type: "password",
                                autocomplete: "off",
                                placeholder: "Enter PIN",
                                value: "{pin.read().as_str()}",
                                oninput: move |event| pin.set(Zeroizing::new(event.value())),
                            }
                            button { class: "primary-button", disabled: busy(), onclick: {
                                let service = state.credentials.clone();
                                let id = id.clone();
                                let mut pin = pin;
                                let mut passkeys = state.passkeys;
                                let mut error = error;
                                let mut busy = busy;
                                move |_| {
                                    if busy() { return; }
                                    let supplied_pin = Zeroizing::new(pin.read().to_string());
                                    pin.set(Zeroizing::new(String::new()));
                                    busy.set_live(true);
                                    error.set_live(None);
                                    let service = service.clone();
                                    let id = id.clone();
                                    std::thread::spawn(move || {
                                        match service.discoverable_credentials(&id, &supplied_pin) {
                                            Ok(credentials) => passkeys.set_live(Some((id, credentials))),
                                            Err(value) => error.set_live(Some(value.to_string())),
                                        }
                                        busy.set_live(false);
                                    });
                                }
                            }, "List passkeys" }
                        }
                        if let Some(entries) = current_passkeys {
                            if entries.is_empty() {
                                div { class: "inline-empty", "No passkeys stored." }
                            } else {
                                div { class: "passkey-list scroll-list",
                                    for credential in entries.iter() {
                                        article { key: "{credential.credential_id}", class: "passkey-row",
                                            div { class: "round-icon", Icon { name: "key", size: 18 } }
                                            div { class: "passkey-info",
                                                strong { "{credential.rp_name}" }
                                                span { "{credential.user_name}" }
                                                small { "{credential.rp_id}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        div { class: "inline-empty", "Passkey management is not supported by this key." }
                    }
                }

                if status.fingerprint_enrollment {
                    FingerprintSection {
                        device_id: id.clone(),
                        fingerprints: current_fingerprints.unwrap_or_default(),
                        pin,
                        busy,
                        pending_delete,
                        message,
                        error,
                    }
                }
            }
            if let Some(message) = message.read().as_ref() {
                div { class: "inline-notice", "{message}" }
            }
        }
    }
}

#[component]
fn FingerprintSection(
    device_id: sigil_core::DeviceId,
    fingerprints: Vec<Fingerprint>,
    pin: Signal<Zeroizing<String>>,
    busy: SyncSignal<bool>,
    pending_delete: SyncSignal<Option<String>>,
    message: SyncSignal<Option<String>>,
    error: SyncSignal<Option<String>>,
) -> Element {
    let state = use_context::<AppState>();
    let id = device_id;
    rsx! {
        section { class: "fido-content-card fingerprint-card",
            div { class: "section-heading",
                div {
                    p { class: "eyebrow", "BIOMETRICS" }
                    h2 { "Fingerprints" }
                    p { class: "muted", "Enter the FIDO2 PIN to list, enroll, or remove a fingerprint." }
                }
            }
            if fingerprints.is_empty() {
                div { class: "inline-empty", "No fingerprints loaded." }
            } else {
                div { class: "fingerprint-list scroll-list",
                    for fingerprint in fingerprints.iter() {
                        article { key: "{fingerprint.id}", class: "fingerprint-row",
                            div { class: "round-icon", Icon { name: "fingerprint", size: 18 } }
                            div { class: "passkey-info",
                                strong { "{fingerprint.name.as_deref().unwrap_or(\"Unnamed fingerprint\")}" }
                                small { "{fingerprint.id}" }
                            }
                            if pending_delete.read().as_ref() == Some(&fingerprint.id) {
                                button { class: "danger-button", disabled: busy(), onclick: {
                                    let service = state.credentials.clone();
                                    let id = id.clone();
                                    let finger_id = fingerprint.id.clone();
                                    let mut busy = busy;
                                    let mut pin = pin;
                                    let mut pending_delete = pending_delete;
                                    let mut message = message;
                                    let mut error = error;
                                    let mut fingerprints_signal = state.fingerprints;
                                    move |_| {
                                        let supplied_pin = Zeroizing::new(pin.read().to_string());
                                        pin.set(Zeroizing::new(String::new()));
                                        pending_delete.set_live(None);
                                        busy.set_live(true);
                                        let service = service.clone();
                                        let id = id.clone();
                                        let finger_id = finger_id.clone();
                                        std::thread::spawn(move || {
                                            match service.remove_fingerprint(&id, &supplied_pin, &finger_id) {
                                                Ok(()) => {
                                                    let refreshed = service.fingerprints(&id, &supplied_pin);
                                                    if let Ok(value) = refreshed {
                                                        fingerprints_signal.set_live(Some((id.clone(), value)));
                                                    }
                                                    message.set_live(Some("Fingerprint removed.".into()));
                                                }
                                                Err(value) => error.set_live(Some(value.to_string())),
                                            }
                                            busy.set_live(false);
                                        });
                                    }
                                }, "Confirm remove" }
                                button { class: "text-button", onclick: move |_| pending_delete.set_live(None), "Cancel" }
                            } else {
                                button { class: "icon-button danger-icon", title: "Remove fingerprint", disabled: busy(), onclick: {
                                    let id = fingerprint.id.clone();
                                    move |_| pending_delete.set_live(Some(id.clone()))
                                }, Icon { name: "trash", size: 16 } }
                            }
                        }
                    }
                }
            }
            div { class: "fingerprint-actions",
                input {
                    r#type: "password",
                    autocomplete: "off",
                    placeholder: "FIDO2 PIN",
                    value: "{pin.read().as_str()}",
                    oninput: move |event| pin.set(Zeroizing::new(event.value())),
                }
                button { class: "secondary-button", disabled: busy(), onclick: {
                    let service = state.credentials.clone();
                    let id = id.clone();
                    let mut pin = pin;
                    let mut busy = busy;
                    let mut error = error;
                    let mut message = message;
                    let mut fingerprints_signal = state.fingerprints;
                    move |_| {
                        let supplied_pin = Zeroizing::new(pin.read().to_string());
                        pin.set(Zeroizing::new(String::new()));
                        busy.set_live(true);
                        error.set_live(None);
                        let service = service.clone();
                        let id = id.clone();
                        std::thread::spawn(move || {
                            match service.fingerprints(&id, &supplied_pin) {
                                Ok(value) => {
                                    fingerprints_signal.set_live(Some((id, value)));
                                    message.set_live(Some("Fingerprint list refreshed.".into()));
                                }
                                Err(value) => error.set_live(Some(value.to_string())),
                            }
                            busy.set_live(false);
                        });
                    }
                }, "List fingerprints" }
                button { class: "primary-button", disabled: busy(), onclick: {
                    let service = state.credentials.clone();
                    let id = id.clone();
                    let mut pin = pin;
                    let mut busy = busy;
                    let mut message = message;
                    let mut error = error;
                    let mut fingerprints_signal = state.fingerprints;
                    move |_| {
                        let supplied_pin = Zeroizing::new(pin.read().to_string());
                        pin.set(Zeroizing::new(String::new()));
                        busy.set_live(true);
                        message.set_live(Some("Touch the sensor when prompted.".into()));
                        error.set_live(None);
                        let service = service.clone();
                        let id = id.clone();
                        std::thread::spawn(move || {
                            let mut progress = message;
                            let result = service.enroll_fingerprint(&id, &supplied_pin, &mut |step| {
                                progress.set_live(Some(format!(
                                    "{} · {} samples remaining",
                                    step.message, step.remaining_samples
                                )));
                            });
                            match result {
                                Ok(_) => match service.fingerprints(&id, &supplied_pin) {
                                    Ok(value) => {
                                        fingerprints_signal.set_live(Some((id, value)));
                                        progress.set_live(Some("Fingerprint enrolled.".into()));
                                    }
                                    Err(value) => error.set_live(Some(value.to_string())),
                                },
                                Err(value) => {
                                    error.set_live(Some(value.to_string()));
                                }
                            }
                            busy.set_live(false);
                        });
                    }
                }, "Enroll fingerprint" }
            }
        }
    }
}
