use dioxus::prelude::*;
use sigil_core::{DeviceInfo, PivPin};
use zeroize::Zeroizing;

use crate::{
    icons::Icon,
    managed,
    state::{AppState, DialogKind, ManagedAction, PivAction, SetLive},
};

#[component]
pub fn ManagedDialog(device: DeviceInfo, action: ManagedAction) -> Element {
    let state = use_context::<AppState>();
    let mut dialog = state.dialog;
    let fips = device.fips == Some(true);
    let new_pin = use_signal(|| Zeroizing::new(String::new()));
    let confirmation = use_signal(|| Zeroizing::new(String::new()));
    let error = use_signal_sync(|| None::<String>);
    let busy = use_signal_sync(|| false);
    let needs_pin = action == ManagedAction::UnblockPin;
    let (title, description, label) = copy(action);
    let length_ok = pin_length_ok(new_pin.read().as_str(), fips);
    let matches = new_pin.read().as_str() == confirmation.read().as_str();
    let can_submit = !busy() && (!needs_pin || (length_ok && matches));
    let live_message = needs_pin
        .then(|| pin_length_message(new_pin.read().as_str(), fips))
        .flatten();
    let length_hint = pin_length_hint(fips);

    rsx! {
        div { class: "modal-backdrop", tabindex: "-1", autofocus: true,
            onkeydown: move |event| {
                if event.key() == Key::Escape && !busy() {
                    dialog.set(None);
                }
            },
            section { class: "modal", role: "dialog", aria_modal: "true",
                header { class: "modal-header",
                    div {
                        p { class: "eyebrow", "MANAGED BY SIGIL" }
                        h2 { "{title}" }
                        p { class: "modal-description", "{description}" }
                    }
                    button { class: "icon-button", title: "Close dialog", disabled: busy(), onclick: move |_| dialog.set(None), Icon { name: "x", size: 17 } }
                }
                div { class: "modal-content",
                    if needs_pin {
                        div { class: "modal-field",
                            label { r#for: "managed-new-pin", "New PIV PIN ({length_hint})" }
                            input {
                                id: "managed-new-pin",
                                r#type: "password",
                                autocomplete: "off",
                                value: "{new_pin.read().as_str()}",
                                oninput: {
                                    let mut new_pin = new_pin;
                                    move |event: Event<FormData>| new_pin.set(Zeroizing::new(event.value()))
                                },
                            }
                        }
                        div { class: "modal-field",
                            label { r#for: "managed-confirm-pin", "Confirm new PIV PIN" }
                            input {
                                id: "managed-confirm-pin",
                                r#type: "password",
                                autocomplete: "off",
                                value: "{confirmation.read().as_str()}",
                                oninput: {
                                    let mut confirmation = confirmation;
                                    move |event: Event<FormData>| confirmation.set(Zeroizing::new(event.value()))
                                },
                            }
                        }
                        if let Some(message) = live_message {
                            div { class: "modal-error", "{message}" }
                        } else if !confirmation.read().is_empty() && !matches {
                            div { class: "modal-error", "The PINs do not match." }
                        }
                    }
                    if let Some(message) = error.read().as_ref() {
                        div { class: "modal-error", "{message}" }
                    }
                }
                footer { class: "modal-footer",
                    button { class: "text-button", disabled: busy(), onclick: move |_| dialog.set(None), "Cancel" }
                    button {
                        class: "primary-button",
                        disabled: !can_submit,
                        onclick: {
                            let id = device.id.clone();
                            let serial = device.serial.clone().unwrap_or_default();
                            let agent = state.managed.clone();
                            let session = state.session.read().clone();
                            let sessions = state.session;
                            let auth_status = state.auth;
                            let service = state.credentials.clone();
                            let info = state.piv_info;
                            let slots = state.piv_slots;
                            let toast = state.toast;
                            let mut new_pin = new_pin;
                            let mut confirmation = confirmation;
                            let mut busy = busy;
                            let mut error = error;
                            move |_| {
                                if busy() {
                                    return;
                                }
                                let (Some(agent), Some(session)) = (agent.clone(), session.clone()) else {
                                    error.set_live(Some("Sign in first to use managed PIV.".into()));
                                    return;
                                };
                                let pin = if needs_pin {
                                    let bytes = new_pin.read().as_bytes().to_vec();
                                    new_pin.set(Zeroizing::new(String::new()));
                                    confirmation.set(Zeroizing::new(String::new()));
                                    match PivPin::new(bytes) {
                                        Ok(pin) => Some(pin),
                                        Err(value) => {
                                            error.set_live(Some(managed::error_message(&value)));
                                            return;
                                        }
                                    }
                                } else {
                                    None
                                };
                                busy.set_live(true);
                                error.set_live(None);
                                let id = id.clone();
                                let serial = serial.clone();
                                let service = service.clone();
                                let mut info = info;
                                let mut slots = slots;
                                let mut toast = toast;
                                let mut dialog = dialog;
                                let mut error = error;
                                let mut busy = busy;

                                std::thread::spawn(move || {
                                    let outcome = managed::fresh_token(&session, sessions, auth_status)
                                        .and_then(|token| {
                                            let result = match (action, pin) {
                                                (ManagedAction::Initialize, _) => agent.initialize(&id, &serial, &token),
                                                (ManagedAction::RotatePuk, _) => {
                                                    agent.rotate_secret(&id, &serial, sigil_connect::ManagedSecret::Puk, &token)
                                                }
                                                (ManagedAction::RotateManagementKey, _) => {
                                                    agent.rotate_secret(&id, &serial, sigil_connect::ManagedSecret::ManagementKey, &token)
                                                }
                                                (ManagedAction::UnblockPin, Some(pin)) => {
                                                    agent.unblock_pin(&id, &serial, &pin, &token)
                                                }
                                                (ManagedAction::UnblockPin, None) => Ok(()),
                                            };
                                            result.map_err(|value| managed::error_message(&value))
                                        });
                                    match outcome {
                                        Ok(()) => {
                                            managed::reload_piv(&service, &id, &mut info, &mut slots);
                                            toast.set_live(Some(success_message(action).into()));
                                            let pin_still_default = service
                                                .piv_info(&id)
                                                .ok()
                                                .and_then(|value| value.pin)
                                                .is_some_and(|status| status.default_value == Some(true));
                                            let next = (action == ManagedAction::Initialize && pin_still_default)
                                                .then_some(DialogKind::Piv(PivAction::ChangePin));
                                            dialog.set_live(next);
                                        }
                                        Err(message) => error.set_live(Some(message)),
                                    }
                                    busy.set_live(false);
                                });
                            }
                        },
                        if busy() { "Working." } else { "{label}" }
                    }
                }
            }
        }
    }
}

fn copy(action: ManagedAction) -> (&'static str, &'static str, &'static str) {
    match action {
        ManagedAction::Initialize => (
            "Set up managed PIV",
            "Sigil replaces the factory PUK and management key with random values that it keeps. Your PIN is unchanged.",
            "Set up",
        ),
        ManagedAction::RotatePuk => (
            "Rotate PUK",
            "Sigil replaces the PUK with a new random value that it keeps.",
            "Rotate PUK",
        ),
        ManagedAction::RotateManagementKey => (
            "Rotate management key",
            "Sigil replaces the management key with a new random AES-256 key that it keeps.",
            "Rotate management key",
        ),
        ManagedAction::UnblockPin => (
            "Unblock PIN",
            "Sigil uses its escrowed PUK to unblock the PIV PIN. Enter the new PIN.",
            "Unblock PIN",
        ),
    }
}

fn success_message(action: ManagedAction) -> &'static str {
    match action {
        ManagedAction::Initialize => "Managed PIV is set up.",
        ManagedAction::RotatePuk => "Rotated the managed PUK.",
        ManagedAction::RotateManagementKey => "Rotated the managed management key.",
        ManagedAction::UnblockPin => "Unblocked the PIV PIN.",
    }
}

/// Checks the PIV PIN/PUK rule: 6-8 ASCII characters, exactly 8 on FIPS keys.
pub(super) fn pin_length_check(value: &str, kind: &str, fips: bool) -> Result<(), String> {
    let characters = value.chars().count();
    if fips && characters != 8 {
        return Err(format!("This FIPS key requires an 8-character {kind}."));
    }
    if !(6..=8).contains(&characters) {
        return Err(format!("The {kind} must be 6-8 characters."));
    }
    if !value.is_ascii() {
        return Err(format!("The {kind} must use ASCII characters."));
    }
    Ok(())
}

pub(super) fn pin_length_ok(value: &str, fips: bool) -> bool {
    pin_length_check(value, "PIN", fips).is_ok()
}

pub(super) fn pin_length_hint(fips: bool) -> &'static str {
    if fips {
        "8 characters"
    } else {
        "6-8 characters"
    }
}

pub(super) fn pin_length_message(value: &str, fips: bool) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        pin_length_check(value, "PIN", fips).err()
    }
}

#[cfg(test)]
mod tests {
    use super::{pin_length_check, pin_length_hint, pin_length_message, pin_length_ok};

    #[test]
    fn fips_pins_are_exactly_eight_characters_and_others_six_to_eight() {
        assert!(pin_length_ok("12345678", true));
        assert!(!pin_length_ok("1234567", true));
        assert!(pin_length_ok("123456", false));
        assert!(pin_length_ok("12345678", false));
        assert!(!pin_length_ok("12345", false));
        assert!(!pin_length_ok("1234567é", false));
    }

    #[test]
    fn pin_length_hint_describes_the_rule() {
        assert_eq!(pin_length_hint(true), "8 characters");
        assert_eq!(pin_length_hint(false), "6-8 characters");
    }

    #[test]
    fn pin_length_message_explains_invalid_non_empty_pins() {
        assert_eq!(pin_length_message("", true), None);
        assert_eq!(pin_length_message("", false), None);
        assert_eq!(pin_length_message("12345678", true), None);
        assert_eq!(pin_length_message("123456", false), None);
        assert_eq!(
            pin_length_message("123456", true).as_deref(),
            Some("This FIPS key requires an 8-character PIN.")
        );
        assert_eq!(
            pin_length_message("12345", false).as_deref(),
            Some("The PIN must be 6-8 characters.")
        );
        assert_eq!(
            pin_length_message("1234567é", false).as_deref(),
            Some("The PIN must use ASCII characters.")
        );
    }

    #[test]
    fn pin_length_check_names_the_code_kind() {
        assert_eq!(pin_length_check("12345678", "PUK", true), Ok(()));
        assert_eq!(
            pin_length_check("123456", "PUK", true),
            Err("This FIPS key requires an 8-character PUK.".to_owned())
        );
        assert_eq!(
            pin_length_check("123456789", "PUK", false),
            Err("The PUK must be 6-8 characters.".to_owned())
        );
        assert_eq!(
            pin_length_check("12345é", "PUK", false),
            Err("The PUK must use ASCII characters.".to_owned())
        );
    }
}
