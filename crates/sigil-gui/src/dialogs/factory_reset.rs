use crate::state::SetLive;
use dioxus::prelude::*;
use sigil_core::{DeviceId, DeviceInfo};

use crate::{icons::Icon, state::AppState};

#[component]
pub fn FactoryResetDialog(device: DeviceInfo) -> Element {
    let state = use_context::<AppState>();
    let mut dialog_signal = state.dialog;
    let service = state.credentials.clone();
    let toast = state.toast;
    let mut piv_info = state.piv_info;
    let mut piv_slots = state.piv_slots;
    let serial = device.serial.clone().unwrap_or_default();
    let mut confirmation = use_signal(String::new);
    let error = use_signal_sync(|| None::<String>);
    let busy = use_signal_sync(|| false);
    let valid = !serial.is_empty() && confirmation.read().trim() == serial;

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
                        p { class: "eyebrow", "DESTRUCTIVE ACTION" }
                        h2 { "Factory reset" }
                        p { class: "modal-description", "Reset the PIV application on serial {serial}. This erases PIV keys, certificates, PIN and PUK state." }
                    }
                    button { class: "icon-button", title: "Close dialog", onclick: move |_| dialog_signal.set(None), Icon { name: "x", size: 17 } }
                }
                div { class: "modal-content",
                    div { class: "warning-callout danger-callout",
                        Icon { name: "warning", size: 17 }
                        span { "Only PIV can be reset here. FIDO, OATH and OTP reset support is coming later." }
                    }
                    div { class: "modal-field",
                        label { r#for: "reset-serial", "Type the device serial to confirm" }
                        input {
                            id: "reset-serial",
                            r#type: "text",
                            autocomplete: "off",
                            placeholder: "{serial}",
                            value: "{confirmation}",
                            oninput: move |event| confirmation.set(event.value()),
                        }
                    }
                    if let Some(message) = error.read().as_ref() {
                        div { class: "modal-error", "{message}" }
                    }
                }
                footer { class: "modal-footer",
                    button { class: "text-button", disabled: busy(), onclick: move |_| dialog_signal.set(None), "Cancel" }
                    button {
                        class: "danger-button",
                        disabled: !valid || busy(),
                        onclick: {
                            let service = service.clone();
                            let id = device.id.clone();
                            let expected_serial = serial.clone();
                            let mut busy = busy;
                            let mut error = error;
                            let mut dialog = dialog_signal;
                            let mut toast = toast;
                            move |_| {
                                if busy() || confirmation.read().trim() != expected_serial {
                                    return;
                                }
                                busy.set_live(true);
                                error.set_live(None);
                                let service = service.clone();
                                let id: DeviceId = id.clone();
                                let serial = expected_serial.clone();
                                std::thread::spawn(move || {
                                    match service.reset(&id, &serial) {
                                        Ok(()) => {
                                            if let Ok(info) = service.piv_info(&id) {
                                                piv_info.set_live(Some((id.clone(), info)));
                                            }
                                            if let Ok(slots) = service.piv_slots(&id) {
                                                piv_slots.set_live(Some((id.clone(), slots)));
                                            }
                                            toast.set_live(Some("PIV factory reset completed.".into()));
                                            dialog.set_live(None);
                                        }
                                        Err(value) => error.set_live(Some(value.to_string())),
                                    }
                                    busy.set_live(false);
                                });
                            }
                        },
                        if busy() { "Resetting…" } else { "Reset PIV" }
                    }
                }
            }
        }
    }
}
