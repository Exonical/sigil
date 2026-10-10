use crate::state::SetLive;
use dioxus::prelude::*;
use sigil_core::{DeviceInfo, KeyStatus, PivSlot, PivSlotInfo};

use crate::{
    icons::Icon,
    managed,
    state::{AppState, DialogKind, ManagedAction, PivAction},
};

#[component]
pub fn CertificatesPage(device: Option<DeviceInfo>) -> Element {
    let state = use_context::<AppState>();
    let Some(device) = device else {
        return rsx! {
            div { class: "empty-state",
                div { class: "empty-icon", Icon { name: "certificate", size: 28 } }
                h2 { "Connect a YubiKey" }
                p { "PIV certificates and keys will appear here." }
            }
        };
    };
    let id = device.id.clone();
    let service = state.credentials.clone();
    let info_signal = state.piv_info;
    let slots_signal = state.piv_slots;
    let mut selected_slot_signal = state.selected_slot;
    let status = state.status;
    let mut fips_banner_dismissed = state.fips_banner_dismissed;
    let mut dialog_signal = state.dialog;
    let load_id = id.clone();
    use_hook(move || {
        if selected_slot_signal.read().is_none() {
            selected_slot_signal.set(Some(PivSlot::AUTHENTICATION));
        }
        let service = service.clone();
        let mut info_signal = info_signal;
        let mut slots_signal = slots_signal;
        let mut status = status;
        let id = load_id.clone();
        std::thread::spawn(move || {
            let result = service
                .piv_info(&id)
                .and_then(|info| service.piv_slots(&id).map(|slots| (info, slots)));
            match result {
                Ok((info, slots)) => {
                    info_signal.set_live(Some((id.clone(), info)));
                    slots_signal.set_live(Some((id.clone(), slots)));
                    status.set_live(None);
                }
                Err(error) => status.set_live(Some(error.to_string())),
            }
        });
    });

    let current_info = state
        .piv_info
        .read()
        .as_ref()
        .filter(|(device_id, _)| device_id == &device.id)
        .map(|(_, info)| info.clone());
    let current_slots = state
        .piv_slots
        .read()
        .as_ref()
        .filter(|(device_id, _)| device_id == &device.id)
        .map(|(_, slots)| slots.clone())
        .unwrap_or_default();
    let selected_slot = state
        .selected_slot
        .read()
        .unwrap_or(PivSlot::AUTHENTICATION);
    let slots = visible_slots(&current_slots);
    let fips_defaults = device.fips == Some(true)
        && current_info.as_ref().is_some_and(|info| {
            info.pin
                .as_ref()
                .is_some_and(|status| status.default_value == Some(true))
                || info
                    .puk
                    .as_ref()
                    .is_some_and(|status| status.default_value == Some(true))
                || info
                    .management_key
                    .as_ref()
                    .is_some_and(|status| status.default_value == Some(true))
        });

    let managed_ready = managed::ready(&state);
    let secrets_default = current_info.as_ref().is_some_and(|info| {
        info.puk
            .as_ref()
            .is_some_and(|status| status.default_value == Some(true))
            || info
                .management_key
                .as_ref()
                .is_some_and(|status| status.default_value == Some(true))
    });
    let (banner_label, banner_action) = match (managed_ready, secrets_default) {
        (false, _) => ("Set up FIPS", DialogKind::SetupFips),
        (true, true) => (
            "Set up managed PIV",
            DialogKind::Managed(ManagedAction::Initialize),
        ),
        (true, false) => ("Change PIN", DialogKind::Piv(PivAction::ChangePin)),
    };

    rsx! {
        div { class: "certificates-page page-scroll",
            if fips_defaults && !*state.fips_banner_dismissed.read() {
                div { class: "fips-banner",
                    Icon { name: "shield", size: 19 }
                    div {
                        strong { "For FIPS compliance it is required to change the default PIN, PUK and management key." }
                    }
                    button { class: "text-button", onclick: move |_| fips_banner_dismissed.set(true), "Dismiss" }
                    button { class: "primary-button", onclick: move |_| dialog_signal.set(Some(banner_action)), "{banner_label}" }
                }
            }
            if let Some(message) = status.read().as_ref() {
                div { class: "error-card",
                    strong { "PIV inspection failed" }
                    p { class: "error-text", "{message}" }
                }
            } else if current_info.is_none() {
                div { class: "loading-card",
                    div { class: "spinner" }
                    span { "Reading PIV certificates…" }
                }
            } else {
                div { class: "section-heading cert-heading",
                    div {
                        p { class: "eyebrow", "PIV APPLICATION" }
                        h2 { "Certificates" }
                    }
                    div { class: "cert-heading-actions",
                        if managed_ready {
                            button { class: "primary-button", onclick: move |_| dialog_signal.set(Some(DialogKind::Enroll(None))), "Enroll certificate" }
                        }
                        span { class: "muted small", "Select a slot to view details" }
                    }
                }
                div { class: "slot-list scroll-list",
                    for slot_info in slots.iter() {
                        SlotRow {
                            key: "{slot_info.slot}",
                            slot_info: slot_info.clone(),
                            selected: slot_info.slot == selected_slot,
                            onclick: {
                                let mut selected = state.selected_slot;
                                let slot = slot_info.slot;
                                move |_| selected.set(Some(slot))
                            }
                        }
                    }
                }
                if device.simulated {
                    p { class: "muted small", "Simulated fixture data. These operations do not modify a physical key." }
                }
            }
        }
    }
}

#[component]
fn SlotRow(slot_info: PivSlotInfo, selected: bool, onclick: EventHandler<MouseEvent>) -> Element {
    let subject = slot_info
        .certificate
        .as_ref()
        .map(|certificate| certificate.subject.as_str())
        .unwrap_or("No certificate loaded");
    let present = matches!(slot_info.key, KeyStatus::Present(_));
    rsx! {
        button {
            class: if selected { "slot-row selected" } else { "slot-row" },
            onclick,
            div { class: "slot-badge", "{slot_info.slot}" }
            div { class: "slot-row-copy",
                strong { "{slot_info.slot.name()}" }
                span { class: if slot_info.certificate.is_some() { "slot-subject" } else { "muted slot-subject" }, "{subject}" }
            }
            if present { span { class: "slot-key-state", Icon { name: "key", size: 16 } "Key present" }
            } else { span { class: "slot-key-state muted", "Empty" } }
            Icon { name: "chevron-right", size: 17 }
        }
    }
}

fn visible_slots(slots: &[PivSlotInfo]) -> Vec<PivSlotInfo> {
    let mut visible = PivSlot::STANDARD
        .iter()
        .map(|slot| {
            slots
                .iter()
                .find(|item| item.slot == *slot)
                .cloned()
                .unwrap_or(PivSlotInfo {
                    slot: *slot,
                    certificate: None,
                    key: KeyStatus::Absent,
                })
        })
        .collect::<Vec<_>>();
    visible.extend(
        slots
            .iter()
            .filter(|item| {
                !PivSlot::STANDARD.contains(&item.slot)
                    && (item.certificate.is_some() || matches!(item.key, KeyStatus::Present(_)))
            })
            .cloned(),
    );
    visible
}
