use dioxus::prelude::*;
use sigil_core::{KeyStatus, PivSlot, PivSlotInfo};

use crate::{
    icons::Icon,
    managed,
    state::{AppState, DialogKind, ManagedAction, Page, PivAction},
};

#[component]
pub fn RightPanel() -> Element {
    let state = use_context::<AppState>();
    let page = *state.page.read();
    let device = state.current_device();
    let hidden = *state.panel_collapsed.read();
    let open = *state.panel_open.read();
    let mut panel_open = state.panel_open;
    let mut panel_collapsed = state.panel_collapsed;
    let class = if open {
        "right-pane drawer drawer-open"
    } else {
        "right-pane drawer"
    };
    let panel_class = if hidden {
        format!("{class} panel-collapsed")
    } else {
        class.into()
    };

    rsx! {
        if !hidden || open {
            if open {
                button {
                    class: "drawer-scrim",
                    aria_label: "Close details panel",
                    onclick: move |_| panel_open.set(false),
                }
            }
            aside { class: "{panel_class}",
                div { class: "right-panel-titlebar",
                    h2 { "Actions" }
                    button {
                        class: "icon-button",
                        title: "Collapse actions",
                        onclick: move |_| {
                            if open {
                                panel_open.set(false);
                            } else {
                                panel_collapsed.set(true);
                            }
                        },
                        Icon { name: "chevron-right", size: 17 }
                    }
                }
                div { class: "right-panel-content panel-scroll",
                    if let Some(device) = device {
                        {match page {
                            Page::Home => home_panel(&state),
                            Page::Accounts => coming_soon_panel("OATH accounts", "OATH"),
                            Page::Passkeys => passkeys_panel(&state),
                            Page::Certificates => certificate_panel(&state, &device),
                            Page::Slots => coming_soon_panel("OTP slot configuration", "YUBICO OTP"),
                            Page::Settings => settings_panel(&device),
                        }}
                    } else {
                        div { class: "panel-empty muted", "Connect a YubiKey to see device actions." }
                    }
                }
            }
        }
    }
}

fn home_panel(state: &AppState) -> Element {
    rsx! {
        PanelSection { title: "DEVICE",
            ActionRow {
                icon: "grid",
                title: "Toggle applications",
                subtitle: "Choose which YubiKey applications are enabled".to_owned(),
                warning: false,
                disabled: false,
                onclick: {
                    let mut dialog = state.dialog;
                    move |_| dialog.set(Some(DialogKind::ToggleApplications))
                }
            }
            ActionRow {
                icon: "rotate",
                title: "Factory reset",
                subtitle: "Reset the PIV application and its keys".to_owned(),
                warning: true,
                disabled: false,
                onclick: {
                    let mut dialog = state.dialog;
                    move |_| dialog.set(Some(DialogKind::FactoryReset))
                }
            }
        }
    }
}

fn passkeys_panel(state: &AppState) -> Element {
    let device = state.current_device();
    let fido = device.as_ref().and_then(|device| {
        state
            .fido_status
            .read()
            .as_ref()
            .filter(|(id, _)| id == &device.id)
            .map(|(_, status)| status.clone())
    });
    rsx! {
        PanelSection { title: "MANAGE",
            if fido.as_ref().is_some_and(|status| status.pin_set == Some(false)) {
                ActionRow {
                    icon: "key",
                    title: "Set PIN",
                    subtitle: "Coming soon".to_owned(),
                    warning: false,
                    disabled: true,
                    onclick: move |_| {}
                }
            } else {
                ActionRow {
                    icon: "key",
                    title: "Unlock passkeys",
                    subtitle: "Enter the FIDO2 PIN in the Passkeys page".to_owned(),
                    warning: false,
                    disabled: !fido.as_ref().is_some_and(|status| status.credential_management),
                    onclick: {
                        let mut page = state.page;
                        move |_| page.set(Page::Passkeys)
                    }
                }
            }
        }
        PanelSection { title: "DETAILS",
            if let Some(status) = fido {
                p { class: "panel-detail", "CTAP: {status.versions.join(\", \")}" }
                p { class: "panel-detail muted", "Fingerprint enrollment: {status.fingerprint_enrollment}" }
            } else {
                p { class: "panel-detail muted", "FIDO2 status has not been inspected yet." }
            }
        }
    }
}

fn certificate_panel(state: &AppState, device: &sigil_core::DeviceInfo) -> Element {
    let info = state
        .piv_info
        .read()
        .as_ref()
        .filter(|(id, _)| id == &device.id)
        .map(|(_, info)| info.clone());
    let slots = state
        .piv_slots
        .read()
        .as_ref()
        .filter(|(id, _)| id == &device.id)
        .map(|(_, slots)| slots.clone())
        .unwrap_or_default();
    let selected = state
        .selected_slot
        .read()
        .unwrap_or(PivSlot::AUTHENTICATION);
    let selected_slot = slots.iter().find(|slot| slot.slot == selected).cloned();
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
    let mgmt_default = info
        .as_ref()
        .and_then(|info| info.management_key.as_ref())
        .and_then(|status| status.default_value)
        == Some(true);
    let pin_subtitle = info
        .as_ref()
        .and_then(|info| info.pin.as_ref())
        .map(|status| {
            if status.default_value == Some(true) {
                format!(
                    "Warning: Default PIN used · {} attempts remaining",
                    status.remaining
                )
            } else {
                format!("{} attempts remaining", status.remaining)
            }
        })
        .unwrap_or_else(|| "PIV PIN".into());
    let puk_subtitle = info
        .as_ref()
        .and_then(|info| info.puk.as_ref())
        .map(|status| {
            if status.default_value == Some(true) {
                format!(
                    "Warning: Default PUK used · {} attempts remaining",
                    status.remaining
                )
            } else {
                format!("{} attempts remaining", status.remaining)
            }
        })
        .unwrap_or_else(|| "PIV PUK".into());
    let fips_defaults = device.fips == Some(true) && (pin_default || puk_default || mgmt_default);
    let managed_mode = managed::ready(state);

    rsx! {
        PanelSection { title: "MANAGE",
            ActionRow {
                icon: "key",
                title: "Change PIN",
                subtitle: pin_subtitle,
                warning: pin_default,
                disabled: false,
                onclick: {
                    let mut dialog = state.dialog;
                    move |_| dialog.set(Some(DialogKind::Piv(PivAction::ChangePin)))
                }
            }
            if !managed_mode {
            ActionRow {
                icon: "key",
                title: "Change PUK",
                subtitle: puk_subtitle,
                warning: puk_default,
                disabled: false,
                onclick: {
                    let mut dialog = state.dialog;
                    move |_| dialog.set(Some(DialogKind::Piv(PivAction::ChangePuk)))
                }
            }
            }
            if managed_mode {
                ActionRow {
                    icon: "unlock",
                    title: "Unblock PIN",
                    subtitle: "Sigil unblocks the PIN with its escrowed PUK".to_owned(),
                    warning: false,
                    disabled: false,
                    onclick: {
                        let mut dialog = state.dialog;
                        move |_| dialog.set(Some(DialogKind::Managed(ManagedAction::UnblockPin)))
                    }
                }
            }
            if !managed_mode && info.as_ref().and_then(|info| info.pin.as_ref()).is_some_and(|status| status.remaining == 0) {
                ActionRow {
                icon: "unlock",
                title: "Unblock PIN",
                subtitle: "Use the PUK to set a new PIN".to_owned(),
                    warning: true,
                    disabled: false,
                    onclick: {
                        let mut dialog = state.dialog;
                        move |_| dialog.set(Some(DialogKind::Piv(PivAction::UnblockPin)))
                    }
                }
            }
            if !managed_mode {
            ActionRow {
                icon: "lock",
                title: "Management key",
                subtitle: if mgmt_default {
                "Warning: Default key used".to_owned()
            } else {
                "Change management key".to_owned()
                },
                warning: mgmt_default,
                disabled: false,
                onclick: {
                    let mut dialog = state.dialog;
                    move |_| dialog.set(Some(DialogKind::Piv(PivAction::ChangeManagementKey)))
                }
            }
            }
        }
        if managed_mode {
            PanelSection { title: "MANAGED BY SIGIL",
                if puk_default && mgmt_default {
                    ActionRow {
                        icon: "shield",
                        title: "Set up managed PIV",
                        subtitle: "Replace the factory PUK and management key with Sigil-held secrets".to_owned(),
                        warning: true,
                        disabled: false,
                        onclick: {
                            let mut dialog = state.dialog;
                            move |_| dialog.set(Some(DialogKind::Managed(ManagedAction::Initialize)))
                        }
                    }
                } else {
                    ActionRow {
                        icon: "rotate",
                        title: "Rotate PUK",
                        subtitle: "Replace the PUK with a new Sigil-held value".to_owned(),
                        warning: false,
                        disabled: false,
                        onclick: {
                            let mut dialog = state.dialog;
                            move |_| dialog.set(Some(DialogKind::Managed(ManagedAction::RotatePuk)))
                        }
                    }
                    ActionRow {
                        icon: "rotate",
                        title: "Rotate management key",
                        subtitle: "Replace the management key with a new Sigil-held AES-256 key".to_owned(),
                        warning: false,
                        disabled: false,
                        onclick: {
                            let mut dialog = state.dialog;
                            move |_| dialog.set(Some(DialogKind::Managed(ManagedAction::RotateManagementKey)))
                        }
                    }
                }
            }
        }
        if fips_defaults && !managed_mode {
            PanelSection { title: "SETUP",
                ActionRow {
                    icon: "shield",
                    title: "Set up FIPS",
                    subtitle: "Change the default PIN, PUK and management key".to_owned(),
                    warning: true,
                    disabled: false,
                    onclick: {
                        let mut dialog = state.dialog;
                        move |_| dialog.set(Some(DialogKind::SetupFips))
                    }
                }
            }
        }

        if let Some(slot) = selected_slot {
            {selected_slot_panel(state, slot)}
        } else {
            PanelSection { title: "DETAILS",
                p { class: "panel-detail muted", "Select a PIV slot to inspect its certificate and key." }
            }
        }
    }
}

fn selected_slot_panel(state: &AppState, slot: PivSlotInfo) -> Element {
    let certificate = slot.certificate.as_ref();
    let metadata = match &slot.key {
        KeyStatus::Present(metadata) => Some(metadata),
        _ => None,
    };
    let slot_id = slot.slot;
    rsx! {
        PanelSection { title: "DETAILS",
            if let Some(certificate) = certificate {
                DetailValue { label: "SUBJECT", value: certificate.subject.clone() }
                DetailValue { label: "ISSUER", value: certificate.issuer.clone() }
                DetailValue { label: "VALID", value: format!("{} – {}", certificate.not_before, certificate.not_after) }
                DetailValue { label: "FINGERPRINT", value: certificate.sha256_fingerprint.clone() }
            } else if metadata.is_some() {
                span { class: "slot-key-state warn", "Key without certificate loaded" }
            } else {
                p { class: "panel-detail muted", "No certificate loaded" }
            }
            if let Some(metadata) = metadata {
                DetailValue { label: "KEY", value: metadata.algorithm.to_string() }
                DetailValue { label: "POLICY", value: format!("PIN {:?} · Touch {:?}", metadata.pin_policy, metadata.touch_policy) }
                if let Some(origin) = metadata.origin {
                    DetailValue { label: "ORIGIN", value: format!("{origin:?}") }
                }
            }
            if let Some(profile) = (managed::ready(state) && certificate.is_none() && metadata.is_some())
                .then(|| managed::enroll_shortcut(state, slot_id))
                .flatten()
            {
                ActionRow {
                    icon: "plus",
                    title: "Enroll",
                    subtitle: format!("Enroll {}", profile.display_name),
                    warning: false,
                    disabled: false,
                    onclick: {
                        let mut dialog = state.dialog;
                        move |_| dialog.set(Some(DialogKind::Enroll(Some(slot_id))))
                    }
                }
            }
            ActionRow {
                icon: "plus",
                title: "Generate key",
                subtitle: "Create a key on the YubiKey".to_owned(),
                warning: false,
                disabled: slot_id == PivSlot::ATTESTATION,
                onclick: {
                    let mut dialog = state.dialog;
                    move |_| dialog.set(Some(DialogKind::Piv(PivAction::GenerateKey(slot_id))))
                }
            }
            ActionRow {
                icon: "upload",
                title: "Import certificate",
                subtitle: "Load a certificate file".to_owned(),
                warning: false,
                disabled: slot_id == PivSlot::ATTESTATION,
                onclick: {
                    let mut dialog = state.dialog;
                    move |_| dialog.set(Some(DialogKind::Piv(PivAction::ImportCertificate(slot_id))))
                }
            }
            if certificate.is_some() {
                ActionRow {
                    icon: "download",
                    title: "Export certificate",
                    subtitle: "Save PEM or DER".to_owned(),
                    warning: false,
                    disabled: false,
                    onclick: {
                        let mut dialog = state.dialog;
                        move |_| dialog.set(Some(DialogKind::Piv(PivAction::ExportCertificate(slot_id))))
                    }
                }
                ActionRow {
                    icon: "trash",
                    title: "Delete certificate",
                    subtitle: "Remove the certificate from this slot".to_owned(),
                    warning: true,
                    disabled: slot_id == PivSlot::ATTESTATION,
                    onclick: {
                        let mut dialog = state.dialog;
                        move |_| dialog.set(Some(DialogKind::Piv(PivAction::DeleteCertificate(slot_id))))
                    }
                }
            }
            if metadata.is_some() && slot_id != PivSlot::ATTESTATION {
                ActionRow {
                    icon: "certificate",
                    title: "Create CSR",
                    subtitle: "Sign a certificate request".to_owned(),
                    warning: false,
                    disabled: false,
                    onclick: {
                        let mut dialog = state.dialog;
                        move |_| dialog.set(Some(DialogKind::Piv(PivAction::CreateCsr(slot_id))))
                    }
                }
                ActionRow {
                    icon: "shield",
                    title: "Attest key",
                    subtitle: "Export PIV attestation".to_owned(),
                    warning: false,
                    disabled: false,
                    onclick: {
                        let mut dialog = state.dialog;
                        move |_| dialog.set(Some(DialogKind::Piv(PivAction::Attest(slot_id))))
                    }
                }
                ActionRow {
                    icon: "trash",
                    title: "Delete key",
                    subtitle: "Permanently remove the private key".to_owned(),
                    warning: true,
                    disabled: false,
                    onclick: {
                        let mut dialog = state.dialog;
                        move |_| dialog.set(Some(DialogKind::Piv(PivAction::DeleteKey(slot_id))))
                    }
                }
            }
        }
    }
}

fn settings_panel(device: &sigil_core::DeviceInfo) -> Element {
    rsx! {
        PanelSection { title: "DEVICE",
            DetailValue { label: "SERIAL", value: device.serial.clone().unwrap_or_else(|| "Unavailable".into()) }
            DetailValue { label: "FIRMWARE", value: crate::pages::home::firmware(device) }
            DetailValue { label: "MODEL", value: device.model.clone() }
        }
    }
}

fn coming_soon_panel(title: &str, section: &str) -> Element {
    rsx! {
        PanelSection { title: "DETAILS",
            p { class: "panel-detail muted", "{title} are coming in a later release." }
            p { class: "eyebrow", "{section}" }
        }
    }
}

#[component]
fn PanelSection(title: &'static str, children: Element) -> Element {
    rsx! {
        section { class: "panel-section",
            h3 { class: "eyebrow", "{title}" }
            {children}
        }
    }
}

#[component]
fn ActionRow(
    icon: &'static str,
    title: &'static str,
    subtitle: String,
    warning: bool,
    disabled: bool,
    onclick: EventHandler<MouseEvent>,
) -> Element {
    rsx! {
        button {
            class: if disabled { "action-row disabled" } else { "action-row" },
            disabled,
            onclick,
            Icon { name: icon, size: 18 }
            span { class: "action-copy",
                strong { "{title}" }
                small { "{subtitle}" }
            }
            if warning { Icon { name: "warning", size: 16 } }
        }
    }
}

#[component]
fn DetailValue(label: &'static str, value: String) -> Element {
    rsx! {
        div { class: "detail-value",
            span { class: "eyebrow", "{label}" }
            p { "{value}" }
        }
    }
}
