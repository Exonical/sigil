use dioxus::prelude::*;
use sigil_core::DeviceId;

use crate::{
    icons::Icon,
    pages::home::firmware,
    state::{AppState, Page},
};

#[component]
pub fn LeftNav() -> Element {
    let state = use_context::<AppState>();
    let devices = state.devices.read().clone();
    let selected = state
        .selected_device
        .read()
        .clone()
        .filter(|id| devices.iter().any(|device| &device.id == id))
        .or_else(|| devices.first().map(|device| device.id.clone()));
    let current = devices
        .iter()
        .find(|device| Some(&device.id) == selected.as_ref())
        .cloned();
    let collapsed = *state.nav_collapsed.read();
    let mut nav_collapsed = state.nav_collapsed;
    let mut selected_device = state.selected_device;
    let mut selected_slot = state.selected_slot;
    let mut dialog = state.dialog;

    rsx! {
        nav { class: if collapsed { "left-pane nav-collapsed" } else { "left-pane" },
            div { class: "nav-top",
                button {
                    class: "icon-button nav-toggle",
                    title: if collapsed { "Expand navigation" } else { "Collapse navigation" },
                    onclick: move |_| nav_collapsed.set(!nav_collapsed()),
                    Icon { name: "menu", size: 19 }
                }
                if !collapsed {
                    span { class: "brand-name", "Sigil" }
                }
            }
            div { class: if collapsed { "device-pill device-pill-collapsed" } else { "device-pill" },
                div { class: "device-pill-icon", Icon { name: "key", size: 18 } }
                if !collapsed {
                    div { class: "device-pill-content",
                        if let Some(device) = current.as_ref() {
                            strong { "{device.model}" }
                            small { "S/N: {device.serial.as_deref().unwrap_or(\"unavailable\")}" }
                            small { "F/W: {firmware(device)}" }
                        } else {
                            strong { "No key connected" }
                            small { "Connect a YubiKey" }
                        }
                    }
                    if devices.len() > 1 {
                        select {
                            class: "device-switcher",
                            aria_label: "Switch security key",
                            value: selected.as_ref().map(|id| id.0.clone()).unwrap_or_default(),
                            onchange: move |event| {
                                let id = DeviceId(event.value());
                                selected_device.set(Some(id));
                                selected_slot.set(None);
                                dialog.set(None);
                            },
                            for device in devices.iter() {
                                option { value: "{device.id.0}", "{device.model}" }
                            }
                        }
                    }
                }
            }
            div { class: "nav-links",
                NavItem { page: Page::Home, icon: "home" }
                NavItem { page: Page::Accounts, icon: "users" }
                NavItem { page: Page::Passkeys, icon: "key" }
                NavItem { page: Page::Certificates, icon: "certificate" }
                NavItem { page: Page::Slots, icon: "grid" }
            }
            div { class: "nav-bottom",
                crate::auth::AuthArea {}
                NavItem { page: Page::Settings, icon: "settings" }
            }
        }
    }
}

#[component]
fn NavItem(page: Page, icon: &'static str) -> Element {
    let state = use_context::<AppState>();
    let active = *state.page.read() == page;
    let mut selected_page = state.page;
    let mut panel_open = state.panel_open;
    rsx! {
        button {
            class: if active { "nav-item active" } else { "nav-item" },
            title: page.title(),
            aria_current: if active { "page" } else { "false" },
            onclick: move |_| {
                selected_page.set(page);
                panel_open.set(false);
            },
            Icon { name: icon, size: 19 }
            span { class: "nav-label", "{page.title()}" }
        }
    }
}
