pub mod nav;
pub mod right_panel;

use dioxus::prelude::*;
use sigil_connect::ConnectionMode;

use crate::{
    dialogs::DialogHost,
    icons::Icon,
    pages::{
        accounts::AccountsPage, certificates::CertificatesPage, home::HomePage,
        passkeys::PasskeysPage, settings::SettingsPage, slots::SlotsPage,
    },
    state::{AppState, Page},
};

#[component]
pub fn AppShell() -> Element {
    let state = use_context::<AppState>();
    let page = *state.page.read();
    let device = state.current_device();
    let device_key = device
        .as_ref()
        .map(|value| value.id.0.clone())
        .unwrap_or_else(|| "none".into());
    let mut panel_collapsed_signal = state.panel_collapsed;
    let mut panel_open_signal = state.panel_open;
    let status_signal = state.status;
    let toast_signal = state.toast;
    let mode = match &state.mode {
        ConnectionMode::Agent { .. } => "Agent",
        ConnectionMode::Direct { elevated: true } => "Direct · Administrator",
        ConnectionMode::Direct { elevated: false } => "Direct",
    };
    let panel_collapsed = *state.panel_collapsed.read();
    let nav_collapsed = *state.nav_collapsed.read();
    let shell_class = format!(
        "app-shell{}{}",
        if nav_collapsed {
            " nav-collapsed-shell"
        } else {
            ""
        },
        if panel_collapsed { " panel-hidden" } else { "" }
    );
    let content = match page {
        Page::Home => rsx! { HomePage {} },
        Page::Accounts => rsx! { AccountsPage {} },
        Page::Passkeys => rsx! { PasskeysPage { key: "{device_key}", device: device.clone() } },
        Page::Certificates => {
            rsx! { CertificatesPage { key: "{device_key}", device: device.clone() } }
        }
        Page::Slots => rsx! { SlotsPage {} },
        Page::Settings => rsx! { SettingsPage {} },
    };

    rsx! {
        style { {crate::theme::stylesheet()} }
        div { class: "{shell_class}",
            nav::LeftNav {}
            section { class: "center-pane",
                header { class: "center-header",
                    div { class: "page-heading",
                        h1 { "{page.title()}" }
                    }
                    div { class: "header-actions",
                        span { class: "header-application-chip", "{page.application_chip()}" }
                        span { class: "mode-badge", "{mode}" }
                        button {
                            class: "icon-button panel-toggle",
                            title: "Toggle actions panel",
                            aria_expanded: (!panel_collapsed).to_string(),
                            onclick: move |_| {
                                panel_collapsed_signal.set(!panel_collapsed_signal());
                                panel_open_signal.set(!panel_open_signal());
                            },
                            Icon { name: "panel", size: 18 }
                        }
                    }
                }
                if let Some(message) = status_signal.read().as_ref() {
                    div { class: "global-status", "{message}" }
                }
                div { class: "page-container", {content} }
            }
            right_panel::RightPanel {}
            if let Some(message) = toast_signal.read().as_ref() {
                div { class: "toast", role: "status", "{message}" }
            }
            DialogHost {}
        }
    }
}
