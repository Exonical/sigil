use dioxus::prelude::*;
use sigil_connect::ConnectionMode;

use crate::state::AppState;

#[component]
pub fn SettingsPage() -> Element {
    let state = use_context::<AppState>();
    let version = env!("CARGO_PKG_VERSION");
    let (mode, log_location) = match &state.mode {
        ConnectionMode::Agent { endpoint } => (
            format!("Agent · {endpoint}"),
            r"C:\ProgramData\Sigil\logs\agent.log".to_owned(),
        ),
        ConnectionMode::Direct { elevated: true } => (
            "Direct · Administrator".into(),
            "stderr (not persisted)".into(),
        ),
        ConnectionMode::Direct { elevated: false } => {
            ("Direct".into(), "stderr (not persisted)".into())
        }
    };

    rsx! {
        div { class: "settings-page page-scroll",
            section { class: "settings-card",
                p { class: "eyebrow", "ABOUT" }
                h2 { "Sigil" }
                p { class: "muted", "Version {version}" }
            }
            section { class: "settings-card",
                p { class: "eyebrow", "CONNECTION" }
                h2 { "{mode}" }
                p { class: "muted", "The GUI prefers a trusted agent and uses direct mode when policy permits." }
            }
            section { class: "settings-card",
                p { class: "eyebrow", "LOG LOCATION" }
                h2 { "{log_location}" }
                p { class: "muted", "Direct mode writes diagnostic tracing to stderr only." }
            }
        }
    }
}
