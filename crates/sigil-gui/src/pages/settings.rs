use dioxus::prelude::*;
use sigil_connect::ConnectionMode;

use crate::state::AppState;

#[component]
pub fn SettingsPage() -> Element {
    let state = use_context::<AppState>();
    let version = env!("CARGO_PKG_VERSION");
    let mode = match &state.mode {
        ConnectionMode::Agent { endpoint } => format!("Agent · {endpoint}"),
        ConnectionMode::Direct { elevated: true } => "Direct · Administrator".into(),
        ConnectionMode::Direct { elevated: false } => "Direct".into(),
    };
    let log_location = log_location(&state.mode, state.agent_log_location.as_deref());

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

/// The agent's log location comes from the agent itself, because its data directory is configurable.
fn log_location(mode: &ConnectionMode, agent_log_location: Option<&str>) -> String {
    match mode {
        ConnectionMode::Agent { .. } => agent_log_location
            .unwrap_or("Not reported by the agent")
            .to_owned(),
        ConnectionMode::Direct { .. } => "stderr (not persisted)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> ConnectionMode {
        ConnectionMode::Agent {
            endpoint: "/run/sigil/agent.sock".into(),
        }
    }

    #[test]
    fn agent_mode_shows_the_location_the_agent_reported() {
        assert_eq!(
            log_location(&agent(), Some("/var/lib/sigil/logs/agent.log")),
            "/var/lib/sigil/logs/agent.log"
        );
    }

    #[test]
    fn agent_mode_without_a_reported_location_does_not_guess_a_path() {
        assert_eq!(log_location(&agent(), None), "Not reported by the agent");
    }

    #[test]
    fn direct_mode_logs_to_stderr() {
        for elevated in [false, true] {
            assert_eq!(
                log_location(&ConnectionMode::Direct { elevated }, Some("ignored")),
                "stderr (not persisted)"
            );
        }
    }
}
