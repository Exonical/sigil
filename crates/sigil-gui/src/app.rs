use std::thread;

use dioxus::prelude::*;
use sigil_connect::{ConnectOptions, ConnectedService};
use sigil_core::{
    DeviceId, DeviceInfo, DiscoverableCredential, FidoStatus, Fingerprint, PivInfo, PivSlot,
    PivSlotInfo,
};

use crate::{
    layout::AppShell,
    state::{AppState, DialogKind, Page},
};

pub fn app() -> Element {
    let connected = use_hook(|| {
        sigil_connect::connect(connection_options()).map_err(|error| {
            let agent_required = matches!(
                &error,
                sigil_connect::ConnectError::AgentRequired
                    | sigil_connect::ConnectError::DirectModeDisabled
            );
            (error.to_string(), agent_required)
        })
    });
    use_context_provider(|| connected.as_ref().ok().cloned());
    match connected {
        Ok(_) => rsx! { ConnectedApp {} },
        Err((error, agent_required)) => {
            let heading = if agent_required {
                "The Sigil agent is required by machine policy"
            } else {
                "Sigil could not connect to hardware"
            };
            rsx! {
                style { {crate::theme::stylesheet()} }
                div { class: "offline-shell",
                    header { h1 { "Sigil" } }
                    section { class: "offline-card",
                        h2 { "{heading}" }
                        p { class: "error-text", "{error}" }
                        if agent_required {
                            p { class: "muted", "Direct mode is disabled by machine policy. Start the agent service, then restart Sigil." }
                        } else {
                            p { class: "muted", "Check the agent, device connection, or local machine policy." }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ConnectedApp() -> Element {
    let connection = use_context::<Option<ConnectedService>>().expect("app connected to a backend");
    let initial_devices = use_signal_sync(Vec::<DeviceInfo>::new);
    let selected_device = use_signal_sync(|| None::<DeviceId>);
    let status = use_signal_sync(|| None::<String>);
    let initial_toast = connection.warning.clone();
    let page = use_signal(startup_page);
    let initial_dialog = startup_dialog();
    let auth_config = use_hook(crate::auth::load_config);
    let auth_cancel = use_hook(|| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)));
    let state = AppState {
        credentials: connection.credentials.clone(),
        mode: connection.mode.clone(),
        auth_config,
        auth: use_signal_sync(|| crate::auth::AuthStatus::Checking),
        session: use_signal_sync(|| None::<std::sync::Arc<sigil_auth::Session>>),
        auth_cancel,
        managed: connection.managed.clone(),
        devices: initial_devices,
        selected_device,
        page,
        nav_collapsed: use_signal(|| false),
        panel_collapsed: use_signal(|| false),
        panel_open: use_signal(startup_panel_open),
        selected_slot: use_signal(|| None::<PivSlot>),
        dialog: use_signal_sync(|| initial_dialog),
        toast: use_signal_sync(|| initial_toast),
        status,
        piv_info: use_signal_sync(|| None::<(DeviceId, PivInfo)>),
        piv_slots: use_signal_sync(|| None::<(DeviceId, Vec<PivSlotInfo>)>),
        fido_status: use_signal_sync(|| None::<(DeviceId, FidoStatus)>),
        passkeys: use_signal_sync(|| None::<(DeviceId, Vec<DiscoverableCredential>)>),
        fingerprints: use_signal_sync(|| None::<(DeviceId, Vec<Fingerprint>)>),
        fips_banner_dismissed: use_signal(|| false),
        certificate_profiles: use_signal_sync(|| {
            None::<(DeviceId, Vec<sigil_connect::CertificateProfile>)>
        }),
    };
    let profile_state = state.clone();
    use_effect(move || crate::managed::refresh_profiles(&profile_state));
    let watcher_state = state.clone();
    use_hook(move || {
        tracing::info!(
            connection_mode = ?watcher_state.mode,
            "GUI connection initialized"
        );
        crate::auth::restore(&watcher_state);
        let service = watcher_state.credentials.clone();
        let mut devices = watcher_state.devices;
        let mut selected = watcher_state.selected_device;
        let mut status = watcher_state.status;
        // The window can close while this thread runs; every signal access is
        // fallible so the thread exits quietly once the signals are dropped.
        thread::spawn(move || {
            let mut apply = |result: sigil_core::Result<Vec<DeviceInfo>>| -> Option<()> {
                match result {
                    Ok(current) => {
                        let selected_id = selected.try_read().ok()?.clone();
                        if !current
                            .iter()
                            .any(|device| Some(&device.id) == selected_id.as_ref())
                        {
                            *selected.try_write().ok()? =
                                current.first().map(|device| device.id.clone());
                        }
                        *devices.try_write().ok()? = current;
                        *status.try_write().ok()? = None;
                    }
                    Err(error) => *status.try_write().ok()? = Some(error.to_string()),
                }
                Some(())
            };
            let watch = service.watch_devices();
            if apply(service.devices()).is_none() {
                return;
            }
            match watch {
                Ok(events) => {
                    while events.recv().is_ok() {
                        if apply(service.devices()).is_none() {
                            return;
                        }
                    }
                }
                Err(error) => {
                    let _ = apply(Err(error));
                }
            }
        });
    });
    use_context_provider(|| state);

    rsx! { AppShell {} }
}

fn connection_options() -> ConnectOptions {
    let mut arguments = std::env::args().skip(1);
    let mut options = ConnectOptions::default();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--agent" => options.agent = arguments.next(),
            other if other.starts_with("--agent=") => {
                options.agent = other.strip_prefix("--agent=").map(str::to_owned);
            }
            "--direct" => options.direct = true,
            #[cfg(debug_assertions)]
            "--direct-mock" => options.direct_mock = true,
            _ => {}
        }
    }
    options
}

fn startup_page() -> Page {
    #[cfg(debug_assertions)]
    {
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            if argument == "--debug-page" {
                return match arguments.next().as_deref() {
                    Some("accounts") => Page::Accounts,
                    Some("passkeys") => Page::Passkeys,
                    Some("certificates") => Page::Certificates,
                    Some("slots") => Page::Slots,
                    Some("settings") => Page::Settings,
                    _ => Page::Home,
                };
            }
        }
    }
    Page::Home
}

fn startup_dialog() -> Option<DialogKind> {
    #[cfg(debug_assertions)]
    if std::env::args().any(|argument| argument == "--debug-toggle-dialog") {
        return Some(DialogKind::ToggleApplications);
    }
    #[cfg(debug_assertions)]
    if std::env::args().any(|argument| argument == "--debug-enroll-dialog") {
        return Some(DialogKind::Enroll(None));
    }
    None
}

fn startup_panel_open() -> bool {
    #[cfg(debug_assertions)]
    return std::env::args().any(|argument| argument == "--debug-panel-open");
    #[cfg(not(debug_assertions))]
    false
}
