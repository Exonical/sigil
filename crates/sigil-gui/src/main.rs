#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use dioxus::prelude::*;
use sigil_connect::{ConnectOptions, ConnectedService, ConnectionMode};

mod piv;

use sigil_core::{
    CredentialError, DeviceId, DeviceInfo, DiscoverableCredential, FidoStatus, Fingerprint,
    MetadataAccess, Transport,
};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new().with_window(
                dioxus::desktop::WindowBuilder::new()
                    .with_title("Sigil")
                    .with_inner_size(dioxus::desktop::LogicalSize::new(1280.0, 860.0))
                    .with_min_inner_size(dioxus::desktop::LogicalSize::new(900.0, 600.0))
                    .with_position(dioxus::desktop::LogicalPosition::new(80.0, 80.0)),
            ),
        )
        .launch(app);
}

fn connection_options() -> ConnectOptions {
    let mut arguments = std::env::args().skip(1);
    let mut options = ConnectOptions::default();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--agent" => options.agent = arguments.next(),
            "--direct" => options.direct = true,
            _ => {}
        }
    }
    options
}

fn app() -> Element {
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
        Ok(connection) => {
            if let Some(warning) = &connection.warning {
                tracing::warn!("{warning}");
            }
            rsx! { AgentUi {} }
        }
        Err((error, agent_required)) => {
            let heading = if agent_required {
                "The Sigil agent is required by machine policy"
            } else {
                "Sigil could not connect to hardware"
            };
            rsx! {
                style { {include_str!("style.css")} }
                div { class: "shell",
                    header {
                        h1 { "Sigil" }
                        span { class: "badge", "Offline" }
                    }
                    main { section {
                        h2 { "{heading}" }
                        p { class: "error", "{error}" }
                        if agent_required {
                            p { class: "muted", "Direct mode is disabled by machine policy. Start the agent service, then restart Sigil." }
                        } else {
                            p { class: "muted", "Check the agent, device connection, or local machine policy." }
                        }
                    } }
                }
            }
        }
    }
}

#[component]
fn AgentUi() -> Element {
    let connection = use_context::<Option<ConnectedService>>().expect("app connected to a backend");
    let service = connection.credentials.clone();
    let mode = connection.mode.clone();
    use_context_provider(|| service.clone());
    let initial = use_hook(|| service.devices().map_err(|error| error.to_string()));
    tracing::info!(
        connection_mode = ?connection.mode,
        device_count = initial.as_ref().map(Vec::len).unwrap_or_default(),
        models = ?initial
            .as_ref()
            .map(|devices| devices.iter().map(|device| device.model.as_str()).collect::<Vec<_>>())
            .unwrap_or_default(),
        "GUI connection initialized"
    );
    let mut devices = use_signal_sync(|| initial.as_ref().cloned().unwrap_or_default());
    let mut status = use_signal_sync(|| initial.as_ref().err().cloned().unwrap_or_default());
    let mut selected = use_signal(|| devices.read().first().map(|item| item.id.clone()));
    let mut inspected = use_signal_sync(|| None::<DeviceId>);
    let mut fido_status = use_signal_sync(|| None::<(DeviceId, FidoStatus)>);
    let mut passkeys = use_signal_sync(|| None::<(DeviceId, Vec<DiscoverableCredential>)>);
    let mut fingerprints = use_signal_sync(|| None::<(DeviceId, Vec<Fingerprint>)>);
    let mut bio_message = use_signal_sync(|| None::<(DeviceId, String)>);
    let mut bio_busy = use_signal_sync(|| false);
    let mut pending_delete = use_signal_sync(|| None::<(DeviceId, String)>);
    let mut fido_error = use_signal_sync(|| None::<(DeviceId, String)>);
    let mut pin = use_signal(String::new);
    use_hook(|| {
        let service = service.clone();
        match service.watch_devices() {
            Ok(events) => {
                let _ = std::thread::spawn(move || {
                    while events.recv().is_ok() {
                        let (updated, message) = match service.devices() {
                            Ok(updated) => (Some(updated), String::new()),
                            Err(error) => (None, error.to_string()),
                        };
                        // The UI may have unmounted (window closed); stop instead of panicking.
                        if let Some(updated) = updated {
                            let Ok(mut current) = devices.try_write() else {
                                break;
                            };
                            *current = updated;
                        }
                        let Ok(mut current) = status.try_write() else {
                            break;
                        };
                        *current = message;
                    }
                });
            }
            Err(error) => status.set(error.to_string()),
        }
    });
    let chosen_id = selected
        .read()
        .clone()
        .filter(|id| devices.read().iter().any(|item| &item.id == id))
        .or_else(|| devices.read().first().map(|item| item.id.clone()));
    let current: Option<DeviceInfo> = devices
        .read()
        .iter()
        .find(|item| Some(&item.id) == chosen_id.as_ref())
        .cloned();
    let status_message = status.read().clone();
    let fido_pin_not_set_message = CredentialError::FidoPinNotSet.to_string();
    let inspection_visible = current
        .as_ref()
        .is_some_and(|device| inspected.read().as_ref() == Some(&device.id));
    let current_fido_status = if inspection_visible {
        fido_status
            .read()
            .as_ref()
            .filter(|(id, _)| Some(id) == chosen_id.as_ref())
            .map(|(_, value)| value.clone())
    } else {
        None
    };
    let current_passkeys = if inspection_visible {
        passkeys
            .read()
            .as_ref()
            .filter(|(id, _)| Some(id) == chosen_id.as_ref())
            .map(|(_, value)| value.clone())
    } else {
        None
    };
    let current_fido_error = if inspection_visible {
        fido_error
            .read()
            .as_ref()
            .filter(|(id, _)| Some(id) == chosen_id.as_ref())
            .map(|(_, error)| error.clone())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let current_fingerprints = fingerprints
        .read()
        .as_ref()
        .filter(|(id, _)| Some(id) == chosen_id.as_ref())
        .map(|(_, value)| value.clone());
    let current_bio_message = bio_message
        .read()
        .as_ref()
        .filter(|(id, _)| Some(id) == chosen_id.as_ref())
        .map(|(_, message)| message.clone())
        .unwrap_or_default();
    let refresh_service = service.clone();
    let form_factor = current
        .as_ref()
        .and_then(|info| info.form_factor.as_deref())
        .unwrap_or("unknown")
        .to_owned();
    let serial = current
        .as_ref()
        .and_then(|info| info.serial.as_deref())
        .unwrap_or("unavailable")
        .to_owned();
    let firmware = current
        .as_ref()
        .and_then(|info| info.firmware.as_ref())
        .map(|v| format!("{}.{}.{}", v.major, v.minor, v.patch))
        .unwrap_or_else(|| "unavailable".into());
    let mode_label = match &mode {
        ConnectionMode::Agent { .. } => "Agent",
        ConnectionMode::Direct { elevated: true } => "Direct · Administrator",
        ConnectionMode::Direct { elevated: false } => "Direct",
    };
    let direct_mode = matches!(mode, ConnectionMode::Direct { .. });
    let fido_access_restricted_message = CredentialError::FidoAccessRestricted.to_string();
    let restart_admin_message = use_signal(String::new);

    rsx! {
        style { {include_str!("style.css")} }
        div { class: "shell",
            header {
                h1 { "Sigil" }
                span { class: "badge", "{mode_label}" }
                button { onclick: move |_| {
                    match refresh_service.devices() {
                        Ok(updated) => {
                            if !updated.iter().any(|item| Some(&item.id) == selected.read().as_ref()) {
                                selected.set(updated.first().map(|item| item.id.clone()));
                            }
                            devices.set(updated);
                            status.set(String::new());
                        }
                        Err(error) => status.set(error.to_string()),
                    }
                }, "Refresh" }
            }
            main {
                aside {
                    h2 { "Devices" }
                    for device in devices.read().iter() {
                        button {
                            key: "{device.id.0}",
                            class: if Some(&device.id) == chosen_id.as_ref() { "device active" } else { "device" },
                            onclick: {
                                let id: DeviceId = device.id.clone();
                                move |_| {
                                    pin.set(String::new());
                                    pending_delete.set(None);
                                    selected.set(Some(id.clone()));
                                }
                            },
                            "{device.model}"
                            small { "{device.id.0}" }
                        }
                    }
                }
                section {
                    if !status_message.is_empty() { p { class: "error", "{status_message}" } }
                    if let Some(info) = current {
                        h2 { "{info.model}" }
                        if info.simulated { span { class: "badge", "SIMULATED HARDWARE" } }
                        if info.simulated { p { class: "muted", "Fixture data for interface development. No physical YubiKey is connected by this backend." } }
                        dl {
                            dt { "Vendor" } dd { "{info.vendor}" }
                            dt { "Connection" }
                            dd { {info.connection.as_ref().map(|connection| format!("{connection:?}")).unwrap_or_else(|| "unknown".into())} }
                            dt { "Serial" } dd { "{serial}" }
                            dt { "Firmware" }
                            dd { "{firmware}" }
                            dt { "Form factor" } dd { "{form_factor}" }
                            dt { "Metadata access" } dd { "{info.metadata_access:?}" }
                        }
                        if info.metadata_access == MetadataAccess::Restricted {
                            p { class: "muted", "The agent cannot access this device's FIDO HID metadata in the current session." }
                        }
                        h3 { "Interfaces" }
                        div { class: "chips",
                            for transport in info.transports.iter() {
                                span { class: "chip", "{transport:?}" }
                            }
                        }
                        h3 { "Enabled applications" }
                        div { class: "chips",
                            for application in info.applications.iter() {
                                span { class: "chip", "{application:?}" }
                            }
                        }
                        h3 { "Supported applications" }
                        div { class: "chips",
                            for application in info.supported_applications.iter() {
                                span { class: "chip", "{application:?}" }
                            }
                        }
                        if info.transports.contains(&Transport::UsbHid) || info.simulated {
                            h3 { "FIDO2 inspection" }
                            button { onclick: {
                                let id = info.id.clone();
                                let service = service.clone();
                                move |_| {
                                    inspected.set(Some(id.clone()));
                                    pin.set(String::new());
                                    fido_status.set(None);
                                    passkeys.set(None);
                                    fingerprints.set(None);
                                    bio_message.set(None);
                                    pending_delete.set(None);
                                    fido_error.set(None);
                                    let service = service.clone();
                                    let id = id.clone();
                                    std::thread::spawn(move || match service.fido_status(&id) {
                                        Ok(value) => fido_status.set(Some((id, value))),
                                        Err(error) => fido_error.set(Some((id, error.to_string()))),
                                    });
                                }
                            }, "Inspect FIDO2" }
                            if !current_fido_error.is_empty() {
                                p { class: "error", "{current_fido_error}" }
                                if direct_mode && current_fido_error == fido_access_restricted_message {
                                    RestartAsAdministrator { message: restart_admin_message }
                                }
                            }
                            if let Some(detail) = current_fido_status.as_ref() {
                                dl {
                                    dt { "CTAP versions" } dd { {detail.versions.join(", ")} }
                                    dt { "PIN configured" } dd { "{detail.pin_set:?}" }
                                    dt { "PIN retries" } dd { "{detail.pin_retries:?}" }
                                    dt { "Passkey management" } dd { "{detail.credential_management}" }
                                    dt { "Fingerprint enrollment" } dd { "{detail.fingerprint_enrollment}" }
                                }
                                if detail.pin_set == Some(false) {
                                    p { class: "muted", "{fido_pin_not_set_message}" }
                                }
                                if detail.pin_set != Some(false) && (detail.credential_management || detail.fingerprint_enrollment) {
                                    input { r#type: "password", placeholder: "FIDO2 PIN", value: "{pin}", oninput: move |event| pin.set(event.value()) }
                                }
                                if detail.pin_set != Some(false) && detail.credential_management {
                                    button { onclick: {
                                        let id = info.id.clone();
                                        let service = service.clone();
                                        move |_| {
                                            let supplied_pin = pin.read().clone();
                                            pin.set(String::new());
                                            passkeys.set(None);
                                            fido_error.set(None);
                                            let service = service.clone();
                                            let id = id.clone();
                                            std::thread::spawn(move || match service.discoverable_credentials(&id, &supplied_pin) {
                                                Ok(value) => passkeys.set(Some((id, value))),
                                                Err(error) => fido_error.set(Some((id, error.to_string()))),
                                            });
                                        }
                                    }, "List passkeys" }
                                }
                                if detail.pin_set != Some(false) && detail.fingerprint_enrollment {
                                    h3 { "Fingerprints" }
                                    p { class: "muted", "Enter the FIDO2 PIN to list or manage fingerprints. Enrollment requires repeated touches of the same finger." }
                                    button { disabled: bio_busy(), onclick: {
                                        let id = info.id.clone();
                                        let service = service.clone();
                                        move |_| {
                                            if bio_busy() { return; }
                                            let supplied_pin = pin.read().clone();
                                            pin.set(String::new());
                                            bio_busy.set(true);
                                            bio_message.set(Some((id.clone(), "Reading fingerprints…".into())));
                                            let service = service.clone();
                                            let id = id.clone();
                                            std::thread::spawn(move || {
                                                match service.fingerprints(&id, &supplied_pin) {
                                                    Ok(value) => {
                                                        fingerprints.set(Some((id.clone(), value)));
                                                        bio_message.set(Some((id, "Fingerprint list refreshed.".into())));
                                                    }
                                                    Err(error) => bio_message.set(Some((id, error.to_string()))),
                                                }
                                                bio_busy.set(false);
                                            });
                                        }
                                    }, "List fingerprints" }
                                    button { disabled: bio_busy(), onclick: {
                                        let id = info.id.clone();
                                        let service = service.clone();
                                        move |_| {
                                            if bio_busy() { return; }
                                            let supplied_pin = pin.read().clone();
                                            pin.set(String::new());
                                            bio_busy.set(true);
                                            bio_message.set(Some((id.clone(), "Touch the sensor when prompted…".into())));
                                            let service = service.clone();
                                            let id = id.clone();
                                            std::thread::spawn(move || {
                                                let progress_id = id.clone();
                                                match service.enroll_fingerprint(&id, &supplied_pin, &mut |progress| {
                                                    bio_message.set(Some((progress_id.clone(), format!("{} Remaining samples: {}", progress.message, progress.remaining_samples))));
                                                }) {
                                                    Ok(value) => {
                                                        let mut entries = fingerprints.read().as_ref()
                                                            .filter(|(device_id, _)| device_id == &id)
                                                            .map(|(_, entries)| entries.clone()).unwrap_or_default();
                                                        entries.push(value);
                                                        fingerprints.set(Some((id.clone(), entries)));
                                                        bio_message.set(Some((id, "Fingerprint enrolled.".into())));
                                                    }
                                                    Err(error) => bio_message.set(Some((id, error.to_string()))),
                                                }
                                                bio_busy.set(false);
                                            });
                                        }
                                    }, "Enroll fingerprint" }
                                    if !current_bio_message.is_empty() {
                                        p { "{current_bio_message}" }
                                        if direct_mode && current_bio_message == fido_access_restricted_message {
                                            RestartAsAdministrator { message: restart_admin_message }
                                        }
                                    }
                                    if let Some(entries) = current_fingerprints {
                                        if entries.is_empty() { p { "No fingerprints enrolled." } }
                                        for entry in entries.iter() {
                                            div { key: "{entry.id}",
                                                span { {entry.name.clone().unwrap_or_else(|| "Unnamed fingerprint".into())} " ({entry.id}) " }
                                                if pending_delete.read().as_ref() == Some(&(info.id.clone(), entry.id.clone())) {
                                                    span { "Enter the PIN again to permanently delete this fingerprint. " }
                                                    button { disabled: bio_busy(), onclick: {
                                                        let id = info.id.clone();
                                                        let fingerprint_id = entry.id.clone();
                                                        let service = service.clone();
                                                        move |_| {
                                                            if bio_busy() { return; }
                                                            let supplied_pin = pin.read().clone();
                                                            pin.set(String::new());
                                                            pending_delete.set(None);
                                                            bio_busy.set(true);
                                                            let service = service.clone();
                                                            let id = id.clone();
                                                            let fingerprint_id = fingerprint_id.clone();
                                                            std::thread::spawn(move || {
                                                                match service.remove_fingerprint(&id, &supplied_pin, &fingerprint_id) {
                                                                    Ok(()) => {
                                                                        let mut entries = fingerprints.read().as_ref()
                                                                            .filter(|(device_id, _)| device_id == &id)
                                                                            .map(|(_, entries)| entries.clone()).unwrap_or_default();
                                                                        entries.retain(|item| item.id != fingerprint_id);
                                                                        fingerprints.set(Some((id.clone(), entries)));
                                                                        bio_message.set(Some((id, "Fingerprint removed.".into())));
                                                                    }
                                                                    Err(error) => bio_message.set(Some((id, error.to_string()))),
                                                                }
                                                                bio_busy.set(false);
                                                            });
                                                        }
                                                    }, "Confirm delete" }
                                                    button { onclick: move |_| pending_delete.set(None), "Cancel" }
                                                } else {
                                                    button { disabled: bio_busy(), onclick: {
                                                        let id = info.id.clone();
                                                        let fingerprint_id = entry.id.clone();
                                                        move |_| pending_delete.set(Some((id.clone(), fingerprint_id.clone())))
                                                    }, "Delete" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if current_fido_status
                                .as_ref()
                                .is_some_and(|detail| detail.pin_set != Some(false))
                            {
                                if let Some(entries) = current_passkeys {
                                    if entries.is_empty() { p { "No discoverable credentials found." } }
                                    for entry in entries.iter() {
                                        p { key: "{entry.credential_id}", "{entry.rp_id} - {entry.user_name}" }
                                    }
                                }
                            }
                        }
                        if matches!(
                            info.connection.as_ref(),
                            Some(Transport::UsbSmartCard | Transport::Nfc)
                        ) || info.simulated
                        {
                            piv::PivPanel { key: "{info.id.0}", device: info.id.clone() }
                        }
                    } else {
                        h2 { "No device selected" }
                        p { class: "muted", "Connect a YubiKey, then refresh the device list." }
                    }
                }
            }
        }
    }
}

#[component]
fn RestartAsAdministrator(message: Signal<String>) -> Element {
    rsx! {
        button {
            onclick: move |_| match restart_as_administrator() {
                Ok(()) => std::process::exit(0),
                Err(error) => message.set(error),
            },
            "Restart as administrator"
        }
        if !message.read().is_empty() {
            p { class: "error", "{message}" }
        }
    }
}

#[cfg(windows)]
fn restart_as_administrator() -> std::result::Result<(), String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_CANCELLED, GetLastError},
        UI::{
            Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    };

    let executable =
        std::env::current_exe().map_err(|error| format!("could not locate Sigil: {error}"))?;
    let file = wide_string(executable.as_os_str());
    let verb = wide_string(std::ffi::OsStr::new("runas"));
    let mut arguments = Vec::new();
    for argument in std::env::args_os().skip(1) {
        if !arguments.is_empty() {
            arguments.push(u16::from(b' '));
        }
        arguments.extend(quote_windows_argument(&argument));
    }
    arguments.push(0);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: arguments.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..SHELLEXECUTEINFOW::default()
    };
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let error = unsafe { GetLastError() };
        if error == ERROR_CANCELLED {
            return Err("Administrator elevation was cancelled.".into());
        }
        return Err(format!(
            "Could not restart Sigil as administrator (Windows error {error})."
        ));
    }
    if !info.hProcess.is_null() {
        unsafe { CloseHandle(info.hProcess) };
    }
    Ok(())
}

#[cfg(not(windows))]
fn restart_as_administrator() -> std::result::Result<(), String> {
    Err("Administrator relaunch is only available on Windows.".into())
}

#[cfg(windows)]
fn wide_string(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn quote_windows_argument(value: &std::ffi::OsStr) -> Vec<u16> {
    let value = value.encode_wide().collect::<Vec<_>>();
    if !value.is_empty() && !value.iter().any(|unit| matches!(*unit, 0x20 | 0x09 | 0x22)) {
        return value;
    }
    let mut quoted = vec![0x22];
    let mut backslashes = 0usize;
    for unit in value {
        if unit == 0x5c {
            backslashes += 1;
        } else if unit == 0x22 {
            quoted.extend(std::iter::repeat_n(0x5c, backslashes * 2 + 1));
            quoted.push(unit);
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n(0x5c, backslashes));
            quoted.push(unit);
            backslashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n(0x5c, backslashes * 2));
    quoted.push(0x22);
    quoted
}
