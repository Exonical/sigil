use std::sync::Arc;

use dioxus::prelude::*;
use sigil_app::CredentialService;
use sigil_client::AgentClient;

mod piv;

use sigil_core::{
    DeviceId, DeviceInfo, DiscoverableCredential, FidoStatus, Fingerprint, MetadataAccess,
    Transport,
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

fn agent_endpoint() -> Option<String> {
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--agent" {
            return arguments.next();
        }
    }
    None
}

fn app() -> Element {
    let connected = use_hook(|| {
        AgentClient::connect(agent_endpoint().as_deref())
            .map(|client| CredentialService::new(Arc::new(client)))
            .map_err(|error| error.to_string())
    });
    use_context_provider(|| connected.as_ref().ok().cloned());
    match connected {
        Ok(_) => rsx! { AgentUi {} },
        Err(error) => rsx! {
            style { {include_str!("style.css")} }
            div { class: "shell",
                header { h1 { "Sigil" } }
                main { section {
                    h2 { "Sigil agent is not running" }
                    p { class: "error", "{error}" }
                    p { class: "muted", "Start sigil-agent or install the Windows service, then restart Sigil." }
                } }
            }
        },
    }
}

#[component]
fn AgentUi() -> Element {
    let service = use_context::<Option<CredentialService>>()
        .expect("connected agent service is provided by app");
    use_context_provider(|| service.clone());
    let initial = use_hook(|| service.devices().map_err(|error| error.to_string()));
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
                        match service.devices() {
                            Ok(updated) => {
                                devices.set(updated);
                                status.set(String::new());
                            }
                            Err(error) => status.set(error.to_string()),
                        }
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

    rsx! {
        style { {include_str!("style.css")} }
        div { class: "shell",
            header {
                h1 { "Sigil" }
                span { class: "badge", "LOCAL AGENT" }
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
                            if !current_fido_error.is_empty() { p { class: "error", "{current_fido_error}" } }
                            if let Some(detail) = current_fido_status {
                                dl {
                                    dt { "CTAP versions" } dd { {detail.versions.join(", ")} }
                                    dt { "PIN configured" } dd { "{detail.pin_set:?}" }
                                    dt { "PIN retries" } dd { "{detail.pin_retries:?}" }
                                    dt { "Passkey management" } dd { "{detail.credential_management}" }
                                    dt { "Fingerprint enrollment" } dd { "{detail.fingerprint_enrollment}" }
                                }
                                if detail.credential_management || detail.fingerprint_enrollment {
                                    input { r#type: "password", placeholder: "FIDO2 PIN", value: "{pin}", oninput: move |event| pin.set(event.value()) }
                                }
                                if detail.credential_management {
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
                                if detail.fingerprint_enrollment {
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
                                    if !current_bio_message.is_empty() { p { "{current_bio_message}" } }
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
                            if let Some(entries) = current_passkeys {
                                if entries.is_empty() { p { "No discoverable credentials found." } }
                                for entry in entries.iter() {
                                    p { key: "{entry.credential_id}", "{entry.rp_id} — {entry.user_name}" }
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
