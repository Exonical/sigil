use std::sync::Arc;

use dioxus::prelude::*;
use sigil_app::CredentialService;
use sigil_core::{
    DeviceDiscovery, DeviceId, DeviceInfo, DiscoverableCredential, FidoStatus, MetadataAccess,
    Transport,
};

#[cfg(target_os = "windows")]
fn open_elevated() -> std::io::Result<()> {
    use std::{iter, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
    let executable = std::env::current_exe()?;
    let path: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(iter::once(0)).collect();
    // SAFETY: Both UTF-16 strings are NUL terminated and live across the call.
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            verb.as_ptr(),
            path.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn open_elevated() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows only",
    ))
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    dioxus::launch(app);
}

fn app() -> Element {
    let (service, is_mock) = use_hook(|| {
        let is_mock = !cfg!(target_os = "windows") || std::env::args().any(|arg| arg == "--mock");
        let backend: Arc<dyn DeviceDiscovery> = if is_mock {
            Arc::new(sigil_mock::MockDiscovery::with_example())
        } else {
            Arc::new(sigil_platform::NativeDiscovery)
        };
        (CredentialService::new(backend), is_mock)
    });
    let initial = use_hook(|| service.devices().map_err(|error| error.to_string()));
    let mut devices = use_signal_sync(|| initial.as_ref().cloned().unwrap_or_default());
    let mut status = use_signal_sync(|| initial.as_ref().err().cloned().unwrap_or_default());
    let mut selected = use_signal(|| devices.read().first().map(|item| item.id.clone()));
    let mut inspected = use_signal_sync(|| None::<DeviceId>);
    let mut fido_status = use_signal_sync(|| None::<(DeviceId, FidoStatus)>);
    let mut passkeys = use_signal_sync(|| None::<(DeviceId, Vec<DiscoverableCredential>)>);
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
                span { class: "badge", if is_mock { "SIMULATED HARDWARE" } else { "WINDOWS DEVICES" } }
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
                                move |_| selected.set(Some(id.clone()))
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
                        if info.simulated { p { class: "muted", "Fixture data for interface development. No physical YubiKey is connected by this backend." } }
                        dl {
                            dt { "Vendor" } dd { "{info.vendor}" }
                            dt { "Serial" } dd { "{serial}" }
                            dt { "Firmware" }
                            dd { "{firmware}" }
                            dt { "Form factor" } dd { "{form_factor}" }
                            dt { "Metadata access" } dd { "{info.metadata_access:?}" }
                        }
                        if info.metadata_access == MetadataAccess::Restricted {
                            p { class: "muted", "Windows restricts FIDO HID access in this session. Open Sigil as administrator to inspect this key." }
                            button { onclick: move |_| {
                                if let Err(error) = open_elevated() { status.set(format!("Could not open elevated Sigil: {error}")); }
                            }, "Open elevated Sigil" }
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
                                    fido_status.set(None);
                                    passkeys.set(None);
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
                                }
                                if detail.credential_management {
                                    input { r#type: "password", placeholder: "FIDO2 PIN", value: "{pin}", oninput: move |event| pin.set(event.value()) }
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
                            }
                            if let Some(entries) = current_passkeys {
                                if entries.is_empty() { p { "No discoverable credentials found." } }
                                for entry in entries.iter() {
                                    p { key: "{entry.credential_id}", "{entry.rp_id} — {entry.user_name}" }
                                }
                            }
                        }
                        p { class: "muted", "PIV inspection and management are planned for later milestones." }
                    } else {
                        h2 { "No device selected" }
                        if !is_mock { p { class: "muted", "Connect a YubiKey, then refresh the device list." } }
                    }
                }
            }
        }
    }
}
