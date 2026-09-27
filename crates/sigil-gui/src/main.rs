use std::sync::Arc;

use dioxus::prelude::*;
use sigil_app::CredentialService;
use sigil_core::{DeviceDiscovery, DeviceId, DeviceInfo};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
                span { class: "badge", if is_mock { "SIMULATED HARDWARE" } else { "WINDOWS SMART CARD" } }
                button { onclick: move |_| {
                    match service.devices() {
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
                        p { class: "muted", "PIV inspection and management are planned for later milestones." }
                    } else {
                        h2 { "No device selected" }
                    }
                }
            }
        }
    }
}
