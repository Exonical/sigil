use std::sync::Arc;

use dioxus::prelude::*;
use sigil_app::CredentialService;
use sigil_core::{DeviceId, DeviceInfo};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    dioxus::launch(app);
}

fn app() -> Element {
    let service =
        use_hook(|| CredentialService::new(Arc::new(sigil_mock::MockDiscovery::with_example())));
    let mut devices = use_signal(|| service.devices().unwrap_or_default());
    let mut selected = use_signal(|| devices.read().first().map(|item| item.id.clone()));
    let current: Option<DeviceInfo> = devices
        .read()
        .iter()
        .find(|item| Some(&item.id) == selected.read().as_ref())
        .cloned();
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
                span { class: "badge", "SIMULATED HARDWARE" }
                button { onclick: move |_| {
                    if let Ok(updated) = service.devices() {
                        if !updated.iter().any(|item| Some(&item.id) == selected.read().as_ref()) {
                            selected.set(updated.first().map(|item| item.id.clone()));
                        }
                        devices.set(updated);
                    }
                }, "Refresh" }
            }
            main {
                aside {
                    h2 { "Devices" }
                    for device in devices.read().iter() {
                        button {
                            key: "{device.id.0}",
                            class: if Some(&device.id) == selected.read().as_ref() { "device active" } else { "device" },
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
                    if let Some(info) = current {
                        h2 { "{info.model}" }
                        p { class: "muted", "Fixture data for interface development. No physical YubiKey is connected by this backend." }
                        dl {
                            dt { "Vendor" } dd { "{info.vendor}" }
                            dt { "Serial" } dd { "{serial}" }
                            dt { "Firmware" }
                            dd { "{firmware}" }
                        }
                        h3 { "Applications" }
                        div { class: "chips",
                            for application in info.applications.iter() {
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
