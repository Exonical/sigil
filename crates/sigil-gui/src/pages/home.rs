use dioxus::prelude::*;
use sigil_core::{Application, DeviceInfo, Transport};

use crate::{icons::Icon, state::AppState};

#[component]
pub fn HomePage() -> Element {
    let state = use_context::<AppState>();
    match state.current_device() {
        Some(device) => rsx! {
            div { class: "home-page page-scroll",
                if device.simulated {
                    div { class: "simulation-banner",
                        Icon { name: "info", size: 17 }
                        span { "Simulated YubiKey. Changes affect fixture data only." }
                    }
                }
                div { class: "hero-card",
                    div { class: "hero-icon", Icon { name: "key", size: 30 } }
                    div {
                        p { class: "eyebrow", "CONNECTED DEVICE" }
                        h2 { "{device_name(&device)}" }
                        p { class: "device-meta", "S/N: {device.serial.as_deref().unwrap_or(\"unavailable\")}  ·  F/W: {firmware(&device)}" }
                    }
                    div { class: "hero-badges",
                        if device.fips == Some(true) {
                            span { class: "status-badge", Icon { name: "shield", size: 14 } "FIPS capable" }
                        }
                        if device
                            .fips_approved
                            .as_ref()
                            .is_some_and(|applications| applications.contains(&Application::Piv))
                        {
                            span { class: "status-badge approved", Icon { name: "check", size: 14 } "FIPS approved" }
                        }
                    }
                }

                div { class: "home-facts",
                    article { class: "info-card",
                        p { class: "eyebrow", "DEVICE" }
                        h3 { "{device.vendor}" }
                        p { class: "muted", "{connection(&device)}" }
                    }
                    article { class: "info-card",
                        p { class: "eyebrow", "SECURITY" }
                        h3 {
                            if device.pin_complexity == Some(true) { "PIN complexity enforced" }
                            else if device.pin_complexity == Some(false) { "PIN complexity disabled" }
                            else { "PIN complexity not reported" }
                        }
                        p { class: "muted", "Reported by the YubiKey management applet" }
                    }
                }

                section { class: "application-section",
                    div { class: "section-heading",
                        div {
                            p { class: "eyebrow", "APPLICATIONS" }
                            h3 { "Enabled over USB" }
                        }
                        span { class: "count-badge", "{device.usb_enabled.len()} enabled" }
                    }
                    div { class: "application-chips",
                        for app in device.usb_enabled.iter() {
                            span { key: "usb-{app:?}", class: "application-chip",
                                {app_icon(app)}
                                "{application_name(app)}"
                            }
                        }
                    }
                    if device.nfc_enabled.is_empty() {
                        p { class: "muted small", "No NFC applications are enabled." }
                    } else {
                        p { class: "eyebrow nfc-heading", "ENABLED OVER NFC" }
                        div { class: "application-chips",
                            for app in device.nfc_enabled.iter() {
                                span { key: "nfc-{app:?}", class: "application-chip",
                                    {app_icon(app)}
                                    "{application_name(app)}"
                                }
                            }
                        }
                    }
                }
            }
        },
        None => rsx! {
            div { class: "empty-state",
                div { class: "empty-icon", Icon { name: "key", size: 28 } }
                h2 { "No security key connected" }
                p { "Connect a YubiKey to manage its applications and credentials." }
            }
        },
    }
}

pub(crate) fn device_name(device: &DeviceInfo) -> String {
    let Some(form_factor) = device.form_factor.as_deref() else {
        return device.model.clone();
    };
    let name = if form_factor.contains("USB-C") {
        if form_factor.contains("Nano") {
            "YubiKey 5C Nano"
        } else {
            "YubiKey 5C"
        }
    } else if form_factor.contains("USB-A") {
        if form_factor.contains("Nano") {
            "YubiKey 5 Nano"
        } else {
            "YubiKey 5"
        }
    } else {
        return device.model.clone();
    };
    let mut name = name.to_owned();
    if device.transports.contains(&Transport::Nfc) {
        name.push_str(" NFC");
    }
    if device.fips == Some(true) {
        name.push_str(" FIPS");
    }
    name
}

pub(crate) fn firmware(device: &DeviceInfo) -> String {
    device
        .firmware
        .as_ref()
        .map(|version| format!("{}.{}.{}", version.major, version.minor, version.patch))
        .unwrap_or_else(|| "unavailable".into())
}

pub(crate) fn application_name(application: &Application) -> &'static str {
    match application {
        Application::Piv => "PIV",
        Application::Fido2 => "FIDO2",
        Application::U2f => "U2F",
        Application::Otp => "Yubico OTP",
        Application::OpenPgp => "OpenPGP",
        Application::Oath => "OATH",
        Application::YubiHsmAuth => "YubiHSM Auth",
    }
}

pub(crate) fn app_icon(application: &Application) -> Element {
    let icon = match application {
        Application::Piv => "certificate",
        Application::Fido2 | Application::U2f => "key",
        Application::Otp => "key",
        Application::OpenPgp => "lock",
        Application::Oath => "shield",
        Application::YubiHsmAuth => "grid",
    };
    rsx! { Icon { name: icon, size: 15 } }
}

fn connection(device: &DeviceInfo) -> String {
    device
        .connection
        .as_ref()
        .map(|transport| format!("{transport:?}"))
        .unwrap_or_else(|| "Connection unavailable".into())
}
