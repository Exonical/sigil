use dioxus::prelude::*;
use sigil_app::CredentialService;
use sigil_core::{
    CertificateFormat, DeviceId, KeyStatus, PivInfo, PivSlot, PivSlotInfo, RetryStatus,
};

#[component]
pub fn PivPanel(device: DeviceId) -> Element {
    let service = use_context::<CredentialService>();
    let mut inspection = use_signal_sync(|| None::<(DeviceId, PivInfo, Vec<PivSlotInfo>)>);
    let mut error = use_signal_sync(|| None::<(DeviceId, String)>);
    let mut certificate = use_signal_sync(|| None::<(DeviceId, PivSlot, String)>);
    let current = inspection
        .read()
        .as_ref()
        .filter(|(id, _, _)| id == &device)
        .map(|(_, info, slots)| (info.clone(), slots.clone()));
    let current_error = error
        .read()
        .as_ref()
        .filter(|(id, _)| id == &device)
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let current_certificate = certificate
        .read()
        .as_ref()
        .filter(|(id, _, _)| id == &device)
        .map(|(_, slot, pem)| (*slot, pem.clone()));

    rsx! {
        section { class: "piv-panel",
            h3 { "PIV inspection" }
            button { onclick: {
                let service = service.clone();
                let id = device.clone();
                move |_| {
                    inspection.set(None);
                    certificate.set(None);
                    error.set(None);
                    let service = service.clone();
                    let id = id.clone();
                    std::thread::spawn(move || {
                        let result = service.piv_info(&id).and_then(|info| {
                            service.piv_slots(&id).map(|slots| (info, slots))
                        });
                        match result {
                            Ok((info, slots)) => inspection.set(Some((id, info, slots))),
                            Err(value) => error.set(Some((id, value.to_string()))),
                        }
                    });
                }
            }, "Inspect PIV" }
            if !current_error.is_empty() { p { class: "error", "{current_error}" } }
            if let Some((info, slots)) = current {
                dl {
                    dt { "Firmware" }
                    dd { {info.version.as_ref().map(|version| format!("{}.{}.{}", version.major, version.minor, version.patch)).unwrap_or_else(|| "unknown".into())} }
                    dt { "PIN retries" }
                    dd { {render_retries(info.pin.as_ref())} }
                    dt { "PUK retries" }
                    dd { {render_retries(info.puk.as_ref())} }
                    dt { "Management key" }
                    dd { {info.management_key.as_ref().map(|key| format!("{} (default: {:?}, touch: {:?})", key.algorithm, key.default_value, key.touch_policy)).unwrap_or_else(|| "unknown".into())} }
                }
                div { class: "piv-table-wrap",
                    table { class: "piv-table",
                        thead {
                            tr {
                                th { "Slot" }
                                th { "Name" }
                                th { "Key" }
                                th { "PIN policy" }
                                th { "Touch policy" }
                                th { "Subject" }
                                th { "Issuer" }
                                th { "Serial" }
                                th { "Valid from" }
                                th { "Valid until" }
                                th { "Certificate" }
                            }
                        }
                        tbody {
                            for slot_info in slots.iter() {
                                {
                                    let slot = slot_info.slot;
                                    let (key, pin, touch) = match &slot_info.key {
                                        KeyStatus::Present(metadata) => (
                                            metadata.algorithm.to_string(),
                                            format!("{:?}", metadata.pin_policy),
                                            format!("{:?}", metadata.touch_policy),
                                        ),
                                        KeyStatus::Absent => ("absent".into(), "-".into(), "-".into()),
                                        KeyStatus::Unknown => ("unknown".into(), "-".into(), "-".into()),
                                    };
                                    let (subject, issuer, serial, not_before, not_after) = slot_info.certificate.as_ref().map(|summary| (
                                        summary.subject.as_str(), summary.issuer.as_str(), summary.serial.as_str(), summary.not_before.as_str(), summary.not_after.as_str()
                                    )).unwrap_or(("-", "-", "-", "-", "-"));
                                    rsx! {
                                        tr { key: "{slot}",
                                            td { "{slot}" }
                                            td { {slot.name()} }
                                            td { "{key}" }
                                            td { "{pin}" }
                                            td { "{touch}" }
                                            td { "{subject}" }
                                            td { "{issuer}" }
                                            td { "{serial}" }
                                            td { "{not_before}" }
                                            td { "{not_after}" }
                                            td {
                                                if slot_info.certificate.is_some() {
                                                    button { onclick: {
                                                        let service = service.clone();
                                                        let id = device.clone();
                                                        move |_| {
                                                            certificate.set(None);
                                                            error.set(None);
                                                            let service = service.clone();
                                                            let id = id.clone();
                                                            std::thread::spawn(move || {
                                                                match service.export_certificate(&id, slot, CertificateFormat::Pem) {
                                                                    Ok(pem) => match String::from_utf8(pem) {
                                                                        Ok(pem) => certificate.set(Some((id, slot, pem))),
                                                                        Err(value) => error.set(Some((id, value.to_string()))),
                                                                    },
                                                                    Err(value) => error.set(Some((id, value.to_string()))),
                                                                }
                                                            });
                                                        }
                                                    }, "Show certificate" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some((slot, pem)) = current_certificate {
                h4 { "Certificate {slot}" }
                pre { class: "certificate-pem", "{pem}" }
            }
        }
    }
}

fn render_retries(status: Option<&RetryStatus>) -> String {
    status
        .map(|status| match status.total {
            Some(total) => format!(
                "{} of {total} remaining (default: {:?})",
                status.remaining, status.default_value
            ),
            None => format!("{} remaining", status.remaining),
        })
        .unwrap_or_else(|| "unknown".into())
}
