use dioxus::prelude::*;
use sigil_connect::{CertificateProfile, EnrolledCertificate};
use sigil_core::{DeviceInfo, PivPin, PivSlot};
use zeroize::Zeroizing;

use crate::{
    icons::Icon,
    managed,
    state::{AppState, SetLive},
};

use super::managed_dialog::pin_length_ok;

const STEPS: [&str; 4] = [
    "Generating key",
    "Attesting",
    "Requesting certificate",
    "Installing",
];

#[component]
pub fn EnrollDialog(device: DeviceInfo, preselected: Option<PivSlot>) -> Element {
    let state = use_context::<AppState>();
    let mut dialog = state.dialog;
    let fips = device.fips == Some(true);
    let profiles: Option<Vec<CertificateProfile>> = state
        .certificate_profiles
        .read()
        .as_ref()
        .filter(|(owner, _)| owner == &device.id)
        .map(|(_, list)| list.clone());
    let chosen = use_signal(|| None::<String>);
    let pin = use_signal(|| Zeroizing::new(String::new()));
    let error = use_signal_sync(|| None::<String>);
    let busy = use_signal_sync(|| false);
    let result = use_signal_sync(|| None::<EnrolledCertificate>);
    let selected_name = chosen.read().clone().or_else(|| {
        profiles
            .as_deref()
            .and_then(|list| list.get(managed::preselected_index(list, preselected)))
            .map(|profile| profile.name.clone())
    });
    let selected = profiles.as_deref().and_then(|list| {
        list.iter()
            .find(|profile| Some(&profile.name) == selected_name.as_ref())
            .cloned()
    });
    let length_ok = pin_length_ok(pin.read().as_str(), fips);
    let can_submit = !busy() && result.read().is_none() && selected.is_some() && length_ok;
    let live_message = (!pin.read().is_empty() && !length_ok).then(|| {
        if fips {
            "This FIPS key requires an 8-character PIN.".to_owned()
        } else {
            "The PIN must be 6-8 characters.".to_owned()
        }
    });

    rsx! {
        div { class: "modal-backdrop", tabindex: "-1", autofocus: true,
            onkeydown: move |event| {
                if event.key() == Key::Escape && !busy() {
                    dialog.set(None);
                }
            },
            section { class: "modal", role: "dialog", aria_modal: "true",
                header { class: "modal-header",
                    div {
                        p { class: "eyebrow", "MANAGED BY SIGIL" }
                        h2 { "Enroll certificate" }
                        p { class: "modal-description", "Sigil generates the key on the token, has it attested, and installs the certificate that the backend issues for your account." }
                    }
                    button { class: "icon-button", title: "Close dialog", disabled: busy(), onclick: move |_| dialog.set(None), Icon { name: "x", size: 17 } }
                }
                div { class: "modal-content",
                    if let Some(done) = result.read().as_ref() {
                        div { class: "enroll-result",
                            p { strong { "Certificate installed" } }
                            p { class: "muted small", "Subject: {done.subject}" }
                            p { class: "muted small", "Serial: {done.serial_number}" }
                            p { class: "muted small", "Valid until: {format_unix_date(done.not_after_unix)}" }
                        }
                    } else if busy() {
                        div { class: "enroll-progress",
                            div { class: "spinner" }
                            ol { class: "fips-step-list",
                                for step in STEPS.iter() {
                                    li { key: "{step}", "{step}" }
                                }
                            }
                        }
                    } else if let Some(list) = profiles.as_ref() {
                        if list.is_empty() {
                            p { class: "muted", "No certificate profiles are available for this token." }
                        } else {
                            div { class: "modal-field",
                                label { r#for: "enroll-profile", "Certificate profile" }
                                select {
                                    id: "enroll-profile",
                                    onchange: {
                                        let mut chosen = chosen;
                                        move |event: Event<FormData>| chosen.set(Some(event.value()))
                                    },
                                    for profile in list.iter() {
                                        option {
                                            key: "{profile.name}",
                                            value: "{profile.name}",
                                            selected: selected_name.as_deref() == Some(profile.name.as_str()),
                                            "{profile.display_name} (slot {profile.slot})"
                                        }
                                    }
                                }
                            }
                            div { class: "modal-field",
                                label { r#for: "enroll-pin", if fips { "PIV PIN (8 characters)" } else { "PIV PIN (6-8 characters)" } }
                                input {
                                    id: "enroll-pin",
                                    r#type: "password",
                                    autocomplete: "off",
                                    value: "{pin.read().as_str()}",
                                    oninput: {
                                        let mut pin = pin;
                                        move |event: Event<FormData>| pin.set(Zeroizing::new(event.value()))
                                    },
                                }
                            }
                            if let Some(message) = live_message {
                                div { class: "modal-error", "{message}" }
                            }
                        }
                    } else {
                        div { class: "loading-card",
                            div { class: "spinner" }
                            span { "Loading certificate profiles." }
                        }
                    }
                    if let Some(message) = error.read().as_ref() {
                        div { class: "modal-error", "{message}" }
                    }
                }
                footer { class: "modal-footer",
                    if result.read().is_some() {
                        button { class: "primary-button", onclick: move |_| dialog.set(None), "Done" }
                    } else {
                        button { class: "text-button", disabled: busy(), onclick: move |_| dialog.set(None), "Cancel" }
                        button {
                            class: "primary-button",
                            disabled: !can_submit,
                            onclick: {
                                let id = device.id.clone();
                                let serial = device.serial.clone().unwrap_or_default();
                                let agent = state.managed.clone();
                                let session = state.session.read().clone();
                                let sessions = state.session;
                                let auth_status = state.auth;
                                let service = state.credentials.clone();
                                let info = state.piv_info;
                                let slots = state.piv_slots;
                                let toast = state.toast;
                                let profile_name = selected.as_ref().map(|profile| profile.name.clone()).unwrap_or_default();
                                let mut pin = pin;
                                let mut busy = busy;
                                let mut error = error;
                                move |_| {
                                    if busy() {
                                        return;
                                    }
                                    let (Some(agent), Some(session)) = (agent.clone(), session.clone()) else {
                                        error.set_live(Some("Sign in first to use managed PIV.".into()));
                                        return;
                                    };
                                    let bytes = pin.read().as_bytes().to_vec();
                                    pin.set(Zeroizing::new(String::new()));
                                    let pin_value = match PivPin::new(bytes) {
                                        Ok(value) => value,
                                        Err(value) => {
                                            error.set_live(Some(managed::error_message(&value)));
                                            return;
                                        }
                                    };
                                    busy.set_live(true);
                                    error.set_live(None);
                                    let id = id.clone();
                                    let serial = serial.clone();
                                    let profile_name = profile_name.clone();
                                    let service = service.clone();
                                    let mut info = info;
                                    let mut slots = slots;
                                    let mut toast = toast;
                                    let mut result = result;
                                    let mut busy = busy;
                                    let mut error = error;
                                    std::thread::spawn(move || {
                                        let outcome = managed::fresh_token(&session, sessions, auth_status).and_then(|token| {
                                            agent
                                                .enroll_certificate(&id, &serial, &profile_name, &pin_value, &token)
                                                .map_err(|value| managed::error_message(&value))
                                        });
                                        match outcome {
                                            Ok(enrolled) => {
                                                managed::reload_piv(&service, &id, &mut info, &mut slots);
                                                toast.set_live(Some("Enrolled the certificate.".into()));
                                                result.set_live(Some(enrolled));
                                            }
                                            Err(message) => error.set_live(Some(message)),
                                        }
                                        busy.set_live(false);
                                    });
                                }
                            },
                            if busy() { "Working." } else { "Enroll" }
                        }
                    }
                }
            }
        }
    }
}

/// Formats a Unix timestamp as a UTC calendar date, for example 2023-11-14.
pub fn format_unix_date(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::format_unix_date;

    #[test]
    fn unix_timestamps_format_as_utc_dates() {
        assert_eq!(format_unix_date(0), "1970-01-01");
        assert_eq!(format_unix_date(1_700_000_000), "2023-11-14");
        assert_eq!(format_unix_date(951_782_400), "2000-02-29");
    }
}
