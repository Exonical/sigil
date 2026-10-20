//! Managed (escrow-backed) PIV actions for the GUI. The agent performs the card operation with
//! backend-released secrets; the GUI supplies only the sign-in access token and user input.

use std::sync::Arc;

use dioxus::prelude::*;
use sigil_auth::{AuthError, Session};
use sigil_connect::{CertificateProfile, ManagedPivAgent};
use sigil_core::{CredentialError, DeviceId, PivInfo, PivKeyConfiguration, PivSlot, PivSlotInfo};
use zeroize::Zeroizing;

use crate::{
    auth::{self, AuthStatus},
    state::{AppState, PivAction, SetLive},
};

/// Managed actions are offered only when the agent is connected and a sign-in session exists.
pub fn ready(state: &AppState) -> bool {
    state.managed.is_some() && state.session.read().is_some()
}

/// Slot actions that take a management key and can run managed.
pub fn slot_action(action: PivAction) -> Option<PivSlot> {
    match action {
        PivAction::GenerateKey(slot)
        | PivAction::ImportCertificate(slot)
        | PivAction::DeleteCertificate(slot)
        | PivAction::DeleteKey(slot) => Some(slot),
        _ => None,
    }
}

pub fn error_message(error: &CredentialError) -> String {
    match error {
        CredentialError::BackendRejected(detail) => {
            format!("The Sigil backend did not allow this: {detail}")
        }
        CredentialError::BackendUnavailable(_) => {
            "The Sigil backend is unavailable. Try again later.".into()
        }
        CredentialError::PivNotFactoryDefault => {
            "This key is not at factory defaults. Reset PIV first, then set up managed PIV.".into()
        }
        CredentialError::ManagedRotationIncomplete(rotation) => format!(
            "Contact an administrator. Rotation {rotation} needs recovery before this key can change again."
        ),
        other => other.to_string(),
    }
}

/// Returns a current access token. When sign-in has expired, ends the session so the UI offers sign-in again.
pub fn fresh_token(
    session: &Session,
    mut sessions: SyncSignal<Option<Arc<Session>>>,
    mut auth_status: SyncSignal<AuthStatus>,
) -> Result<Zeroizing<String>, String> {
    match auth::fresh_token(session) {
        Ok(token) => Ok(token),
        Err(AuthError::SignedOut) => {
            sessions.set_live(None);
            auth_status.set_live(AuthStatus::SignedOut);
            Err("Your sign-in has expired. Sign in again from the navigation bar.".into())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// The managed slot operations that the slot dialog can run.
pub enum SlotOperation {
    GenerateKey(PivKeyConfiguration),
    ImportCertificate(Vec<u8>, Option<Vec<u8>>),
    DeleteCertificate,
    DeleteKey,
}

pub fn run_slot_operation(
    agent: &dyn ManagedPivAgent,
    token: &str,
    id: &DeviceId,
    serial: &str,
    slot: PivSlot,
    operation: SlotOperation,
) -> Result<Option<Vec<u8>>, CredentialError> {
    match operation {
        SlotOperation::GenerateKey(configuration) => agent
            .generate_key(id, serial, configuration, token)
            .map(Some),
        SlotOperation::ImportCertificate(der, expected_public_key) => agent
            .import_certificate(
                id,
                serial,
                slot,
                &der,
                expected_public_key.as_deref(),
                token,
            )
            .map(|()| None),
        SlotOperation::DeleteCertificate => agent
            .delete_certificate(id, serial, slot, token)
            .map(|()| None),
        SlotOperation::DeleteKey => agent.delete_key(id, serial, slot, token).map(|()| None),
    }
}

/// Reloads PIV info and slots after a change, from a background thread.
pub fn reload_piv(
    service: &sigil_app::CredentialService,
    id: &DeviceId,
    info: &mut SyncSignal<Option<(DeviceId, PivInfo)>>,
    slots: &mut SyncSignal<Option<(DeviceId, Vec<PivSlotInfo>)>>,
) {
    if let Ok(value) = service.piv_info(id) {
        info.set_live(Some((id.clone(), value)));
    }
    if let Ok(value) = service.piv_slots(id) {
        slots.set_live(Some((id.clone(), value)));
    }
}

/// Loads the certificate profiles for the selected device. Runs whenever managed mode, the selected device,
/// the sign-in, or the PIV state changes. A failed load publishes an empty list, which hides the enroll shortcut.
pub fn refresh_profiles(state: &AppState) {
    let device = state.current_device().map(|device| device.id);
    let session = state.session.read().clone();
    let _ = state.piv_info.read();
    let mut profiles = state.certificate_profiles;
    let (Some(agent), Some(session), Some(id)) = (state.managed.clone(), session, device) else {
        profiles.set(None);
        return;
    };
    let sessions = state.session;
    let auth_status = state.auth;
    std::thread::spawn(move || {
        let listed = fresh_token(&session, sessions, auth_status)
            .ok()
            .and_then(|token| agent.certificate_profiles(&id, &token).ok())
            .unwrap_or_default();
        profiles.set_live(Some((id, listed)));
    });
}

/// Whether a profile's PIV slot, written as two hex digits, is the given slot.
pub fn profile_matches_slot(profile: &CertificateProfile, slot: PivSlot) -> bool {
    u8::from_str_radix(&profile.slot, 16).ok() == Some(slot.byte())
}

/// The index to preselect: the first profile for the given slot, otherwise the first profile.
pub fn preselected_index(profiles: &[CertificateProfile], slot: Option<PivSlot>) -> usize {
    slot.and_then(|slot| {
        profiles
            .iter()
            .position(|profile| profile_matches_slot(profile, slot))
    })
    .unwrap_or(0)
}

/// The enroll shortcut for an unenrolled key in this slot, if a profile for the selected device targets it.
pub fn enroll_shortcut(state: &AppState, slot: PivSlot) -> Option<CertificateProfile> {
    let device = state.current_device()?.id;
    let profiles = state.certificate_profiles.read();
    let (owner, list) = profiles.as_ref()?;
    if owner != &device {
        return None;
    }
    list.iter()
        .find(|profile| profile_matches_slot(profile, slot))
        .cloned()
}

#[cfg(test)]
mod tests {
    use sigil_core::{CredentialError, PivSlot};

    use super::{preselected_index, profile_matches_slot};
    use sigil_connect::CertificateProfile;

    fn profile(name: &str, slot: &str) -> CertificateProfile {
        CertificateProfile {
            name: name.into(),
            display_name: name.into(),
            slot: slot.into(),
            algorithm: "p256".into(),
            pin_policy: "once".into(),
            touch_policy: "never".into(),
            expected_subject: "alice".into(),
        }
    }

    #[test]
    fn profiles_match_their_slot_by_hex_value() {
        assert!(profile_matches_slot(
            &profile("auth", "9a"),
            PivSlot::AUTHENTICATION
        ));
        assert!(!profile_matches_slot(
            &profile("auth", "9c"),
            PivSlot::AUTHENTICATION
        ));
        assert!(!profile_matches_slot(
            &profile("bad", "zz"),
            PivSlot::AUTHENTICATION
        ));
    }

    #[test]
    fn preselection_prefers_the_slot_match_and_falls_back_to_the_first_profile() {
        let profiles = [profile("signing", "9c"), profile("auth", "9a")];
        assert_eq!(
            preselected_index(&profiles, Some(PivSlot::AUTHENTICATION)),
            1
        );
        assert_eq!(preselected_index(&profiles, None), 0);
        assert_eq!(
            preselected_index(&profiles, Some(PivSlot::retired(1).unwrap())),
            0
        );
    }

    use super::*;
    use crate::state::PivAction;

    #[test]
    fn only_slot_actions_that_take_a_management_key_are_managed_capable() {
        let slot = PivSlot::AUTHENTICATION;
        assert_eq!(slot_action(PivAction::GenerateKey(slot)), Some(slot));
        assert_eq!(slot_action(PivAction::ImportCertificate(slot)), Some(slot));
        assert_eq!(slot_action(PivAction::DeleteCertificate(slot)), Some(slot));
        assert_eq!(slot_action(PivAction::DeleteKey(slot)), Some(slot));
        assert_eq!(slot_action(PivAction::ChangePin), None);
        assert_eq!(slot_action(PivAction::ChangeManagementKey), None);
    }

    #[test]
    fn managed_errors_get_friendly_text_and_other_errors_are_unchanged() {
        assert!(
            error_message(&CredentialError::BackendRejected(
                "not allowed by policy".into()
            ))
            .contains("not allowed by policy")
        );
        assert!(error_message(&CredentialError::PivNotFactoryDefault).contains("Reset PIV first"));
        assert!(
            error_message(&CredentialError::ManagedRotationIncomplete("rot-7".into()))
                .contains("rot-7 needs recovery")
        );
        assert_eq!(
            error_message(&CredentialError::PinComplexity),
            CredentialError::PinComplexity.to_string()
        );
        assert_eq!(
            error_message(&CredentialError::PinIncorrect { remaining: 2 }),
            CredentialError::PinIncorrect { remaining: 2 }.to_string()
        );
    }
}
