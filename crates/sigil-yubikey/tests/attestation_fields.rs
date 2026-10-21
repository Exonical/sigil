//! Field checks an enrollment applies to an inspected attestation, before any certificate is requested.

use sigil_core::{AttestationInspection, PinPolicy, PivSlot, TouchPolicy};
use sigil_yubikey::attestation::{ExpectedAttestation, check_expected};

const SPKI: &[u8] = &[0x30, 0x59, 0x01, 0x02, 0x03];

fn matching() -> AttestationInspection {
    AttestationInspection {
        verified: true,
        verification_error: None,
        attestation_root: Some("Yubico Attestation Root 1".into()),
        attested_serial: Some(39_192_733),
        attested_slot: Some(0x9a),
        firmware: Some("5.7.4".into()),
        pin_policy: Some(0x02),
        touch_policy: Some(0x01),
        subject_public_key_info: Some(SPKI.to_vec()),
    }
}

fn expected() -> ExpectedAttestation<'static> {
    ExpectedAttestation {
        serial: 39_192_733,
        slot: PivSlot::AUTHENTICATION,
        pin_policy: PinPolicy::Once,
        touch_policy: TouchPolicy::Never,
        subject_public_key_info: SPKI,
    }
}

#[test]
fn a_matching_verified_attestation_passes() {
    assert_eq!(check_expected(&matching(), &expected()), Ok(()));
}

#[test]
fn an_unverified_attestation_fails_with_its_reason_before_any_field_is_compared() {
    let inspection = AttestationInspection {
        verified: false,
        verification_error: Some("no trusted Yubico root signs CN=X".into()),
        ..matching()
    };
    let error = check_expected(&inspection, &expected()).unwrap_err();
    assert_eq!(
        error,
        "attestation is not verified: no trusted Yubico root signs CN=X"
    );
}

#[test]
fn a_different_attested_serial_is_rejected() {
    let inspection = AttestationInspection {
        attested_serial: Some(1),
        ..matching()
    };
    assert!(
        check_expected(&inspection, &expected())
            .unwrap_err()
            .contains("does not match the token serial")
    );
}

#[test]
fn a_missing_attested_serial_is_rejected() {
    let inspection = AttestationInspection {
        attested_serial: None,
        ..matching()
    };
    assert!(
        check_expected(&inspection, &expected())
            .unwrap_err()
            .contains("missing")
    );
}

#[test]
fn a_different_slot_is_rejected() {
    let inspection = AttestationInspection {
        attested_slot: Some(0x9c),
        ..matching()
    };
    assert!(
        check_expected(&inspection, &expected())
            .unwrap_err()
            .contains("slot")
    );
}

#[test]
fn a_different_pin_policy_is_rejected() {
    let inspection = AttestationInspection {
        pin_policy: Some(0x03),
        ..matching()
    };
    assert!(
        check_expected(&inspection, &expected())
            .unwrap_err()
            .contains("PIN policy")
    );
}

#[test]
fn a_different_touch_policy_is_rejected() {
    let inspection = AttestationInspection {
        touch_policy: Some(0x02),
        ..matching()
    };
    assert!(
        check_expected(&inspection, &expected())
            .unwrap_err()
            .contains("touch policy")
    );
}

#[test]
fn a_key_other_than_the_generated_key_is_rejected() {
    let inspection = AttestationInspection {
        subject_public_key_info: Some(vec![0xff]),
        ..matching()
    };
    assert!(
        check_expected(&inspection, &expected())
            .unwrap_err()
            .contains("generated key")
    );
}
