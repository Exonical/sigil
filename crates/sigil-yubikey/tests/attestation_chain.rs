//! Attestation chain verification against generated hierarchies, plus a real-device fixture test.

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair, date_time_ymd,
};
use sigil_core::{PinPolicy, PivSlot, TouchPolicy};
use sigil_yubikey::attestation::{
    AttestationTrust, ExpectedAttestation, check_expected, inspect, now_unix, verify_path,
};
use x509_cert::Certificate;
use x509_cert::der::Decode;

const OID_FIRMWARE: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 3];
const OID_SERIAL: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 7];
const OID_POLICY: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 8];

struct Hierarchy {
    root: rcgen::Certificate,
    intermediate: rcgen::Certificate,
    f9: rcgen::Certificate,
    leaf: rcgen::Certificate,
    leaf_key: KeyPair,
    f9_key: KeyPair,
}

fn params(common_name: &str, ca: bool) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = if ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::NoCa
    };
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2099, 1, 1);
    params
}

fn der_integer(value: u64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    let mut out = vec![0x02, bytes.len() as u8];
    out.extend(bytes);
    out
}

fn leaf_params(
    slot_cn: &str,
    serial: u64,
    pin: u8,
    touch: u8,
    not_after_year: i32,
) -> CertificateParams {
    let mut params = params(slot_cn, false);
    params.not_after = date_time_ymd(not_after_year, 1, 1);
    params.custom_extensions = vec![
        CustomExtension::from_oid_content(OID_FIRMWARE, vec![5, 7, 4]),
        CustomExtension::from_oid_content(OID_SERIAL, der_integer(serial)),
        CustomExtension::from_oid_content(OID_POLICY, vec![pin, touch]),
    ];
    params
}

fn hierarchy() -> Hierarchy {
    let root_key = KeyPair::generate().expect("root key");
    let root = params("Test Yubico Root", true)
        .self_signed(&root_key)
        .expect("root");
    let intermediate_key = KeyPair::generate().expect("intermediate key");
    let intermediate = params("Test Yubico Intermediate", true)
        .signed_by(&intermediate_key, &root, &root_key)
        .expect("intermediate");
    let f9_key = KeyPair::generate().expect("f9 key");
    let f9 = params("Yubico PIV Attestation", true)
        .signed_by(&f9_key, &intermediate, &intermediate_key)
        .expect("f9");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = leaf_params("YubiKey PIV Attestation 9A", 39_192_733, 0x02, 0x01, 2099)
        .signed_by(&leaf_key, &f9, &f9_key)
        .expect("leaf");
    Hierarchy {
        root,
        intermediate,
        f9,
        leaf,
        leaf_key,
        f9_key,
    }
}

fn trust(roots: &[&rcgen::Certificate], intermediates: &[&rcgen::Certificate]) -> AttestationTrust {
    let parse = |certificate: &rcgen::Certificate| {
        Certificate::from_der(certificate.der().as_ref()).expect("parse")
    };
    AttestationTrust::from_parts(
        roots.iter().map(|certificate| parse(certificate)).collect(),
        intermediates
            .iter()
            .map(|certificate| parse(certificate))
            .collect(),
    )
}

#[test]
fn generated_hierarchy_verifies_to_its_root_and_reports_the_fields() {
    let h = hierarchy();
    let trust = trust(&[&h.root], &[&h.intermediate]);
    let report = inspect(
        h.leaf.der().as_ref(),
        h.f9.der().as_ref(),
        &trust,
        now_unix(),
    );
    assert!(report.verified, "{:?}", report.verification_error);
    assert_eq!(report.attestation_root.as_deref(), Some("Test Yubico Root"));
    assert_eq!(report.attested_slot.as_deref(), Some("9A"));
    assert_eq!(report.serial, Some(39_192_733));
    assert_eq!(report.firmware.as_deref(), Some("5.7.4"));
    assert_eq!(
        (report.pin_policy, report.touch_policy),
        (Some(0x02), Some(0x01))
    );
}

#[test]
fn a_chain_to_a_different_root_is_rejected() {
    let h = hierarchy();
    let other = hierarchy();
    let trust = trust(&[&other.root], &[&other.intermediate]);
    let report = inspect(
        h.leaf.der().as_ref(),
        h.f9.der().as_ref(),
        &trust,
        now_unix(),
    );
    assert!(!report.verified);
    assert!(
        report
            .verification_error
            .unwrap()
            .contains("no trusted Yubico root")
    );
}

#[test]
fn a_broken_signature_is_rejected() {
    let h = hierarchy();
    let trust = trust(&[&h.root], &[&h.intermediate]);
    let mut leaf = h.leaf.der().as_ref().to_vec();
    let last = leaf.len() - 1;
    leaf[last] ^= 0x01;
    let report = inspect(&leaf, h.f9.der().as_ref(), &trust, now_unix());
    assert!(!report.verified);
    assert!(report.verification_error.is_some());
}

#[test]
fn an_expired_attestation_is_rejected() {
    let h = hierarchy();
    let trust = trust(&[&h.root], &[&h.intermediate]);
    let expired = leaf_params("YubiKey PIV Attestation 9A", 1, 0x02, 0x01, 2021)
        .signed_by(&h.leaf_key, &h.f9, &h.f9_key)
        .expect("expired leaf");
    let report = inspect(
        expired.der().as_ref(),
        h.f9.der().as_ref(),
        &trust,
        now_unix(),
    );
    assert!(!report.verified);
    assert!(report.verification_error.unwrap().contains("expired"));
}

#[test]
fn the_embedded_roots_contain_no_intermediates() {
    let trust = AttestationTrust::embedded().expect("embedded trust");
    let subjects = trust.root_subjects();
    assert_eq!(subjects.len(), 2, "{subjects:?}");
    assert!(
        subjects
            .iter()
            .all(|subject| !subject.contains("Intermediate")
                && !subject.contains("Attestation 1")
                && !subject.contains("PIV Attestation")),
        "{subjects:?}"
    );
    assert!(subjects.contains(&"Yubico Attestation Root 1".to_owned()));
}
#[test]
fn an_intermediate_in_the_pool_does_not_stand_in_for_a_root() {
    let h = hierarchy();
    let pool_only = trust(&[], &[&h.intermediate]);
    let report = inspect(
        h.leaf.der().as_ref(),
        h.f9.der().as_ref(),
        &pool_only,
        now_unix(),
    );
    assert!(!report.verified);
}

#[test]
fn a_leaf_signed_by_an_unrelated_key_is_rejected() {
    // The leaf names the F9 certificate as its issuer but is signed by another key, so the signature fails.
    let h = hierarchy();
    let trust = trust(&[&h.root], &[&h.intermediate]);
    let stranger_key = KeyPair::generate().expect("stranger");
    let forged = leaf_params("YubiKey PIV Attestation 9A", 1, 0x02, 0x01, 2099)
        .signed_by(&h.leaf_key, &h.f9, &stranger_key)
        .expect("forged");
    let report = inspect(
        forged.der().as_ref(),
        h.f9.der().as_ref(),
        &trust,
        now_unix(),
    );
    assert!(!report.verified);
}

#[test]
fn the_slot_certificate_must_itself_chain_to_the_root() {
    let h = hierarchy();
    let other = hierarchy();
    let trust = trust(&[&h.root], &[&h.intermediate]);
    // The leaf is from one hierarchy, but the F9 certificate is from another: the path cannot reach h.root.
    let report = inspect(
        h.leaf.der().as_ref(),
        other.f9.der().as_ref(),
        &trust,
        now_unix(),
    );
    assert!(!report.verified);
}

#[test]
fn an_inspected_attestation_passes_the_enrollment_check_only_for_what_it_attests() {
    let h = hierarchy();
    let trust = trust(&[&h.root], &[&h.intermediate]);
    let inspection = inspect(
        h.leaf.der().as_ref(),
        h.f9.der().as_ref(),
        &trust,
        now_unix(),
    )
    .into_inspection();
    let spki = h.leaf_key.public_key_der();
    let expected = ExpectedAttestation {
        serial: 39_192_733,
        slot: PivSlot::AUTHENTICATION,
        pin_policy: PinPolicy::Once,
        touch_policy: TouchPolicy::Never,
        subject_public_key_info: &spki,
    };
    assert_eq!(check_expected(&inspection, &expected), Ok(()));
    assert!(
        check_expected(
            &inspection,
            &ExpectedAttestation {
                serial: 1,
                ..expected
            }
        )
        .unwrap_err()
        .contains("attested serial")
    );
    assert!(
        check_expected(
            &inspection,
            &ExpectedAttestation {
                pin_policy: PinPolicy::Always,
                ..expected
            }
        )
        .unwrap_err()
        .contains("PIN policy")
    );
}

#[test]
fn verify_path_reports_the_root_subject_for_a_leaf_issued_under_the_pool() {
    let h = hierarchy();
    let trust = trust(&[&h.root], &[&h.intermediate]);
    let leaf = Certificate::from_der(h.f9.der().as_ref()).expect("f9 as leaf");
    let root = verify_path(&leaf, &[], &trust, now_unix()).expect("f9 chains to the test root");
    assert_eq!(root, "Test Yubico Root");
}

/// Real-device fixture. Set SIGIL_ATTEST_FIXTURE_DIR to a directory containing `f9-attestation.der`, exported
/// read-only from the device with `cms --direct piv certificate export <device> f9 --format der`.
/// Without the variable the test returns immediately.
#[test]
fn real_f9_certificate_chains_to_the_embedded_yubico_root() {
    let Ok(directory) = std::env::var("SIGIL_ATTEST_FIXTURE_DIR") else {
        eprintln!(
            "SIGIL_ATTEST_FIXTURE_DIR is not set; skipping the real-device attestation fixture"
        );
        return;
    };
    let der = std::fs::read(std::path::Path::new(&directory).join("f9-attestation.der"))
        .expect("fixture file");
    let certificate = Certificate::from_der(&der).expect("real F9 certificate parses");
    let trust = AttestationTrust::embedded().expect("embedded trust");
    let root = verify_path(&certificate, &[], &trust, now_unix())
        .expect("real F9 certificate chains to a Yubico root");
    assert_eq!(root, "Yubico Attestation Root 1");
}
