//! Issuer checks on the attestation path: every issuer must be a CA with keyCertSign where KeyUsage is present.

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair, KeyUsagePurpose,
    date_time_ymd,
};
use sigil_yubikey::attestation::{AttestationTrust, inspect, now_unix};
use x509_cert::Certificate;
use x509_cert::der::Decode;

const OID_SERIAL: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 7];
const OID_POLICY: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 8];

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

fn explicit_non_ca(common_name: &str) -> CertificateParams {
    let mut params = params(common_name, false);
    params.is_ca = IsCa::ExplicitNoCa;
    params
}

fn leaf_params() -> CertificateParams {
    let mut params = params("YubiKey PIV Attestation 9A", false);
    params.custom_extensions = vec![
        CustomExtension::from_oid_content(OID_SERIAL, vec![0x02, 0x01, 0x01]),
        CustomExtension::from_oid_content(OID_POLICY, vec![0x02, 0x01]),
    ];
    params
}

fn parse(certificate: &rcgen::Certificate) -> Certificate {
    Certificate::from_der(certificate.der().as_ref()).expect("parse")
}

/// Builds root → intermediate → F9 → leaf with the given parameters for the root, intermediate and F9.
fn hierarchy(
    root: CertificateParams,
    intermediate: CertificateParams,
    f9: CertificateParams,
) -> (
    rcgen::Certificate,
    rcgen::Certificate,
    rcgen::Certificate,
    rcgen::Certificate,
) {
    let root_key = KeyPair::generate().expect("root key");
    let root_cert = root.self_signed(&root_key).expect("root");
    let intermediate_key = KeyPair::generate().expect("intermediate key");
    let intermediate_cert = intermediate
        .signed_by(&intermediate_key, &root_cert, &root_key)
        .expect("intermediate");
    let f9_key = KeyPair::generate().expect("f9 key");
    let f9_cert = f9
        .signed_by(&f9_key, &intermediate_cert, &intermediate_key)
        .expect("f9");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = leaf_params()
        .signed_by(&leaf_key, &f9_cert, &f9_key)
        .expect("leaf");
    (root_cert, intermediate_cert, f9_cert, leaf)
}

fn verification_error(
    root: &rcgen::Certificate,
    intermediate: &rcgen::Certificate,
    f9: &rcgen::Certificate,
    leaf: &rcgen::Certificate,
) -> Option<String> {
    let trust = AttestationTrust::from_parts(vec![parse(root)], vec![parse(intermediate)]);
    let report = inspect(leaf.der().as_ref(), f9.der().as_ref(), &trust, now_unix());
    if report.verified {
        None
    } else {
        report.verification_error
    }
}

#[test]
fn a_chain_with_proper_ca_issuers_verifies() {
    let (root, intermediate, f9, leaf) = hierarchy(
        params("Test Root", true),
        params("Test Intermediate", true),
        params("Yubico PIV Attestation", true),
    );
    assert_eq!(verification_error(&root, &intermediate, &f9, &leaf), None);
}

#[test]
fn an_intermediate_with_explicit_ca_false_is_rejected() {
    let (root, intermediate, f9, leaf) = hierarchy(
        params("Test Root", true),
        explicit_non_ca("Test Intermediate"),
        params("Yubico PIV Attestation", true),
    );
    let error = verification_error(&root, &intermediate, &f9, &leaf).expect("must be rejected");
    assert!(error.contains("not a CA certificate"), "{error}");
}

#[test]
fn an_intermediate_without_the_ca_flag_is_rejected() {
    let (root, intermediate, f9, leaf) = hierarchy(
        params("Test Root", true),
        params("Test Intermediate", false),
        params("Yubico PIV Attestation", true),
    );
    let error = verification_error(&root, &intermediate, &f9, &leaf).expect("must be rejected");
    assert!(
        error.contains("basicConstraints") || error.contains("not a CA certificate"),
        "{error}"
    );
}

#[test]
fn an_intermediate_whose_key_usage_forbids_cert_signing_is_rejected() {
    let mut intermediate = params("Test Intermediate", true);
    intermediate.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let (root, intermediate, f9, leaf) = hierarchy(
        params("Test Root", true),
        intermediate,
        params("Yubico PIV Attestation", true),
    );
    let error = verification_error(&root, &intermediate, &f9, &leaf).expect("must be rejected");
    assert!(error.contains("keyCertSign"), "{error}");
}

#[test]
fn a_slot_f9_certificate_without_the_ca_flag_is_rejected() {
    let (root, intermediate, f9, leaf) = hierarchy(
        params("Test Root", true),
        params("Test Intermediate", true),
        params("Yubico PIV Attestation", false),
    );
    let error = verification_error(&root, &intermediate, &f9, &leaf).expect("must be rejected");
    assert!(
        error.contains("basicConstraints") || error.contains("not a CA certificate"),
        "{error}"
    );
}

#[test]
fn a_root_without_the_ca_flag_is_rejected() {
    let (root, intermediate, f9, leaf) = hierarchy(
        params("Test Root", false),
        params("Test Intermediate", true),
        params("Yubico PIV Attestation", true),
    );
    let error = verification_error(&root, &intermediate, &f9, &leaf).expect("must be rejected");
    assert!(
        error.contains("basicConstraints") || error.contains("not a CA certificate"),
        "{error}"
    );
}
