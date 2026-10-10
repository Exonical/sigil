//! PIV attestation chain verification.
//!
//! A slot attestation certificate is signed by the slot F9 attestation certificate. F9 is signed by a Yubico
//! intermediate, and that intermediate by a Yubico root. Verification builds that path and checks every
//! signature and validity period at the current time. The intermediates are a pool used to build the path and are
//! never trust anchors: a path counts only if it ends at one of the embedded roots.
//!
//! The certificates are the files in `backend/internal/attestation/roots/`, included at compile time, so the
//! backend and the agent share one copy. Sources: https://developers.yubico.com/PKI/ (see docs/attestation-roots.md).
//!
//! Subject and extension formats follow Yubico's PIV attestation documentation: the attestation subject names the
//! attested slot, for example "YubiKey PIV Attestation 9A" (the documentation uses uppercase; both cases are
//! accepted). The extension OIDs under 1.3.6.1.4.1.41482.3 are firmware (.3), serial (.7) and usage policy (.8).

use std::time::{SystemTime, UNIX_EPOCH};

use der::{Decode, DecodePem, Encode};
use sha2_legacy::{Digest, Sha256, Sha384, Sha512};
use sigil_core::{CredentialError, Result};
use x509_cert::Certificate;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

const ROOT_PIV_CA_1: &str =
    include_str!("../../../backend/internal/attestation/roots/yubico-piv-ca-1.pem");
const ROOT_ATTESTATION_1: &str =
    include_str!("../../../backend/internal/attestation/roots/yubico-ca-1.pem");
const INTERMEDIATES: &str =
    include_str!("../../../backend/internal/attestation/roots/yubico-intermediate.pem");

const MAX_PATH_LENGTH: usize = 5;

const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512: &str = "1.2.840.113549.1.1.13";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_CURVE_P256: &str = "1.2.840.10045.3.1.7";
const OID_CURVE_P384: &str = "1.3.132.0.34";

/// Trust for attestation chains: the Yubico roots (anchors) and the Yubico intermediates (a pool only).
pub struct AttestationTrust {
    roots: Vec<Certificate>,
    intermediates: Vec<Certificate>,
}

impl AttestationTrust {
    /// The roots and intermediates compiled into this build.
    pub fn embedded() -> Result<Self> {
        let mut roots = parse_pem_chain(ROOT_PIV_CA_1)?;
        roots.extend(parse_pem_chain(ROOT_ATTESTATION_1)?);
        Ok(Self {
            roots,
            intermediates: parse_pem_chain(INTERMEDIATES)?,
        })
    }

    /// Subject names of the trust anchors, for checks on what the build embeds.
    pub fn root_subjects(&self) -> Vec<String> {
        self.roots
            .iter()
            .map(|root| common_name(root.tbs_certificate().subject()))
            .collect()
    }

    /// Trust built from explicit certificates. Used by tests with generated hierarchies.
    pub fn from_parts(roots: Vec<Certificate>, intermediates: Vec<Certificate>) -> Self {
        Self {
            roots,
            intermediates,
        }
    }
}

/// What an attestation inspection found. A failed chain does not stop the parsed fields from being reported.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttestationReport {
    pub verified: bool,
    pub verification_error: Option<String>,
    /// Subject common name of the Yubico root the chain ends at, when verified.
    pub attestation_root: Option<String>,
    /// The attested slot from the subject, for example "9A" or "9a".
    pub attested_slot: Option<String>,
    pub serial: Option<u64>,
    pub firmware: Option<String>,
    pub pin_policy: Option<u8>,
    pub touch_policy: Option<u8>,
}

/// Verifies `attestation` against `trust`, using `slot_certificate` (F9) and the trust intermediates to build the path.
pub fn inspect(
    attestation_der: &[u8],
    slot_certificate_der: &[u8],
    trust: &AttestationTrust,
    now_unix: u64,
) -> AttestationReport {
    let mut report = AttestationReport::default();
    let leaf = match Certificate::from_der(attestation_der) {
        Ok(leaf) => leaf,
        Err(error) => {
            report.verification_error =
                Some(format!("attestation certificate is not valid DER: {error}"));
            return report;
        }
    };
    parse_fields(&leaf, &mut report);
    let slot_certificate = match Certificate::from_der(slot_certificate_der) {
        Ok(certificate) => certificate,
        Err(error) => {
            report.verification_error =
                Some(format!("slot F9 certificate is not valid DER: {error}"));
            return report;
        }
    };
    match verify_path(
        &leaf,
        std::slice::from_ref(&slot_certificate),
        trust,
        now_unix,
    ) {
        Ok(root) => {
            report.verified = true;
            report.attestation_root = Some(root);
        }
        Err(error) => report.verification_error = Some(error),
    }
    report
}

/// Verifies a leaf certificate against the pool and the trusted roots, and returns the root subject it reaches.
/// `extra_intermediates` are added to the pool for this check only. Used for the slot F9 certificate.
pub fn verify_path(
    leaf: &Certificate,
    extra_intermediates: &[Certificate],
    trust: &AttestationTrust,
    now_unix: u64,
) -> std::result::Result<String, String> {
    check_validity(leaf, now_unix, "attestation certificate")?;
    let mut pool: Vec<&Certificate> = trust.intermediates.iter().collect();
    pool.extend(extra_intermediates.iter());
    let mut current = leaf;
    for _ in 0..MAX_PATH_LENGTH {
        let issuer_name = current.tbs_certificate().issuer().to_string();
        // Prefer a trusted root, then a pool intermediate. A candidate must sign the current certificate.
        let mut candidates: Vec<&Certificate> = trust.roots.iter().collect();
        candidates.extend(pool.iter().copied());
        let mut next = None;
        for candidate in candidates {
            if candidate.tbs_certificate().subject().to_string() != issuer_name {
                continue;
            }
            if verify_signature(
                current,
                candidate.tbs_certificate().subject_public_key_info(),
            )
            .is_err()
            {
                continue;
            }
            check_validity(candidate, now_unix, "issuer certificate")?;
            if is_root(candidate, trust) {
                return Ok(common_name(candidate.tbs_certificate().subject()));
            }
            next = Some(candidate);
            break;
        }
        match next {
            Some(issuer) => current = issuer,
            None => return Err(format!("no trusted Yubico root signs {issuer_name}")),
        }
    }
    Err("attestation chain is longer than the allowed depth".into())
}

fn is_root(certificate: &Certificate, trust: &AttestationTrust) -> bool {
    let Ok(der) = certificate.to_der() else {
        return false;
    };
    trust
        .roots
        .iter()
        .any(|root| root.to_der().is_ok_and(|root_der| root_der == der))
}

fn check_validity(
    certificate: &Certificate,
    now_unix: u64,
    label: &str,
) -> std::result::Result<(), String> {
    let validity = certificate.tbs_certificate().validity();
    let not_before = validity.not_before.to_unix_duration().as_secs();
    let not_after = validity.not_after.to_unix_duration().as_secs();
    if now_unix < not_before {
        return Err(format!("{label} is not valid yet"));
    }
    if now_unix > not_after {
        return Err(format!("{label} has expired"));
    }
    Ok(())
}

/// Checks the signature of `certificate` with the issuer's public key. RSA PKCS#1 v1.5 (SHA-256/384/512) and
/// ECDSA P-256/P-384 (SHA-256/384) are supported, which covers the Yubico chains.
pub fn verify_signature(
    certificate: &Certificate,
    issuer_key: &SubjectPublicKeyInfoOwned,
) -> std::result::Result<(), String> {
    let tbs = certificate
        .tbs_certificate()
        .to_der()
        .map_err(|error| error.to_string())?;
    let signature = certificate.signature().raw_bytes();
    let algorithm = certificate.signature_algorithm().oid.to_string();
    let key_der = issuer_key.to_der().map_err(|error| error.to_string())?;
    match algorithm.as_str() {
        OID_RSA_SHA256 => verify_rsa(&key_der, &tbs, signature, RsaHash::Sha256),
        OID_RSA_SHA384 => verify_rsa(&key_der, &tbs, signature, RsaHash::Sha384),
        OID_RSA_SHA512 => verify_rsa(&key_der, &tbs, signature, RsaHash::Sha512),
        OID_ECDSA_SHA256 => verify_ecdsa(
            issuer_key,
            &key_der,
            signature,
            Sha256::digest(&tbs).to_vec(),
        ),
        OID_ECDSA_SHA384 => verify_ecdsa(
            issuer_key,
            &key_der,
            signature,
            Sha384::digest(&tbs).to_vec(),
        ),
        other => Err(format!("unsupported signature algorithm {other}")),
    }
}

#[derive(Clone, Copy)]
enum RsaHash {
    Sha256,
    Sha384,
    Sha512,
}

fn verify_rsa(
    key_der: &[u8],
    tbs: &[u8],
    signature: &[u8],
    hash: RsaHash,
) -> std::result::Result<(), String> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    let key = rsa::RsaPublicKey::from_public_key_der(key_der).map_err(|error| error.to_string())?;
    let signature = Signature::try_from(signature).map_err(|error| error.to_string())?;
    let outcome = match hash {
        RsaHash::Sha256 => VerifyingKey::<Sha256>::new(key).verify(tbs, &signature),
        RsaHash::Sha384 => VerifyingKey::<Sha384>::new(key).verify(tbs, &signature),
        RsaHash::Sha512 => VerifyingKey::<Sha512>::new(key).verify(tbs, &signature),
    };
    outcome.map_err(|_| "RSA signature does not verify".to_owned())
}
fn verify_ecdsa(
    issuer_key: &SubjectPublicKeyInfoOwned,
    key_der: &[u8],
    signature: &[u8],
    digest: Vec<u8>,
) -> std::result::Result<(), String> {
    use x509_cert::spki::ObjectIdentifier;
    let algorithm = issuer_key.algorithm.oid.to_string();
    if algorithm != OID_EC_PUBLIC_KEY {
        return Err("issuer key is not an EC key".into());
    }
    let parameters = issuer_key
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| "EC key has no curve".to_owned())?;
    let curve: ObjectIdentifier = parameters
        .decode_as()
        .map_err(|error: der::Error| error.to_string())?;
    match curve.to_string().as_str() {
        OID_CURVE_P256 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            use p256::pkcs8::DecodePublicKey;
            let key = p256::ecdsa::VerifyingKey::from_public_key_der(key_der)
                .map_err(|error| error.to_string())?;
            let signature = p256::ecdsa::DerSignature::try_from(signature)
                .map_err(|error| error.to_string())?;
            key.verify_prehash(&digest, &signature)
                .map_err(|_| "ECDSA signature does not verify".to_owned())
        }
        OID_CURVE_P384 => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            use p384::pkcs8::DecodePublicKey;
            let key = p384::ecdsa::VerifyingKey::from_public_key_der(key_der)
                .map_err(|error| error.to_string())?;
            let signature = p384::ecdsa::DerSignature::try_from(signature)
                .map_err(|error| error.to_string())?;
            key.verify_prehash(&digest, &signature)
                .map_err(|_| "ECDSA signature does not verify".to_owned())
        }
        other => Err(format!("unsupported EC curve {other}")),
    }
}

fn parse_fields(leaf: &Certificate, report: &mut AttestationReport) {
    report.attested_slot = common_name(leaf.tbs_certificate().subject())
        .strip_prefix("YubiKey PIV Attestation ")
        .map(str::to_owned);
    let Some(extensions) = leaf.tbs_certificate().extensions() else {
        return;
    };
    for extension in extensions {
        let value = extension.extn_value.as_bytes();
        match extension.extn_id.to_string().as_str() {
            "1.3.6.1.4.1.41482.3.3" => {
                let bytes = payload(value);
                report.firmware = Some(format!(
                    "{}.{}.{}",
                    bytes.first().copied().unwrap_or(0),
                    bytes.get(1).copied().unwrap_or(0),
                    bytes.get(2).copied().unwrap_or(0)
                ));
            }
            "1.3.6.1.4.1.41482.3.7" => report.serial = unsigned_integer(value),
            "1.3.6.1.4.1.41482.3.8" => {
                let bytes = payload(value);
                report.pin_policy = bytes.first().copied();
                report.touch_policy = bytes.get(1).copied();
            }
            _ => {}
        }
    }
}

/// The extension payload. Yubico encodes firmware and policy as raw bytes; a DER OCTET STRING wrapper is accepted too.
fn payload(value: &[u8]) -> Vec<u8> {
    match x509_cert::der::asn1::OctetString::from_der(value) {
        Ok(octets) => octets.as_bytes().to_vec(),
        Err(_) => value.to_vec(),
    }
}

fn unsigned_integer(bytes: &[u8]) -> Option<u64> {
    if let Ok(integer) = x509_cert::der::asn1::Uint::from_der(bytes) {
        return bytes_to_u64(integer.as_bytes());
    }
    bytes_to_u64(bytes)
}

fn bytes_to_u64(bytes: &[u8]) -> Option<u64> {
    bytes.iter().try_fold(0u64, |value, byte| {
        value.checked_mul(256)?.checked_add(u64::from(*byte))
    })
}

fn common_name(name: &x509_cert::name::Name) -> String {
    name.to_string()
        .split(',')
        .find_map(|part| part.trim().strip_prefix("CN=").map(str::to_owned))
        .unwrap_or_default()
}

fn parse_pem_chain(text: &str) -> Result<Vec<Certificate>> {
    let mut out = Vec::new();
    for block in text
        .split("-----END CERTIFICATE-----")
        .filter(|block| block.contains("-----BEGIN CERTIFICATE-----"))
    {
        let pem = format!("{block}-----END CERTIFICATE-----\n");
        out.push(
            Certificate::from_pem(pem.as_bytes())
                .map_err(|error| CredentialError::CertificateParse(error.to_string()))?,
        );
    }
    if out.is_empty() {
        return Err(CredentialError::CertificateParse(
            "no embedded attestation certificates".into(),
        ));
    }
    Ok(out)
}

/// Current Unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
