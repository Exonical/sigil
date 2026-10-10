use crate::attestation::{self, AttestationTrust};
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey,
    signature::hazmat::PrehashVerifier,
};
use p256::pkcs8::DecodePublicKey;
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use rsa::{
    pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey},
    pkcs8::DecodePublicKey as RsaDecodePublicKey,
    signature::hazmat::PrehashVerifier as RsaPrehashVerifier,
};
use sha2::{Digest, Sha256, Sha384};
use sha2_legacy::Digest as LegacyDigest;
use sigil_core::{
    CredentialError, FirmwareVersion, KeyOrigin, KeyStatus, ManagementKey, ManagementKeyAlgorithm,
    ManagementKeyStatus, PinPolicy, PivAlgorithm, PivAttestation, PivInfo, PivKeyMetadata, PivPin,
    PivPuk, PivSlot, PivSlotInfo, Result, RetryStatus, TouchPolicy,
};
use sigil_piv::{
    CardTransport, management, pin_retries, read_certificate as read_certificate_data, select,
    summarize_certificate, transceive,
};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

const YUBICO_SERIAL_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.7");
const YUBICO_POLICY_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");
const OID_ECDSA_WITH_SHA256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_WITH_SHA384: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_RSA_WITH_SHA256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_WITH_SHA384: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YubiKeyMetadata {
    pub algorithm: Option<PivAlgorithm>,
    pub pin_policy: Option<PinPolicy>,
    pub touch_policy: Option<TouchPolicy>,
    pub origin: Option<KeyOrigin>,
    pub default_value: Option<bool>,
    pub retries: Option<(u8, u8)>,
}

pub fn algorithm_from_yubikey_id(id: u8) -> PivAlgorithm {
    match id {
        0x06 => PivAlgorithm::Rsa1024,
        0x07 => PivAlgorithm::Rsa2048,
        0x05 => PivAlgorithm::Rsa3072,
        0x16 => PivAlgorithm::Rsa4096,
        0x11 => PivAlgorithm::EccP256,
        0x14 => PivAlgorithm::EccP384,
        0xe0 => PivAlgorithm::Ed25519,
        0xe1 => PivAlgorithm::X25519,
        0x03 => PivAlgorithm::Tdes,
        0x08 => PivAlgorithm::Aes128,
        0x0a => PivAlgorithm::Aes192,
        0x0c => PivAlgorithm::Aes256,
        other => PivAlgorithm::Unknown(other),
    }
}

pub fn parse_metadata(encoded: &[u8]) -> Result<YubiKeyMetadata> {
    let fields = sigil_piv::tlv::parse(encoded)
        .map_err(|error| CredentialError::SmartCardOperation(error.to_string()))?;
    let field = |tag| {
        fields
            .iter()
            .find(|(candidate, _)| *candidate == tag)
            .map(|(_, v)| v.as_slice())
    };
    let algorithm = field(0x01)
        .and_then(|value| value.first())
        .copied()
        .map(algorithm_from_yubikey_id);
    let (pin_policy, touch_policy) = match field(0x02) {
        Some([pin, touch, ..]) => (decode_pin_policy(*pin), decode_touch_policy(*touch)),
        _ => (None, None),
    };
    let origin = field(0x03).and_then(|value| match value.first().copied() {
        Some(1) => Some(KeyOrigin::Generated),
        Some(2) => Some(KeyOrigin::Imported),
        _ => None,
    });
    let default_value = field(0x05)
        .and_then(|value| value.first())
        .map(|value| *value != 0);
    let retries = field(0x06).and_then(|value| (value.len() >= 2).then(|| (value[0], value[1])));
    Ok(YubiKeyMetadata {
        algorithm,
        pin_policy,
        touch_policy,
        origin,
        default_value,
        retries,
    })
}

fn decode_pin_policy(value: u8) -> Option<PinPolicy> {
    match value {
        0 => Some(PinPolicy::Default),
        1 => Some(PinPolicy::Never),
        2 => Some(PinPolicy::Once),
        3 => Some(PinPolicy::Always),
        4 => Some(PinPolicy::MatchOnce),
        5 => Some(PinPolicy::MatchAlways),
        _ => None,
    }
}

fn decode_touch_policy(value: u8) -> Option<TouchPolicy> {
    match value {
        0 => Some(TouchPolicy::Default),
        1 => Some(TouchPolicy::Never),
        2 => Some(TouchPolicy::Always),
        3 => Some(TouchPolicy::Cached),
        _ => None,
    }
}

pub fn metadata<T: CardTransport>(
    transport: &mut T,
    key_ref: u8,
) -> Result<Option<YubiKeyMetadata>> {
    let (data, sw) = transceive(transport, &[0x00, 0xf7, 0x00, key_ref])?;
    match sw {
        0x9000 => parse_metadata(&data).map(Some),
        0x6a82 | 0x6a88 => Ok(None),
        0x6d00 | 0x6e00 => Ok(None),
        other => Err(CredentialError::CardStatus(other)),
    }
}

pub fn version<T: CardTransport>(transport: &mut T) -> Result<Option<FirmwareVersion>> {
    let (data, sw) = transceive(transport, &[0x00, 0xfd, 0x00, 0x00])?;
    match sw {
        0x6d00 | 0x6e00 => Ok(None),
        0x9000 if data.len() == 3 => Ok(Some(FirmwareVersion {
            major: data[0],
            minor: data[1],
            patch: data[2],
        })),
        0x9000 => Err(CredentialError::SmartCardOperation(
            "YubiKey version response must contain three bytes".into(),
        )),
        other => Err(CredentialError::CardStatus(other)),
    }
}

pub fn serial<T: CardTransport>(transport: &mut T) -> Result<Option<u32>> {
    select(transport)?;
    serial_selected(transport)
}

fn serial_selected<T: CardTransport>(transport: &mut T) -> Result<Option<u32>> {
    let (data, sw) = transceive(transport, &[0x00, 0xf8, 0x00, 0x00])?;
    match sw {
        0x6d00 | 0x6e00 => Ok(None),
        0x9000 if data.len() == 4 => Ok(Some(u32::from_be_bytes(data.try_into().unwrap()))),
        0x9000 => Err(CredentialError::SmartCardOperation(
            "YubiKey serial response must contain four bytes".into(),
        )),
        other => Err(CredentialError::CardStatus(other)),
    }
}

pub fn slot_key_status<T: CardTransport>(transport: &mut T, slot: PivSlot) -> Result<KeyStatus> {
    let (data, sw) = transceive(transport, &[0x00, 0xf7, 0x00, slot.byte()])?;
    match sw {
        0x6a82 | 0x6a88 => Ok(KeyStatus::Absent),
        0x6d00 | 0x6e00 => Ok(KeyStatus::Unknown),
        0x9000 => {
            let value = parse_metadata(&data)?;
            Ok(KeyStatus::Present(PivKeyMetadata {
                algorithm: value.algorithm.unwrap_or(PivAlgorithm::Unknown(0)),
                pin_policy: value.pin_policy.unwrap_or(PinPolicy::Default),
                touch_policy: value.touch_policy.unwrap_or(TouchPolicy::Default),
                origin: value.origin,
            }))
        }
        other => Err(CredentialError::CardStatus(other)),
    }
}

pub fn retry_status<T: CardTransport>(
    transport: &mut T,
    key_ref: u8,
) -> Result<Option<RetryStatus>> {
    let Some(value) = metadata(transport, key_ref)? else {
        return Ok(None);
    };
    Ok(value.retries.map(|(total, remaining)| RetryStatus {
        remaining,
        total: Some(total),
        default_value: value.default_value,
    }))
}

pub fn management_key_status<T: CardTransport>(
    transport: &mut T,
) -> Result<Option<ManagementKeyStatus>> {
    let Some(value) = metadata(transport, 0x9b)? else {
        return Ok(None);
    };
    Ok(value.algorithm.map(|algorithm| ManagementKeyStatus {
        algorithm,
        default_value: value.default_value,
        touch_policy: value.touch_policy,
    }))
}

pub fn read_info<T: CardTransport>(transport: &mut T) -> Result<PivInfo> {
    select(transport)?;
    let version = version(transport)?;
    let pin = match retry_status(transport, 0x80)? {
        Some(value) => Some(value),
        None => pin_retries(transport)?.map(|remaining| RetryStatus {
            remaining,
            total: None,
            default_value: None,
        }),
    };
    let puk = retry_status(transport, 0x81)?;
    let management_key = management_key_status(transport)?;
    Ok(PivInfo {
        version,
        pin,
        puk,
        management_key,
    })
}

pub fn read_slots<T: CardTransport>(transport: &mut T) -> Result<Vec<PivSlotInfo>> {
    select(transport)?;
    let mut slots = PivSlot::STANDARD.to_vec();
    slots.extend(PivSlot::retired_slots());
    slots.push(PivSlot::ATTESTATION);
    let mut entries = Vec::new();
    for slot in slots {
        let (certificate_present, certificate) = match read_certificate_data(transport, slot) {
            Ok(Some(bytes)) => match summarize_certificate(&bytes) {
                Ok(summary) => (true, Some(summary)),
                Err(error @ CredentialError::CertificateParse(_)) => {
                    tracing::warn!(slot = %slot, %error, "could not parse PIV slot certificate");
                    (true, None)
                }
                Err(error) => return Err(error),
            },
            Ok(None) => (false, None),
            Err(error @ CredentialError::CertificateParse(_)) => {
                tracing::warn!(slot = %slot, %error, "could not parse PIV slot certificate");
                (true, None)
            }
            Err(error) => return Err(error),
        };
        let key = slot_key_status(transport, slot)?;
        let is_standard = PivSlot::STANDARD.contains(&slot);
        if !is_standard && !certificate_present && !matches!(key, KeyStatus::Present(_)) {
            continue;
        }
        entries.push(PivSlotInfo {
            slot,
            certificate,
            key,
        });
    }
    Ok(entries)
}

pub fn read_certificate<T: CardTransport>(
    transport: &mut T,
    slot: PivSlot,
) -> Result<Option<sigil_core::PivCertificate>> {
    select(transport)?;
    let Some(der) = read_certificate_data(transport, slot)? else {
        return Ok(None);
    };
    let summary = summarize_certificate(&der)?;
    Ok(Some(sigil_core::PivCertificate { slot, summary, der }))
}

pub fn verify_serial<T: CardTransport>(transport: &mut T, expected: &str) -> Result<()> {
    verify_expected_serial(transport, expected)
}

pub fn verify_expected_serial<T: CardTransport>(
    transport: &mut T,
    expected_serial: &str,
) -> Result<()> {
    read_expected_serial(transport, expected_serial).map(|_| ())
}

pub fn read_expected_serial<T: CardTransport>(
    transport: &mut T,
    expected_serial: &str,
) -> Result<String> {
    select(transport)?;
    let actual = serial_selected(transport)?
        .ok_or(CredentialError::DeviceMismatch)?
        .to_string();
    if expected_serial.is_empty() || actual != expected_serial {
        return Err(CredentialError::DeviceMismatch);
    }
    Ok(actual)
}

pub fn set_management_key_selected<T: CardTransport>(
    transport: &mut T,
    new_key: &ManagementKey,
) -> Result<()> {
    let algorithm = match new_key.algorithm() {
        ManagementKeyAlgorithm::Aes128 => 0x08,
        ManagementKeyAlgorithm::Aes192 => 0x0a,
        ManagementKeyAlgorithm::Aes256 => 0x0c,
    };
    let key = new_key.as_bytes();
    let mut command = zeroize::Zeroizing::new(vec![
        0x00,
        0xff,
        0xff,
        0xff,
        (3 + key.len()) as u8,
        algorithm,
        0x9b,
        key.len() as u8,
    ]);
    command.extend_from_slice(key);
    let (_, status) = transceive(transport, command.as_slice())?;
    match status {
        0x9000 => Ok(()),
        0x6982 => Err(CredentialError::ManagementKeyIncorrect),
        other => Err(CredentialError::CardStatus(other)),
    }
}

pub fn change_management_key<T: CardTransport>(
    transport: &mut T,
    current: &ManagementKey,
    new_key: &ManagementKey,
) -> Result<()> {
    select(transport)?;
    management::authenticate_management_key_selected(transport, current)?;
    set_management_key_selected(transport, new_key)?;
    management::authenticate_management_key_selected(transport, new_key)
}

pub fn attest_selected<T: CardTransport>(
    transport: &mut T,
    slot: PivSlot,
) -> Result<PivAttestation> {
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "the attestation slot cannot attest itself".into(),
        ));
    }
    let (attestation_der, status) = transceive(transport, &[0x00, 0xf9, slot.byte(), 0x00])?;
    if status != 0x9000 {
        return Err(CredentialError::CardStatus(status));
    }
    let object = management::read_data_object_selected(transport, &[0x5f, 0xff, 0x01])?.ok_or(
        CredentialError::CertificateNotFound(PivSlot::ATTESTATION.to_string()),
    )?;
    let intermediate_der = certificate_from_object(&object)?;
    Ok(PivAttestation {
        attestation_der,
        intermediate_der,
    })
}

pub fn attest<T: CardTransport>(transport: &mut T, slot: PivSlot) -> Result<PivAttestation> {
    select(transport)?;
    attest_selected(transport, slot)
}

pub fn delete_key_selected<T: CardTransport>(transport: &mut T, slot: PivSlot) -> Result<()> {
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "slot F9 is reserved for the YubiKey attestation key".into(),
        ));
    }
    let firmware = version(transport)?;
    if !firmware.is_some_and(|version| (version.major, version.minor) >= (5, 7)) {
        return Err(CredentialError::UnsupportedOperation(
            "PIV key deletion requires firmware 5.7 or later".into(),
        ));
    }
    let (_, status) = transceive(transport, &[0x00, 0xf6, 0xff, slot.byte()])?;
    if status == 0x9000 {
        Ok(())
    } else {
        Err(CredentialError::CardStatus(status))
    }
}

pub fn reset_piv<T: CardTransport>(transport: &mut T) -> Result<()> {
    select(transport)?;
    reset_piv_selected(transport)
}

pub fn reset_piv_selected<T: CardTransport>(transport: &mut T) -> Result<()> {
    block_pin(transport)?;
    block_puk(transport)?;
    let (_, status) = transceive(transport, &[0x00, 0xfb, 0x00, 0x00])?;
    if status == 0x9000 {
        Ok(())
    } else {
        Err(CredentialError::CardStatus(status))
    }
}

fn block_pin<T: CardTransport>(transport: &mut T) -> Result<()> {
    let mut remaining = retry_status(transport, 0x80)?
        .ok_or_else(|| CredentialError::SmartCardOperation("PIN retries are unavailable".into()))?
        .remaining;
    if remaining > 16 {
        return Err(CredentialError::SmartCardOperation(
            "PIN retry count exceeds the reset safety limit".into(),
        ));
    }
    for _ in 0..16 {
        if remaining == 0 {
            return Ok(());
        }
        let wrong_pin = PivPin::new(random_code()?)?;
        match sigil_piv::management::verify_pin_selected(transport, &wrong_pin) {
            Err(CredentialError::PinIncorrect {
                remaining: reported,
            }) => {
                if reported != remaining.saturating_sub(1) {
                    return Err(CredentialError::SmartCardOperation(
                        "PIN retry count did not decrease by exactly one".into(),
                    ));
                }
                remaining = reported;
            }
            Err(CredentialError::PinBlocked) => {
                if remaining != 1
                    || retry_status(transport, 0x80)?.is_none_or(|value| value.remaining != 0)
                {
                    return Err(CredentialError::SmartCardOperation(
                        "PIN became blocked with an unexpected retry count".into(),
                    ));
                }
                return Ok(());
            }
            Ok(()) => {
                return Err(CredentialError::SmartCardOperation(
                    "random PIN reset challenge unexpectedly succeeded".into(),
                ));
            }
            Err(error) => return Err(error),
        }
    }
    Err(CredentialError::SmartCardOperation(
        "PIN was not blocked within the 16-attempt safety limit".into(),
    ))
}

fn block_puk<T: CardTransport>(transport: &mut T) -> Result<()> {
    let mut remaining = retry_status(transport, 0x81)?
        .ok_or_else(|| CredentialError::SmartCardOperation("PUK retries are unavailable".into()))?
        .remaining;
    if remaining > 16 {
        return Err(CredentialError::SmartCardOperation(
            "PUK retry count exceeds the reset safety limit".into(),
        ));
    }
    for _ in 0..16 {
        if remaining == 0 {
            return Ok(());
        }
        let wrong_puk = PivPuk::new(random_code()?)?;
        let new_pin = PivPin::new(random_code()?)?;
        match sigil_piv::management::unblock_pin_selected(transport, &wrong_puk, &new_pin) {
            Err(CredentialError::PukIncorrect {
                remaining: reported,
            }) => {
                if reported != remaining.saturating_sub(1) {
                    return Err(CredentialError::SmartCardOperation(
                        "PUK retry count did not decrease by exactly one".into(),
                    ));
                }
                remaining = reported;
            }
            Err(CredentialError::PukBlocked) => {
                if remaining != 1
                    || retry_status(transport, 0x81)?.is_none_or(|value| value.remaining != 0)
                {
                    return Err(CredentialError::SmartCardOperation(
                        "PUK became blocked with an unexpected retry count".into(),
                    ));
                }
                return Ok(());
            }
            Ok(()) => {
                return Err(CredentialError::SmartCardOperation(
                    "random PUK reset challenge unexpectedly succeeded".into(),
                ));
            }
            Err(error) => return Err(error),
        }
    }
    Err(CredentialError::SmartCardOperation(
        "PUK was not blocked within the 16-attempt safety limit".into(),
    ))
}

fn random_code() -> Result<Vec<u8>> {
    const ALPHANUMERIC: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut result = Vec::with_capacity(8);
    while result.len() < 8 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| {
            CredentialError::BackendUnavailable("OS random source unavailable".into())
        })?;
        for value in random {
            if value < 248 {
                result.push(ALPHANUMERIC[usize::from(value % 62)]);
                if result.len() == 8 {
                    break;
                }
            }
        }
    }
    Ok(result)
}

pub fn slot_public_key_spki<T: CardTransport>(transport: &mut T, slot: PivSlot) -> Result<Vec<u8>> {
    let (data, status) = transceive(transport, &[0x00, 0xf7, 0x00, slot.byte()])?;
    if status == 0x6a82 || status == 0x6a88 {
        return Err(CredentialError::DeviceMismatch);
    }
    if status != 0x9000 {
        return Err(CredentialError::CardStatus(status));
    }
    let fields = sigil_piv::tlv::parse(&data)
        .map_err(|error| CredentialError::SmartCardOperation(error.to_string()))?;
    let algorithm = fields
        .iter()
        .find(|(tag, _)| *tag == 0x01)
        .and_then(|(_, value)| value.first())
        .copied()
        .map(algorithm_from_yubikey_id)
        .ok_or_else(|| {
            CredentialError::SmartCardOperation("PIV metadata omitted key algorithm".into())
        })?;
    let public = fields
        .iter()
        .find(|(tag, _)| *tag == 0x04)
        .map(|(_, value)| value.as_slice())
        .ok_or(CredentialError::DeviceMismatch)?;
    management::public_key_spki_from_metadata(algorithm, public)
}

pub fn verify_certificate_matches_key(certificate_der: &[u8], expected_spki: &[u8]) -> Result<()> {
    let certificate = Certificate::from_der(certificate_der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let spki = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    if spki != expected_spki {
        return Err(CredentialError::DeviceMismatch);
    }
    Ok(())
}

/// Verifies an attestation against the Yubico roots embedded in this build.
pub fn verify_attestation(
    attestation_der: &[u8],
    intermediate_der: &[u8],
    expected_spki: &[u8],
    expected_serial: &str,
    slot: PivSlot,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<()> {
    verify_attestation_with(
        &AttestationTrust::embedded()?,
        attestation::now_unix(),
        attestation_der,
        intermediate_der,
        expected_spki,
        expected_serial,
        slot,
        pin_policy,
        touch_policy,
    )
}

/// Verifies an attestation chain against `trust` at `now_unix`, then the key, serial, slot and policies.
/// The chain is attestation → slot F9 → intermediates → root, and must end at a root in `trust`.
#[allow(clippy::too_many_arguments)]
pub fn verify_attestation_with(
    trust: &AttestationTrust,
    now_unix: u64,
    attestation_der: &[u8],
    intermediate_der: &[u8],
    expected_spki: &[u8],
    expected_serial: &str,
    slot: PivSlot,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<()> {
    let attestation = Certificate::from_der(attestation_der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let intermediate = Certificate::from_der(intermediate_der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    attestation::verify_path(
        &attestation,
        std::slice::from_ref(&intermediate),
        trust,
        now_unix,
    )
    .map_err(|error| {
        CredentialError::CertificateParse(format!(
            "attestation does not verify to a Yubico root: {error}"
        ))
    })?;
    let attested_spki = attestation
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    if attested_spki != expected_spki {
        return Err(CredentialError::DeviceMismatch);
    }
    let extensions = attestation.tbs_certificate().extensions().ok_or_else(|| {
        CredentialError::CertificateParse("attestation extensions are missing".into())
    })?;
    let serial_extension = extensions
        .iter()
        .find(|extension| extension.extn_id == YUBICO_SERIAL_OID)
        .ok_or_else(|| {
            CredentialError::CertificateParse("YubiKey serial extension is missing".into())
        })?;
    let serial_integer =
        x509_cert::der::asn1::Uint::from_der(serial_extension.extn_value.as_bytes())
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let expected_serial_number = expected_serial
        .parse::<u64>()
        .map_err(|_| CredentialError::DeviceMismatch)?;
    if unsigned_integer_to_u64(serial_integer.as_bytes())? != expected_serial_number {
        return Err(CredentialError::DeviceMismatch);
    }
    let policy_extension = extensions
        .iter()
        .find(|extension| extension.extn_id == YUBICO_POLICY_OID)
        .ok_or_else(|| {
            CredentialError::CertificateParse("YubiKey policy extension is missing".into())
        })?;
    let policy = policy_extension.extn_value.as_bytes();
    let expected_policy = [
        attested_pin_policy(slot, pin_policy)?,
        attested_touch_policy(touch_policy),
    ];
    if policy != expected_policy {
        return Err(CredentialError::DeviceMismatch);
    }
    verify_attestation_signature(&attestation, &intermediate)
}

fn unsigned_integer_to_u64(bytes: &[u8]) -> Result<u64> {
    bytes.iter().try_fold(0u64, |value, byte| {
        value
            .checked_mul(256)
            .and_then(|value| value.checked_add(u64::from(*byte)))
            .ok_or_else(|| CredentialError::CertificateParse("YubiKey serial is too large".into()))
    })
}

fn attested_pin_policy(slot: PivSlot, policy: PinPolicy) -> Result<u8> {
    match policy {
        PinPolicy::Never => Ok(0x01),
        PinPolicy::Once => Ok(0x02),
        PinPolicy::Always => Ok(0x03),
        PinPolicy::Default => Ok(match slot {
            PivSlot::AUTHENTICATION | PivSlot::KEY_MANAGEMENT => 0x02,
            PivSlot::SIGNATURE => 0x03,
            PivSlot::CARD_AUTHENTICATION => 0x01,
            _ => 0x02,
        }),
        PinPolicy::MatchOnce | PinPolicy::MatchAlways => Err(
            CredentialError::UnsupportedOperation("biometric PIV policy attestation".into()),
        ),
    }
}

fn attested_touch_policy(policy: TouchPolicy) -> u8 {
    match policy {
        TouchPolicy::Default | TouchPolicy::Never => 0x01,
        TouchPolicy::Always => 0x02,
        TouchPolicy::Cached => 0x03,
    }
}

fn verify_attestation_signature(attestation: &Certificate, issuer: &Certificate) -> Result<()> {
    let spki = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let tbs = attestation
        .tbs_certificate()
        .to_der()
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let signature = attestation.signature().as_bytes().ok_or_else(|| {
        CredentialError::CertificateParse("attestation signature is invalid".into())
    })?;
    let algorithm = attestation.signature_algorithm().oid;
    if algorithm == OID_ECDSA_WITH_SHA256 {
        let key = P256VerifyingKey::from_public_key_der(&spki)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let signature = P256Signature::from_der(signature)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let digest = Sha256::digest(&tbs);
        key.verify_prehash(&digest, &signature).map_err(|_| {
            CredentialError::CertificateParse("attestation signature is invalid".into())
        })
    } else if algorithm == OID_ECDSA_WITH_SHA384 {
        let key = P384VerifyingKey::from_public_key_der(&spki)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let signature = P384Signature::from_der(signature)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let digest = Sha384::digest(&tbs);
        key.verify_prehash(&digest, &signature).map_err(|_| {
            CredentialError::CertificateParse("attestation signature is invalid".into())
        })
    } else if algorithm == OID_RSA_WITH_SHA256 {
        let key = rsa::RsaPublicKey::from_public_key_der(&spki)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let key = RsaVerifyingKey::<sha2_legacy::Sha256>::new(key);
        let signature = RsaSignature::try_from(signature)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let digest = <sha2_legacy::Sha256 as LegacyDigest>::digest(&tbs);
        key.verify_prehash(&digest, &signature).map_err(|_| {
            CredentialError::CertificateParse("attestation signature is invalid".into())
        })
    } else if algorithm == OID_RSA_WITH_SHA384 {
        let key = rsa::RsaPublicKey::from_public_key_der(&spki)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let key = RsaVerifyingKey::<sha2_legacy::Sha384>::new(key);
        let signature = RsaSignature::try_from(signature)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let digest = <sha2_legacy::Sha384 as LegacyDigest>::digest(&tbs);
        key.verify_prehash(&digest, &signature).map_err(|_| {
            CredentialError::CertificateParse("attestation signature is invalid".into())
        })
    } else {
        Err(CredentialError::UnsupportedOperation(
            "unsupported YubiKey attestation signature algorithm".into(),
        ))
    }
}

fn certificate_from_object(object: &[u8]) -> Result<Vec<u8>> {
    let fields = sigil_piv::tlv::parse(object)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    fields
        .into_iter()
        .find(|(tag, _)| *tag == 0x70)
        .map(|(_, certificate)| certificate)
        .filter(|certificate| !certificate.is_empty())
        .ok_or_else(|| {
            CredentialError::CertificateParse("certificate object omitted tag 70".into())
        })
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, str::FromStr};

    const P256_CERT: &[u8] = include_bytes!("../../sigil-mock/fixtures/piv-9a-p256.der");
    const RSA_CERT: &[u8] = include_bytes!("../../sigil-mock/fixtures/piv-9d-rsa2048.der");

    use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
    use x509_cert::{
        builder::{Builder, CertificateBuilder, profile::BuilderProfile},
        certificate::TbsCertificate,
        der::{Encode, asn1::OctetString},
        ext::Extension,
        name::Name,
        serial_number::SerialNumber,
        spki::{SubjectPublicKeyInfo, SubjectPublicKeyInfoRef},
        time::Validity,
    };

    use super::*;

    struct ScriptedTransport(VecDeque<(Vec<u8>, Vec<u8>)>);

    impl ScriptedTransport {
        fn new(steps: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> Self {
            Self(steps.into_iter().collect())
        }
    }

    impl CardTransport for ScriptedTransport {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            let (expected, response) = self.0.pop_front().expect("unexpected APDU");
            assert_eq!(command, expected);
            Ok(response)
        }
    }

    fn response(data: &[u8], sw: u16) -> Vec<u8> {
        [data, &sw.to_be_bytes()].concat()
    }

    #[test]
    fn parses_metadata_fields_and_yubikey_algorithms() {
        let fields = [
            0x01, 0x01, 0x07, 0x02, 0x02, 0x04, 0x03, 0x03, 0x01, 0x01, 0x05, 0x01, 0x01, 0x06,
            0x02, 0x05, 0x03,
        ];
        let parsed = parse_metadata(&fields).unwrap();
        assert_eq!(parsed.algorithm, Some(PivAlgorithm::Rsa2048));
        assert_eq!(parsed.pin_policy, Some(PinPolicy::MatchOnce));
        assert_eq!(parsed.touch_policy, Some(TouchPolicy::Cached));
        assert_eq!(parsed.origin, Some(KeyOrigin::Generated));
        assert_eq!(parsed.default_value, Some(true));
        assert_eq!(parsed.retries, Some((5, 3)));
        assert_eq!(algorithm_from_yubikey_id(0x14), PivAlgorithm::EccP384);
        assert_eq!(algorithm_from_yubikey_id(0xff), PivAlgorithm::Unknown(0xff));
    }

    #[test]
    fn parses_version_serial_and_serial_mismatch() {
        let mut v =
            ScriptedTransport::new([(vec![0x00, 0xfd, 0x00, 0x00], response(&[5, 7, 1], 0x9000))]);
        assert_eq!(
            version(&mut v).unwrap(),
            Some(FirmwareVersion {
                major: 5,
                minor: 7,
                patch: 1
            })
        );
        let select_apdu = vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08];
        let serial_apdu = vec![0x00, 0xf8, 0x00, 0x00];
        let mut s = ScriptedTransport::new([
            (select_apdu.clone(), response(&[], 0x9000)),
            (
                serial_apdu.clone(),
                response(&[0x00, 0xbc, 0x61, 0x4e], 0x9000),
            ),
        ]);
        assert_eq!(serial(&mut s).unwrap(), Some(12_345_678));
        let mut matching = ScriptedTransport::new([
            (select_apdu.clone(), response(&[], 0x9000)),
            (
                serial_apdu.clone(),
                response(&[0x00, 0xbc, 0x61, 0x4e], 0x9000),
            ),
        ]);
        verify_serial(&mut matching, "12345678").unwrap();
        let mut mismatch = ScriptedTransport::new([
            (select_apdu.clone(), response(&[], 0x9000)),
            (serial_apdu.clone(), response(&[0, 0, 0, 1], 0x9000)),
        ]);
        assert_eq!(
            verify_serial(&mut mismatch, "12345678"),
            Err(CredentialError::DeviceMismatch)
        );
        let mut strict_mismatch = ScriptedTransport::new([
            (select_apdu.clone(), response(&[], 0x9000)),
            (serial_apdu.clone(), response(&[0, 0, 0, 1], 0x9000)),
        ]);
        assert_eq!(
            verify_expected_serial(&mut strict_mismatch, "12345678"),
            Err(CredentialError::DeviceMismatch)
        );
        let mut unavailable = ScriptedTransport::new([
            (select_apdu, response(&[], 0x9000)),
            (serial_apdu, response(&[], 0x6d00)),
        ]);
        assert_eq!(
            verify_serial(&mut unavailable, "12345678"),
            Err(CredentialError::DeviceMismatch)
        );
    }

    fn encode_tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
        let mut encoded = tag.to_vec();
        if value.len() < 0x80 {
            encoded.push(value.len() as u8);
        } else if value.len() <= 0xff {
            encoded.extend_from_slice(&[0x81, value.len() as u8]);
        } else {
            encoded.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]);
        }
        encoded.extend_from_slice(value);
        encoded
    }

    #[test]
    fn maps_slot_key_status_responses() {
        for status in [0x6a82u16, 0x6a88] {
            let mut absent = ScriptedTransport::new([(
                vec![0x00, 0xf7, 0x00, 0x9a],
                status.to_be_bytes().to_vec(),
            )]);
            assert_eq!(
                slot_key_status(&mut absent, PivSlot::AUTHENTICATION),
                Ok(KeyStatus::Absent)
            );
        }
        let mut unknown =
            ScriptedTransport::new([(vec![0x00, 0xf7, 0x00, 0x9a], vec![0x6d, 0x00])]);
        assert_eq!(
            slot_key_status(&mut unknown, PivSlot::AUTHENTICATION),
            Ok(KeyStatus::Unknown)
        );
        let mut unauthorized =
            ScriptedTransport::new([(vec![0x00, 0xf7, 0x00, 0x9a], vec![0x69, 0x82])]);
        assert_eq!(
            slot_key_status(&mut unauthorized, PivSlot::AUTHENTICATION),
            Err(CredentialError::CardStatus(0x6982))
        );
    }

    #[test]
    fn metadata_treats_missing_reference_data_as_absent() {
        for status in [0x6a82u16, 0x6a88] {
            let mut transport = ScriptedTransport::new([(
                vec![0x00, 0xf7, 0x00, 0x9a],
                status.to_be_bytes().to_vec(),
            )]);
            assert_eq!(metadata(&mut transport, 0x9a), Ok(None));
        }
    }

    #[test]
    fn read_slots_omits_empty_retired_slots_and_includes_a_certificate_slot() {
        let certificate = include_bytes!("../../sigil-mock/fixtures/piv-9a-p256.der");
        let certificate_field = encode_tlv(&[0x70], certificate);
        let certificate_object = encode_tlv(&[0x53], &certificate_field);
        let mut steps = vec![(
            vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08],
            vec![0x90, 0x00],
        )];
        let mut slots = PivSlot::STANDARD.to_vec();
        slots.extend(PivSlot::retired_slots());
        slots.push(PivSlot::ATTESTATION);
        for slot in slots {
            let tag = sigil_piv::data_object_tag(slot);
            let get_data = vec![
                0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, tag[0], tag[1], tag[2], 0x00,
            ];
            let certificate_response = if slot.byte() == 0x82 {
                response(&certificate_object, 0x9000)
            } else {
                vec![0x6a, 0x82]
            };
            steps.push((get_data, certificate_response));
            steps.push((vec![0x00, 0xf7, 0x00, slot.byte()], vec![0x6d, 0x00]));
        }
        let mut transport = ScriptedTransport::new(steps);
        let entries = read_slots(&mut transport).unwrap();
        assert_eq!(entries.len(), 5);
        assert!(
            entries
                .iter()
                .any(|entry| entry.slot.byte() == 0x82 && entry.certificate.is_some())
        );
        assert!(
            !entries
                .iter()
                .any(|entry| (0x83..=0x95).contains(&entry.slot.byte()))
        );
        assert!(
            !entries
                .iter()
                .any(|entry| entry.slot == PivSlot::ATTESTATION)
        );
    }

    #[test]
    fn set_management_key_uses_aes_metadata_and_never_touch() {
        let key = ManagementKey::new(ManagementKeyAlgorithm::Aes192, vec![0x55; 24]).unwrap();
        let mut command = vec![0x00, 0xff, 0xff, 0xff, 0x1b, 0x0a, 0x9b, 0x18];
        command.extend_from_slice(&[0x55; 24]);
        let mut transport = ScriptedTransport::new([(command, response(&[], 0x9000))]);
        set_management_key_selected(&mut transport, &key).unwrap();
    }

    #[test]
    fn attestation_reads_only_target_and_f9_certificate_objects() {
        let attestation_object = response(P256_CERT, 0x9000);
        let f9_template = encode_tlv(&[0x70], P256_CERT);
        let f9_object = encode_tlv(&[0x53], &f9_template);
        let mut transport = ScriptedTransport::new([
            (
                vec![0x00, 0xf9, PivSlot::AUTHENTICATION.byte(), 0x00],
                attestation_object,
            ),
            (
                vec![
                    0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xff, 0x01, 0x00,
                ],
                response(&f9_object, 0x9000),
            ),
        ]);
        let result = attest_selected(&mut transport, PivSlot::AUTHENTICATION).unwrap();
        assert_eq!(result.attestation_der, P256_CERT);
        assert_eq!(result.intermediate_der, P256_CERT);

        let mut forbidden = ScriptedTransport::new([]);
        assert!(matches!(
            attest_selected(&mut forbidden, PivSlot::ATTESTATION),
            Err(CredentialError::UnsupportedOperation(_))
        ));
    }

    #[test]
    fn delete_key_requires_firmware_57_and_never_allows_f9() {
        let mut supported = ScriptedTransport::new([
            (vec![0x00, 0xfd, 0x00, 0x00], response(&[5, 7, 4], 0x9000)),
            (
                vec![0x00, 0xf6, 0xff, PivSlot::AUTHENTICATION.byte()],
                response(&[], 0x9000),
            ),
        ]);
        delete_key_selected(&mut supported, PivSlot::AUTHENTICATION).unwrap();

        let mut old_firmware =
            ScriptedTransport::new([(vec![0x00, 0xfd, 0x00, 0x00], response(&[5, 6, 9], 0x9000))]);
        assert!(matches!(
            delete_key_selected(&mut old_firmware, PivSlot::AUTHENTICATION),
            Err(CredentialError::UnsupportedOperation(_))
        ));
        let mut f9 = ScriptedTransport::new([]);
        assert!(matches!(
            delete_key_selected(&mut f9, PivSlot::ATTESTATION),
            Err(CredentialError::UnsupportedOperation(_))
        ));
    }

    struct ResetTransport {
        pin_remaining: u8,
        puk_remaining: u8,
        pin_attempts: u8,
        puk_attempts: u8,
        reset: bool,
        bad_pin_decrement: bool,
    }

    impl CardTransport for ResetTransport {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            match command {
                [0x00, 0xa4, 0x04, 0x00, ..] => Ok(response(&[], 0x9000)),
                [0x00, 0xf7, 0x00, 0x80] => Ok(response(
                    &[
                        0x01,
                        0x01,
                        0xff,
                        0x05,
                        0x01,
                        0x01,
                        0x06,
                        0x02,
                        0x03,
                        self.pin_remaining,
                    ],
                    0x9000,
                )),
                [0x00, 0xf7, 0x00, 0x81] => Ok(response(
                    &[
                        0x01,
                        0x01,
                        0xff,
                        0x05,
                        0x01,
                        0x01,
                        0x06,
                        0x02,
                        0x03,
                        self.puk_remaining,
                    ],
                    0x9000,
                )),
                [0x00, 0x20, 0x00, 0x80, 0x08, ..] => {
                    assert!(self.pin_attempts < 16);
                    self.pin_attempts += 1;
                    let decrement = if self.bad_pin_decrement { 2 } else { 1 };
                    self.pin_remaining = self.pin_remaining.saturating_sub(decrement);
                    Ok(0x63c0u16
                        .saturating_add(u16::from(self.pin_remaining))
                        .to_be_bytes()
                        .to_vec())
                }
                [0x00, 0x2c, 0x00, 0x80, 0x10, ..] => {
                    assert!(self.puk_attempts < 16);
                    self.puk_attempts += 1;
                    self.puk_remaining = self.puk_remaining.saturating_sub(1);
                    Ok(0x63c0u16
                        .saturating_add(u16::from(self.puk_remaining))
                        .to_be_bytes()
                        .to_vec())
                }
                [0x00, 0xfb, 0x00, 0x00] => {
                    self.reset = true;
                    Ok(response(&[], 0x9000))
                }
                _ => panic!("unexpected PIV APDU"),
            }
        }
    }

    #[test]
    fn reset_blocks_both_references_one_retry_at_a_time_before_resetting() {
        let mut transport = ResetTransport {
            pin_remaining: 3,
            puk_remaining: 3,
            pin_attempts: 0,
            puk_attempts: 0,
            reset: false,
            bad_pin_decrement: false,
        };
        reset_piv(&mut transport).unwrap();
        assert_eq!(transport.pin_attempts, 3);
        assert_eq!(transport.puk_attempts, 3);
        assert!(transport.reset);
    }

    #[test]
    fn reset_aborts_when_a_retry_count_drops_by_more_than_one() {
        let mut transport = ResetTransport {
            pin_remaining: 3,
            puk_remaining: 3,
            pin_attempts: 0,
            puk_attempts: 0,
            reset: false,
            bad_pin_decrement: true,
        };
        assert!(matches!(
            reset_piv(&mut transport),
            Err(CredentialError::SmartCardOperation(_))
        ));
        assert_eq!(transport.pin_attempts, 1);
        assert_eq!(transport.puk_attempts, 0);
        assert!(!transport.reset);
    }

    #[test]
    fn metadata_public_point_builds_matching_subject_public_key_info() {
        let certificate = Certificate::from_der(P256_CERT).unwrap();
        let expected = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();
        let public_point = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .unwrap();
        let metadata = [
            encode_tlv(&[0x01], &[0x11]),
            encode_tlv(&[0x04], &encode_tlv(&[0x86], public_point)),
        ]
        .concat();
        let mut transport = ScriptedTransport::new([(
            vec![0x00, 0xf7, 0x00, PivSlot::AUTHENTICATION.byte()],
            response(&metadata, 0x9000),
        )]);
        let actual = slot_public_key_spki(&mut transport, PivSlot::AUTHENTICATION).unwrap();
        assert_eq!(actual, expected);
        verify_certificate_matches_key(P256_CERT, &actual).unwrap();
        assert_eq!(
            verify_certificate_matches_key(RSA_CERT, &actual),
            Err(CredentialError::DeviceMismatch)
        );
    }

    #[derive(Clone)]
    struct TestProfile {
        subject: Name,
        issuer: Name,
    }

    impl BuilderProfile for TestProfile {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.issuer.clone()
        }

        fn get_subject(&self) -> Name {
            self.subject.clone()
        }

        fn build_extensions(
            &self,
            _spk: SubjectPublicKeyInfoRef<'_>,
            _issuer_spk: SubjectPublicKeyInfoRef<'_>,
            _tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            Ok(Vec::new())
        }
    }

    fn issue_test_certificate(
        subject_name: &str,
        issuer_name: &str,
        spki_der: &[u8],
        serial: u32,
        signer: &SigningKey,
        extensions: Vec<Extension>,
    ) -> Vec<u8> {
        let subject = Name::from_str(subject_name).expect("subject name");
        let issuer = Name::from_str(issuer_name).expect("issuer name");
        let builder = CertificateBuilder::new(
            TestProfile { subject, issuer },
            SerialNumber::from(serial),
            Validity::from_now(std::time::Duration::from_secs(3600)).expect("validity"),
            SubjectPublicKeyInfo::from_der(spki_der).expect("subject public key"),
        )
        .expect("certificate builder");
        let mut builder = builder;
        for extension in extensions {
            builder
                .add_extension(extension)
                .expect("add test extension");
        }
        builder
            .build::<_, p256::ecdsa::DerSignature>(signer)
            .expect("sign test certificate")
            .to_der()
            .expect("certificate DER")
    }

    fn test_extension(oid: const_oid::ObjectIdentifier, value: &[u8]) -> Extension {
        Extension {
            extn_id: oid,
            critical: false,
            extn_value: OctetString::new(value).expect("extension value"),
        }
    }

    #[test]
    fn attestation_helper_checks_signature_spki_serial_and_policies() {
        let attestation_signer =
            SigningKey::from_bytes((&[11u8; 32]).into()).expect("attestation signer");
        let attested_signer = SigningKey::from_bytes((&[7u8; 32]).into()).expect("attested signer");
        let attestation_spki = attestation_signer
            .verifying_key()
            .to_public_key_der()
            .expect("F9 public key");
        let attested_spki = attested_signer
            .verifying_key()
            .to_public_key_der()
            .expect("slot public key");
        let f9 = issue_test_certificate(
            "CN=F9 test attestation",
            "CN=F9 test attestation",
            attestation_spki.as_bytes(),
            1,
            &attestation_signer,
            vec![test_extension(
                const_oid::ObjectIdentifier::new_unwrap("2.5.29.19"),
                &[0x30, 0x03, 0x01, 0x01, 0xff],
            )],
        );
        let serial_value = x509_cert::der::asn1::Uint::new(&39192733u32.to_be_bytes())
            .unwrap()
            .to_der()
            .unwrap();
        let attestation = issue_test_certificate(
            "CN=Attested key",
            "CN=F9 test attestation",
            attested_spki.as_bytes(),
            2,
            &attestation_signer,
            vec![
                test_extension(YUBICO_SERIAL_OID, &serial_value),
                test_extension(YUBICO_POLICY_OID, &[0x02, 0x01]),
            ],
        );
        let trust = AttestationTrust::from_parts(
            vec![x509_cert::Certificate::from_der(&f9).expect("F9 as trust anchor")],
            Vec::new(),
        );
        let now = attestation::now_unix();
        verify_attestation_with(
            &trust,
            now,
            &attestation,
            &f9,
            attested_spki.as_bytes(),
            "39192733",
            PivSlot::AUTHENTICATION,
            PinPolicy::Once,
            TouchPolicy::Never,
        )
        .expect("valid attestation");
        assert_eq!(
            verify_attestation_with(
                &trust,
                now,
                &attestation,
                &f9,
                attested_spki.as_bytes(),
                "wrong-serial",
                PivSlot::AUTHENTICATION,
                PinPolicy::Once,
                TouchPolicy::Never,
            ),
            Err(CredentialError::DeviceMismatch)
        );
        assert_eq!(
            verify_attestation_with(
                &trust,
                now,
                &attestation,
                &f9,
                attested_spki.as_bytes(),
                "39192733",
                PivSlot::AUTHENTICATION,
                PinPolicy::Always,
                TouchPolicy::Never,
            ),
            Err(CredentialError::DeviceMismatch)
        );
    }
}
