//! PIV state-changing APDUs and signing helpers. Callers keep transport local to providers.

use std::str::FromStr;

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use der::{
    Decode, Encode,
    asn1::{Any, BitString},
};
use p256::{
    ecdsa::{
        Signature as P256Signature, VerifyingKey as P256VerifyingKey,
        signature::hazmat::PrehashVerifier,
    },
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use sha2::{Digest, Sha256, Sha384};
use sigil_core::{
    CredentialError, ManagementKey, ManagementKeyAlgorithm, PinPolicy, PivAlgorithm,
    PivKeyAlgorithm, PivPin, PivPuk, PivSlot, Result, TouchPolicy,
};
use x509_cert::{
    Certificate,
    name::Name,
    request::{CertReq, CertReqInfo, Version},
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfo},
};

use crate::{CardTransport, select, tlv, transceive};

const OID_EC_PUBLIC_KEY: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_RSA_ENCRYPTION: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_P256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ECDSA_WITH_SHA256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_WITH_SHA384: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

fn command_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
    let mut command = vec![0x00, ins, p1, p2];
    if data.is_empty() {
        return Ok(command);
    }
    if data.len() > u8::MAX as usize {
        return Err(CredentialError::SmartCardOperation(
            "PIV command data exceeds short Lc; use command chaining".into(),
        ));
    }
    command.push(data.len() as u8);
    command.extend_from_slice(data);
    Ok(command)
}

fn command_apdus(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if data.len() <= u8::MAX as usize {
        return Ok(vec![command_apdu(ins, p1, p2, data)?]);
    }
    if data.len() > u16::MAX as usize {
        return Err(CredentialError::SmartCardOperation(
            "PIV command data exceeded 65535 bytes".into(),
        ));
    }
    let chunks: Vec<_> = data.chunks(u8::MAX as usize).collect();
    Ok(chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let cla = if index + 1 == chunks.len() {
                0x00
            } else {
                0x10
            };
            let mut command = vec![cla, ins, p1, p2, chunk.len() as u8];
            command.extend_from_slice(chunk);
            command
        })
        .collect())
}

fn transceive_command_apdus<T: CardTransport + ?Sized>(
    transport: &mut T,
    commands: &[Vec<u8>],
) -> Result<(Vec<u8>, u16)> {
    let Some((final_command, intermediate_commands)) = commands.split_last() else {
        return Err(CredentialError::SmartCardOperation(
            "PIV command chain is empty".into(),
        ));
    };
    for command in intermediate_commands {
        let (_, status) = transceive(transport, command)?;
        if status != 0x9000 {
            return Err(CredentialError::CardStatus(status));
        }
    }
    transceive(transport, final_command)
}

fn transmit_command_apdus<T: CardTransport + ?Sized>(
    transport: &mut T,
    commands: &[Vec<u8>],
) -> Result<()> {
    let (_, status) = transceive_command_apdus(transport, commands)?;
    if status == 0x9000 {
        Ok(())
    } else {
        Err(CredentialError::CardStatus(status))
    }
}

fn transmit<T: CardTransport + ?Sized>(transport: &mut T, command: &[u8]) -> Result<()> {
    let (_, status) = transceive(transport, command)?;
    if status == 0x9000 {
        Ok(())
    } else {
        Err(CredentialError::CardStatus(status))
    }
}

fn transmit_pin_command<T: CardTransport + ?Sized>(
    transport: &mut T,
    command: &[u8],
    puk: bool,
) -> Result<()> {
    let (_, status) = transceive(transport, command)?;
    match status {
        0x9000 => Ok(()),
        0x6983 if puk => Err(CredentialError::PukBlocked),
        0x6983 => Err(CredentialError::PinBlocked),
        value if value & 0xfff0 == 0x63c0 && puk => Err(CredentialError::PukIncorrect {
            remaining: (value & 0x000f) as u8,
        }),
        value if value & 0xfff0 == 0x63c0 => Err(CredentialError::PinIncorrect {
            remaining: (value & 0x000f) as u8,
        }),
        other => Err(CredentialError::CardStatus(other)),
    }
}

/// PIN complexity (firmware 5.7+) rejects a new PIN or PUK with SW 6985. Only change and
/// unblock commands can produce it; verification keeps the generic card status.
fn transmit_pin_change<T: CardTransport + ?Sized>(
    transport: &mut T,
    command: &[u8],
    puk: bool,
    complexity: CredentialError,
) -> Result<()> {
    match transmit_pin_command(transport, command, puk) {
        Err(CredentialError::CardStatus(0x6985)) => Err(complexity),
        other => other,
    }
}

fn pin_verify_command(pin: &PivPin) -> Vec<u8> {
    let padded = pin.padded();
    let mut command = vec![0x00, 0x20, 0x00, 0x80, 0x08];
    command.extend_from_slice(padded.as_slice());
    command
}

fn change_reference_data_command(
    reference: u8,
    old: &[u8],
    new: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if !matches!(reference, 0x80 | 0x81) || old.len() != 8 || new.len() != 8 {
        return Err(CredentialError::SmartCardOperation(
            "invalid PIV reference-data command".into(),
        ));
    }
    let mut command = zeroize::Zeroizing::new(vec![0x00, 0x24, 0x00, reference, 0x10]);
    command.extend_from_slice(old);
    command.extend_from_slice(new);
    Ok(command)
}

fn reset_retry_counter_command(puk: &[u8], new_pin: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if puk.len() != 8 || new_pin.len() != 8 {
        return Err(CredentialError::SmartCardOperation(
            "invalid PIV retry-counter command".into(),
        ));
    }
    let mut command = zeroize::Zeroizing::new(vec![0x00, 0x2c, 0x00, 0x80, 0x10]);
    command.extend_from_slice(puk);
    command.extend_from_slice(new_pin);
    Ok(command)
}

fn sign_digest_command(
    slot: PivSlot,
    algorithm: PivKeyAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>> {
    if digest.len() != algorithm.digest_len() {
        return Err(CredentialError::SmartCardOperation(
            "CSR digest has an invalid length".into(),
        ));
    }
    let mut inner = tlv::encode(0x82, &[])?;
    inner.extend_from_slice(&tlv::encode(0x81, digest)?);
    command_apdu(
        0x87,
        algorithm.yubikey_id(),
        slot.byte(),
        &tlv::encode(0x7c, &inner)?,
    )
}

fn build_put_certificate_data(slot: PivSlot, certificate_der: &[u8]) -> Result<Vec<u8>> {
    let tag = crate::data_object_tag(slot);
    let mut certificate_template = tlv::encode(0x70, certificate_der)?;
    certificate_template.extend_from_slice(&tlv::encode(0x71, &[0x00])?);
    certificate_template.extend_from_slice(&tlv::encode(0xfe, &[])?);
    let mut data = tlv::encode(0x5c, &tag)?;
    data.extend_from_slice(&tlv::encode(0x53, &certificate_template)?);
    Ok(data)
}

fn build_put_certificate_commands(slot: PivSlot, certificate_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    command_apdus(
        0xdb,
        0x3f,
        0xff,
        &build_put_certificate_data(slot, certificate_der)?,
    )
}

fn build_delete_certificate_command(slot: PivSlot) -> Result<Vec<u8>> {
    let tag = crate::data_object_tag(slot);
    let mut data = tlv::encode(0x5c, &tag)?;
    data.extend_from_slice(&tlv::encode(0x53, &[])?);
    command_apdu(0xdb, 0x3f, 0xff, &data)
}

fn build_get_data_command(tag: &[u8]) -> Result<Vec<u8>> {
    if tag.is_empty() || tag.len() > 3 {
        return Err(CredentialError::SmartCardOperation(
            "invalid PIV data object tag".into(),
        ));
    }
    let data = tlv::encode(0x5c, tag)?;
    let mut command = command_apdu(0xcb, 0x3f, 0xff, &data)?;
    command.push(0x00);
    Ok(command)
}

pub fn verify_pin<T: CardTransport + ?Sized>(transport: &mut T, pin: &PivPin) -> Result<()> {
    select(transport)?;
    verify_pin_selected(transport, pin)
}

pub fn verify_pin_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    pin: &PivPin,
) -> Result<()> {
    let command = zeroize::Zeroizing::new(pin_verify_command(pin));
    transmit_pin_command(transport, command.as_slice(), false)
}

pub fn change_pin<T: CardTransport + ?Sized>(
    transport: &mut T,
    old_pin: &PivPin,
    new_pin: &PivPin,
) -> Result<()> {
    select(transport)?;
    change_pin_selected(transport, old_pin, new_pin)
}

pub fn change_pin_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    old_pin: &PivPin,
    new_pin: &PivPin,
) -> Result<()> {
    let old = old_pin.padded();
    let new = new_pin.padded();
    let command = change_reference_data_command(0x80, old.as_slice(), new.as_slice())?;
    transmit_pin_change(
        transport,
        command.as_slice(),
        false,
        CredentialError::PinComplexity,
    )
}

pub fn change_puk<T: CardTransport + ?Sized>(
    transport: &mut T,
    old_puk: &PivPuk,
    new_puk: &PivPuk,
) -> Result<()> {
    select(transport)?;
    change_puk_selected(transport, old_puk, new_puk)
}

pub fn change_puk_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    old_puk: &PivPuk,
    new_puk: &PivPuk,
) -> Result<()> {
    let old = old_puk.padded();
    let new = new_puk.padded();
    let command = change_reference_data_command(0x81, old.as_slice(), new.as_slice())?;
    transmit_pin_change(
        transport,
        command.as_slice(),
        true,
        CredentialError::PukComplexity,
    )
}

pub fn unblock_pin<T: CardTransport + ?Sized>(
    transport: &mut T,
    puk: &PivPuk,
    new_pin: &PivPin,
) -> Result<()> {
    select(transport)?;
    unblock_pin_selected(transport, puk, new_pin)
}

pub fn unblock_pin_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    puk: &PivPuk,
    new_pin: &PivPin,
) -> Result<()> {
    let puk = puk.padded();
    let pin = new_pin.padded();
    let command = reset_retry_counter_command(puk.as_slice(), pin.as_slice())?;
    transmit_pin_change(
        transport,
        command.as_slice(),
        true,
        CredentialError::PinComplexity,
    )
}

pub fn authenticate_management_key<T: CardTransport + ?Sized>(
    transport: &mut T,
    management_key: &ManagementKey,
) -> Result<()> {
    select(transport)?;
    authenticate_management_key_selected(transport, management_key)
}

pub fn authenticate_management_key_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    management_key: &ManagementKey,
) -> Result<()> {
    authenticate_management_key_with_challenge(transport, management_key, None)
}

/// Mutual authentication (SP 800-73-4 Part 2, section 3.2.4). The host sends the decrypted witness and its challenge,
/// and the card answers with the encrypted challenge. SP 800-73-4 does not settle whether that answer is tag 82 or
/// tag 80, so tag 82 is preferred and tag 80 is accepted when it is absent, as OpenSC does (card-piv.c,
/// piv_general_mutual_authenticate). Thales IDPrime PIV answers with tag 80.
fn authenticate_management_key_with_challenge<T: CardTransport + ?Sized>(
    transport: &mut T,
    management_key: &ManagementKey,
    fixed_challenge: Option<[u8; 16]>,
) -> Result<()> {
    let algorithm = management_key.algorithm();
    let p1 = match algorithm {
        ManagementKeyAlgorithm::Aes128 => 0x08,
        ManagementKeyAlgorithm::Aes192 => 0x0a,
        ManagementKeyAlgorithm::Aes256 => 0x0c,
    };
    let first_data = tlv::encode(0x7c, &tlv::encode(0x80, &[])?)?;
    let first = command_apdu(0x87, p1, 0x9b, &first_data)?;
    let (first_response, status) = transceive(transport, &first)?;
    if status != 0x9000 {
        return Err(management_auth_error(status));
    }
    let encrypted_witness = response_field(&first_response, 0x80)?;
    if encrypted_witness.len() != 16 {
        return Err(CredentialError::SmartCardOperation(
            "management-key witness had an invalid length".into(),
        ));
    }
    let mut witness = zeroize::Zeroizing::new([0u8; 16]);
    witness.copy_from_slice(&aes_decrypt_block(
        algorithm,
        management_key.as_bytes(),
        &encrypted_witness,
    )?);
    let mut host_challenge = zeroize::Zeroizing::new([0u8; 16]);
    if let Some(challenge) = fixed_challenge {
        *host_challenge = challenge;
    } else {
        getrandom::fill(host_challenge.as_mut_slice()).map_err(|_| {
            CredentialError::BackendUnavailable("OS random source unavailable".into())
        })?;
    }
    let mut inner = tlv::encode(0x80, witness.as_slice())?;
    inner.extend_from_slice(&tlv::encode(0x81, host_challenge.as_slice())?);
    let data = tlv::encode(0x7c, &inner)?;
    let command = zeroize::Zeroizing::new(command_apdu(0x87, p1, 0x9b, &data)?);
    let (response, status) = transceive(transport, command.as_slice())?;
    if status != 0x9000 {
        return Err(management_auth_error(status));
    }
    let encrypted_response = match response_field(&response, 0x82) {
        Ok(field) => field,
        Err(_) => response_field(&response, 0x80).map_err(|_| {
            CredentialError::SmartCardOperation(
                "card returned no management-key challenge response (tag 82 or 80)".into(),
            )
        })?,
    };
    if encrypted_response.len() != 16 {
        return Err(CredentialError::ManagementKeyIncorrect);
    }
    let expected_response = aes_encrypt_block(
        algorithm,
        management_key.as_bytes(),
        host_challenge.as_slice(),
    )?;
    let mismatch = encrypted_response
        .iter()
        .zip(expected_response.iter())
        .fold(0u8, |difference, (actual, expected)| {
            difference | (actual ^ expected)
        });
    if mismatch != 0 {
        return Err(CredentialError::ManagementKeyIncorrect);
    }
    Ok(())
}

fn management_auth_error(status: u16) -> CredentialError {
    if matches!(status, 0x6982 | 0x6a80) {
        CredentialError::ManagementKeyIncorrect
    } else {
        CredentialError::CardStatus(status)
    }
}

fn aes_encrypt_block(
    algorithm: ManagementKeyAlgorithm,
    key: &[u8],
    input: &[u8],
) -> Result<[u8; 16]> {
    if input.len() != 16 || key.len() != algorithm.key_len() {
        return Err(CredentialError::SmartCardOperation(
            "invalid AES management-key block".into(),
        ));
    }
    let mut output = [0u8; 16];
    match algorithm {
        ManagementKeyAlgorithm::Aes128 => {
            let cipher = Aes128::new_from_slice(key).map_err(aes_error)?;
            let mut block = GenericArray::clone_from_slice(input);
            cipher.encrypt_block(&mut block);
            output.copy_from_slice(&block);
        }
        ManagementKeyAlgorithm::Aes192 => {
            let cipher = Aes192::new_from_slice(key).map_err(aes_error)?;
            let mut block = GenericArray::clone_from_slice(input);
            cipher.encrypt_block(&mut block);
            output.copy_from_slice(&block);
        }
        ManagementKeyAlgorithm::Aes256 => {
            let cipher = Aes256::new_from_slice(key).map_err(aes_error)?;
            let mut block = GenericArray::clone_from_slice(input);
            cipher.encrypt_block(&mut block);
            output.copy_from_slice(&block);
        }
    }
    Ok(output)
}

fn aes_decrypt_block(
    algorithm: ManagementKeyAlgorithm,
    key: &[u8],
    input: &[u8],
) -> Result<[u8; 16]> {
    if input.len() != 16 || key.len() != algorithm.key_len() {
        return Err(CredentialError::SmartCardOperation(
            "invalid AES management-key block".into(),
        ));
    }
    let mut output = [0u8; 16];
    match algorithm {
        ManagementKeyAlgorithm::Aes128 => {
            let cipher = Aes128::new_from_slice(key).map_err(aes_error)?;
            let mut block = GenericArray::clone_from_slice(input);
            cipher.decrypt_block(&mut block);
            output.copy_from_slice(&block);
        }
        ManagementKeyAlgorithm::Aes192 => {
            let cipher = Aes192::new_from_slice(key).map_err(aes_error)?;
            let mut block = GenericArray::clone_from_slice(input);
            cipher.decrypt_block(&mut block);
            output.copy_from_slice(&block);
        }
        ManagementKeyAlgorithm::Aes256 => {
            let cipher = Aes256::new_from_slice(key).map_err(aes_error)?;
            let mut block = GenericArray::clone_from_slice(input);
            cipher.decrypt_block(&mut block);
            output.copy_from_slice(&block);
        }
    }
    Ok(output)
}

fn aes_error(_: aes::cipher::InvalidLength) -> CredentialError {
    CredentialError::SmartCardOperation("invalid AES key length".into())
}

fn response_field(response: &[u8], wanted: u16) -> Result<Vec<u8>> {
    let outer = tlv::parse(response)?;
    let template = outer
        .iter()
        .find(|(tag, _)| *tag == 0x7c)
        .map(|(_, value)| value)
        .ok_or_else(|| {
            CredentialError::SmartCardOperation("card response omitted PIV template".into())
        })?;
    tlv::parse(template)?
        .into_iter()
        .find(|(tag, _)| *tag == wanted)
        .map(|(_, value)| value)
        .ok_or_else(|| {
            CredentialError::SmartCardOperation("card response omitted a PIV field".into())
        })
}

pub fn generate_key_pair<T: CardTransport + ?Sized>(
    transport: &mut T,
    management_key: &ManagementKey,
    slot: PivSlot,
    algorithm: PivKeyAlgorithm,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<Vec<u8>> {
    generate_key_pair_with_policies(
        transport,
        management_key,
        slot,
        algorithm,
        Some((pin_policy, touch_policy)),
    )
}

/// None omits the PIN and touch policy objects, so the token applies its defaults.
pub fn generate_key_pair_with_policies<T: CardTransport + ?Sized>(
    transport: &mut T,
    management_key: &ManagementKey,
    slot: PivSlot,
    algorithm: PivKeyAlgorithm,
    policies: Option<(PinPolicy, TouchPolicy)>,
) -> Result<Vec<u8>> {
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "slot F9 is reserved for the YubiKey attestation key".into(),
        ));
    }
    select(transport)?;
    authenticate_management_key_selected(transport, management_key)?;
    generate_key_pair_selected(transport, slot, algorithm, policies)
}

/// Generates a key on an already-selected PIV application after management-key authentication.
pub fn generate_key_pair_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    slot: PivSlot,
    algorithm: PivKeyAlgorithm,
    policies: Option<(PinPolicy, TouchPolicy)>,
) -> Result<Vec<u8>> {
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "slot F9 is reserved for the YubiKey attestation key".into(),
        ));
    }
    let command = generate_key_command(slot, algorithm, policies)?;
    let (response, status) = transceive(transport, &command)?;
    if status != 0x9000 {
        return Err(CredentialError::CardStatus(status));
    }
    parse_generated_public_key(&response, algorithm)
}

fn generate_key_command(
    slot: PivSlot,
    algorithm: PivKeyAlgorithm,
    policies: Option<(PinPolicy, TouchPolicy)>,
) -> Result<Vec<u8>> {
    let mut data = tlv::encode(0x80, &[algorithm.yubikey_id()])?;
    if let Some((pin_policy, touch_policy)) = policies {
        if let Some(policy) = pin_policy_value(pin_policy)? {
            data.extend_from_slice(&tlv::encode(0xaa, &[policy])?);
        }
        if let Some(policy) = touch_policy_value(touch_policy) {
            data.extend_from_slice(&tlv::encode(0xab, &[policy])?);
        }
    }
    command_apdu(0x47, 0x00, slot.byte(), &tlv::encode(0xac, &data)?)
}

fn pin_policy_value(policy: PinPolicy) -> Result<Option<u8>> {
    match policy {
        PinPolicy::Default => Ok(None),
        PinPolicy::Never => Ok(Some(0x01)),
        PinPolicy::Once => Ok(Some(0x02)),
        PinPolicy::Always => Ok(Some(0x03)),
        PinPolicy::MatchOnce | PinPolicy::MatchAlways => {
            Err(CredentialError::UnsupportedOperation(
                "biometric PIV PIN policies are not supported".into(),
            ))
        }
    }
}

fn touch_policy_value(policy: TouchPolicy) -> Option<u8> {
    match policy {
        TouchPolicy::Default => None,
        TouchPolicy::Never => Some(0x01),
        TouchPolicy::Always => Some(0x02),
        TouchPolicy::Cached => Some(0x03),
    }
}

fn parse_generated_public_key(response: &[u8], algorithm: PivKeyAlgorithm) -> Result<Vec<u8>> {
    let template = tlv::parse(response)?
        .into_iter()
        .find(|(tag, _)| *tag == 0x7f49)
        .map(|(_, value)| value)
        .ok_or_else(|| {
            CredentialError::SmartCardOperation("key generation omitted public-key template".into())
        })?;
    let point = tlv::parse(&template)?
        .into_iter()
        .find(|(tag, _)| *tag == 0x86)
        .map(|(_, value)| value)
        .ok_or_else(|| {
            CredentialError::SmartCardOperation("key generation omitted public point".into())
        })?;
    public_key_spki(algorithm, &point)
}

pub fn public_key_spki(algorithm: PivKeyAlgorithm, point: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        PivKeyAlgorithm::EccP256 => {
            let key = p256::PublicKey::from_sec1_bytes(point).map_err(|_| {
                CredentialError::CertificateParse("invalid P-256 public point".into())
            })?;
            key.to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|error| CredentialError::CertificateParse(error.to_string()))
        }
        PivKeyAlgorithm::EccP384 => {
            let key = p384::PublicKey::from_sec1_bytes(point).map_err(|_| {
                CredentialError::CertificateParse("invalid P-384 public point".into())
            })?;
            key.to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|error| CredentialError::CertificateParse(error.to_string()))
        }
    }
}

pub fn public_key_spki_from_metadata(algorithm: PivAlgorithm, encoded: &[u8]) -> Result<Vec<u8>> {
    let fields = tlv::parse(encoded)?;
    match algorithm {
        PivAlgorithm::EccP256 | PivAlgorithm::EccP384 => {
            let point = fields
                .iter()
                .find(|(tag, _)| *tag == 0x86)
                .map(|(_, value)| value.as_slice())
                .ok_or_else(|| {
                    CredentialError::SmartCardOperation(
                        "PIV metadata omitted the EC public point".into(),
                    )
                })?;
            let key_algorithm = match algorithm {
                PivAlgorithm::EccP256 => PivKeyAlgorithm::EccP256,
                PivAlgorithm::EccP384 => PivKeyAlgorithm::EccP384,
                _ => unreachable!(),
            };
            public_key_spki(key_algorithm, point)
        }
        PivAlgorithm::Rsa1024
        | PivAlgorithm::Rsa2048
        | PivAlgorithm::Rsa3072
        | PivAlgorithm::Rsa4096 => {
            let modulus = fields
                .iter()
                .find(|(tag, _)| *tag == 0x81)
                .map(|(_, value)| value.as_slice())
                .ok_or_else(|| {
                    CredentialError::SmartCardOperation(
                        "PIV metadata omitted the RSA modulus".into(),
                    )
                })?;
            let exponent = fields
                .iter()
                .find(|(tag, _)| *tag == 0x82)
                .map(|(_, value)| value.as_slice())
                .ok_or_else(|| {
                    CredentialError::SmartCardOperation(
                        "PIV metadata omitted the RSA public exponent".into(),
                    )
                })?;
            let mut rsa = unsigned_integer_tlv(modulus)?;
            rsa.extend_from_slice(&unsigned_integer_tlv(exponent)?);
            let rsa_der = tlv::encode(0x30, &rsa)?;
            let null = Any::from_der(&[0x05, 0x00])
                .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
            SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    oid: OID_RSA_ENCRYPTION,
                    parameters: Some(null),
                },
                subject_public_key: BitString::from_bytes(&rsa_der)
                    .map_err(|error| CredentialError::CertificateParse(error.to_string()))?,
            }
            .to_der()
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))
        }
        other => Err(CredentialError::UnsupportedOperation(format!(
            "PIV public-key algorithm {other} is not supported for certificate binding"
        ))),
    }
}

fn unsigned_integer_tlv(bytes: &[u8]) -> Result<Vec<u8>> {
    let value = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map(|index| &bytes[index..])
        .unwrap_or(&[0]);
    let mut contents = Vec::with_capacity(value.len() + 1);
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        contents.push(0);
    }
    contents.extend_from_slice(value);
    tlv::encode(0x02, &contents)
}

pub fn sign_digest<T: CardTransport + ?Sized>(
    transport: &mut T,
    slot: PivSlot,
    algorithm: PivKeyAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>> {
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "slot F9 cannot sign arbitrary data".into(),
        ));
    }
    select(transport)?;
    sign_digest_selected(transport, slot, algorithm, digest)
}

pub fn sign_digest_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    slot: PivSlot,
    algorithm: PivKeyAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>> {
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "slot F9 cannot sign arbitrary data".into(),
        ));
    }
    let command = sign_digest_command(slot, algorithm, digest)?;
    let (response, status) = transceive(transport, &command)?;
    if status != 0x9000 {
        return Err(CredentialError::CardStatus(status));
    }
    response_field(&response, 0x82)
}

pub fn put_certificate_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    slot: PivSlot,
    certificate_der: &[u8],
) -> Result<()> {
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "slot F9 is reserved for the YubiKey attestation certificate".into(),
        ));
    }
    let commands = build_put_certificate_commands(slot, certificate_der)?;
    transmit_command_apdus(transport, &commands)
}

pub fn put_data_object_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    tag: &[u8],
    contents: &[u8],
) -> Result<()> {
    let mut data = tlv::encode(0x5c, tag)?;
    data.extend_from_slice(&tlv::encode(0x53, contents)?);
    let commands = command_apdus(0xdb, 0x3f, 0xff, &data)?;
    transmit_command_apdus(transport, &commands)
}

pub fn delete_certificate_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    slot: PivSlot,
) -> Result<()> {
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "slot F9 is reserved for the YubiKey attestation certificate".into(),
        ));
    }
    let command = build_delete_certificate_command(slot)?;
    transmit(transport, &command)
}

pub fn read_data_object_selected<T: CardTransport + ?Sized>(
    transport: &mut T,
    tag: &[u8],
) -> Result<Option<Vec<u8>>> {
    let command = build_get_data_command(tag)?;
    let (response, status) = transceive(transport, &command)?;
    match status {
        0x9000 => {
            let outer = tlv::parse(&response)?;
            let value = outer
                .into_iter()
                .find(|(tag, _)| *tag == 0x53)
                .map(|(_, value)| value)
                .ok_or_else(|| {
                    CredentialError::SmartCardOperation(
                        "GET DATA omitted the data object template".into(),
                    )
                })?;
            Ok(Some(value))
        }
        0x6a80 | 0x6a82 | 0x6a88 => Ok(None),
        other => Err(CredentialError::CardStatus(other)),
    }
}

pub fn build_csr_info(subject_dn: &str, spki_der: &[u8]) -> Result<(Vec<u8>, PivKeyAlgorithm)> {
    let public_key = SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let curve = public_key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters: &Any| parameters.decode_as::<const_oid::ObjectIdentifier>().ok())
        .ok_or_else(|| {
            CredentialError::UnsupportedOperation("CSR requires an EC public key".into())
        })?;
    let algorithm = if public_key.algorithm.oid == OID_EC_PUBLIC_KEY && curve == OID_P256 {
        PivKeyAlgorithm::EccP256
    } else if public_key.algorithm.oid == OID_EC_PUBLIC_KEY && curve == OID_P384 {
        PivKeyAlgorithm::EccP384
    } else {
        return Err(CredentialError::UnsupportedOperation(
            "CSR requires a P-256 or P-384 public key".into(),
        ));
    };
    let subject = Name::from_str(subject_dn)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let info = CertReqInfo {
        version: Version::V1,
        subject,
        public_key,
        attributes: Default::default(),
    };
    info.to_der()
        .map(|der| (der, algorithm))
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))
}

pub fn certificate_spki(certificate_der: &[u8]) -> Result<Vec<u8>> {
    Certificate::from_der(certificate_der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))
}

pub fn assemble_csr(
    info_der: &[u8],
    signature_der: &[u8],
    algorithm: PivKeyAlgorithm,
) -> Result<Vec<u8>> {
    let info = CertReqInfo::from_der(info_der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let signature = BitString::from_bytes(signature_der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let oid = match algorithm {
        PivKeyAlgorithm::EccP256 => OID_ECDSA_WITH_SHA256,
        PivKeyAlgorithm::EccP384 => OID_ECDSA_WITH_SHA384,
    };
    CertReq {
        info,
        algorithm: AlgorithmIdentifier {
            oid,
            parameters: None,
        },
        signature,
    }
    .to_der()
    .map_err(|error| CredentialError::CertificateParse(error.to_string()))
}

pub fn verify_csr(csr_der: &[u8]) -> Result<()> {
    let request = CertReq::from_der(csr_der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let info_der = request
        .info
        .to_der()
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let signature = request.signature.as_bytes().ok_or_else(|| {
        CredentialError::CertificateParse("CSR signature is not octet-aligned".into())
    })?;
    let key_der = request
        .info
        .public_key
        .to_der()
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    if request.algorithm.oid == OID_ECDSA_WITH_SHA256 {
        let key = P256VerifyingKey::from_public_key_der(&key_der)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let signature = P256Signature::from_der(signature)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let digest = Sha256::digest(&info_der);
        key.verify_prehash(&digest, &signature).map_err(|_| {
            CredentialError::CertificateParse("CSR signature verification failed".into())
        })
    } else if request.algorithm.oid == OID_ECDSA_WITH_SHA384 {
        let key = P384VerifyingKey::from_public_key_der(&key_der)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let signature = P384Signature::from_der(signature)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        let digest = Sha384::digest(&info_der);
        key.verify_prehash(&digest, &signature).map_err(|_| {
            CredentialError::CertificateParse("CSR signature verification failed".into())
        })
    } else {
        Err(CredentialError::UnsupportedOperation(
            "CSR signature algorithm is not ECDSA with SHA-256 or SHA-384".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner},
        elliptic_curve::sec1::ToSec1Point,
    };
    use pkcs1::der::Decode as Pkcs1Decode;
    struct ScriptedTransport(Vec<(Vec<u8>, Vec<u8>)>);

    impl CardTransport for ScriptedTransport {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            let (expected, response) = self.0.remove(0);
            assert_eq!(command, expected);
            Ok(response)
        }
    }

    fn response(data: &[u8], status: u16) -> Vec<u8> {
        [data, &status.to_be_bytes()].concat()
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let value = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(value, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn nist_aes_single_block_vectors_cover_all_management_key_sizes() {
        let plain = decode_hex("00112233445566778899aabbccddeeff");
        for (algorithm, key, encrypted) in [
            (
                ManagementKeyAlgorithm::Aes128,
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                ManagementKeyAlgorithm::Aes192,
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "dda97ca4864cdfe06eaf70a0ec0d7191",
            ),
            (
                ManagementKeyAlgorithm::Aes256,
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            let key = decode_hex(key);
            let cipher = aes_encrypt_block(algorithm, &key, &plain).unwrap();
            assert_eq!(cipher.as_slice(), decode_hex(encrypted));
            assert_eq!(
                aes_decrypt_block(algorithm, &key, &cipher).unwrap(),
                plain.as_slice()
            );
        }
    }

    #[test]
    fn verify_and_change_pin_and_puk_build_standard_apdus_and_map_retry_status() {
        let pin = PivPin::new(b"123456".to_vec()).unwrap();
        let new_pin = PivPin::new(b"654321".to_vec()).unwrap();
        let mut verify = ScriptedTransport(vec![
            (
                vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0, 0, 3, 8],
                response(&[], 0x9000),
            ),
            (
                vec![
                    0x00, 0x20, 0x00, 0x80, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff,
                ],
                response(&[], 0x63c2),
            ),
        ]);
        assert_eq!(
            verify_pin(&mut verify, &pin),
            Err(CredentialError::PinIncorrect { remaining: 2 })
        );

        let old_puk = PivPuk::new(b"12345678".to_vec()).unwrap();
        let new_puk = PivPuk::new(b"87654321".to_vec()).unwrap();
        let expected_prefix = vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0, 0, 3, 8];
        let mut change = ScriptedTransport(vec![
            (expected_prefix.clone(), response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x24, 0x00, 0x80, 0x10, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff,
                    b'6', b'5', b'4', b'3', b'2', b'1', 0xff, 0xff,
                ],
                response(&[], 0x9000),
            ),
            (expected_prefix, response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x24, 0x00, 0x81, 0x10, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
                    b'8', b'7', b'6', b'5', b'4', b'3', b'2', b'1',
                ],
                response(&[], 0x9000),
            ),
        ]);
        change_pin(&mut change, &pin, &new_pin).unwrap();
        change_puk(&mut change, &old_puk, &new_puk).unwrap();
    }

    #[test]
    fn pin_complexity_is_typed_only_for_pin_and_puk_changes() {
        let pin = PivPin::new(b"123456".to_vec()).unwrap();
        let new_pin = PivPin::new(b"654321".to_vec()).unwrap();
        let puk = PivPuk::new(b"12345678".to_vec()).unwrap();
        let new_puk = PivPuk::new(b"87654321".to_vec()).unwrap();
        let select_apdu = vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0, 0, 3, 8];

        let mut change_pin_rejected = ScriptedTransport(vec![
            (select_apdu.clone(), response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x24, 0x00, 0x80, 0x10, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff,
                    b'6', b'5', b'4', b'3', b'2', b'1', 0xff, 0xff,
                ],
                response(&[], 0x6985),
            ),
        ]);
        assert_eq!(
            change_pin(&mut change_pin_rejected, &pin, &new_pin),
            Err(CredentialError::PinComplexity)
        );

        let mut change_puk_rejected = ScriptedTransport(vec![
            (select_apdu.clone(), response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x24, 0x00, 0x81, 0x10, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
                    b'8', b'7', b'6', b'5', b'4', b'3', b'2', b'1',
                ],
                response(&[], 0x6985),
            ),
        ]);
        assert_eq!(
            change_puk(&mut change_puk_rejected, &puk, &new_puk),
            Err(CredentialError::PukComplexity)
        );

        let mut unblock_rejected = ScriptedTransport(vec![
            (select_apdu.clone(), response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x2c, 0x00, 0x80, 0x10, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
                    b'6', b'5', b'4', b'3', b'2', b'1', 0xff, 0xff,
                ],
                response(&[], 0x6985),
            ),
        ]);
        assert_eq!(
            unblock_pin(&mut unblock_rejected, &puk, &new_pin),
            Err(CredentialError::PinComplexity)
        );

        let mut verify_unchanged = ScriptedTransport(vec![
            (select_apdu.clone(), response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x20, 0x00, 0x80, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff,
                ],
                response(&[], 0x6985),
            ),
        ]);
        assert_eq!(
            verify_pin(&mut verify_unchanged, &pin),
            Err(CredentialError::CardStatus(0x6985))
        );

        let mut other_status = ScriptedTransport(vec![
            (select_apdu, response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x24, 0x00, 0x80, 0x10, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff,
                    b'6', b'5', b'4', b'3', b'2', b'1', 0xff, 0xff,
                ],
                response(&[], 0x6a80),
            ),
        ]);
        assert_eq!(
            change_pin(&mut other_status, &pin, &new_pin),
            Err(CredentialError::CardStatus(0x6a80))
        );
    }

    #[test]
    fn unblock_pin_and_blocked_statuses_are_typed() {
        let puk = PivPuk::new(b"12345678".to_vec()).unwrap();
        let pin = PivPin::new(b"654321".to_vec()).unwrap();
        let select_apdu = vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0, 0, 3, 8];
        let mut transport = ScriptedTransport(vec![
            (select_apdu.clone(), response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x2c, 0x00, 0x80, 0x10, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
                    b'6', b'5', b'4', b'3', b'2', b'1', 0xff, 0xff,
                ],
                response(&[], 0x63c3),
            ),
            (select_apdu.clone(), response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x20, 0x00, 0x80, 0x08, b'6', b'5', b'4', b'3', b'2', b'1', 0xff, 0xff,
                ],
                response(&[], 0x6983),
            ),
        ]);
        assert_eq!(
            unblock_pin(&mut transport, &puk, &pin),
            Err(CredentialError::PukIncorrect { remaining: 3 })
        );
        assert_eq!(
            verify_pin(&mut transport, &pin),
            Err(CredentialError::PinBlocked)
        );

        let mut blocked_puk = ScriptedTransport(vec![
            (select_apdu, response(&[], 0x9000)),
            (
                vec![
                    0x00, 0x2c, 0x00, 0x80, 0x10, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
                    b'6', b'5', b'4', b'3', b'2', b'1', 0xff, 0xff,
                ],
                response(&[], 0x6983),
            ),
        ]);
        assert_eq!(
            unblock_pin(&mut blocked_puk, &puk, &pin),
            Err(CredentialError::PukBlocked)
        );
    }

    #[test]
    fn management_authentication_verifies_card_response_and_rejects_mismatch() {
        let management_key = ManagementKey::new(
            ManagementKeyAlgorithm::Aes128,
            decode_hex("000102030405060708090a0b0c0d0e0f"),
        )
        .unwrap();
        let witness = decode_hex("00112233445566778899aabbccddeeff");
        let encrypted_witness = decode_hex("69c4e0d86a7b0430d8cdb78070b4c55a");
        let challenge = [0x00u8; 16];
        let encrypted_challenge = decode_hex("c6a13b37878f5b826f4f8162a1c8d879");
        let first = vec![0x00, 0x87, 0x08, 0x9b, 0x04, 0x7c, 0x02, 0x80, 0x00];
        let mut first_response = vec![0x7c, 0x12, 0x80, 0x10];
        first_response.extend_from_slice(&encrypted_witness);
        let mut second = vec![0x00, 0x87, 0x08, 0x9b, 0x26, 0x7c, 0x24, 0x80, 0x10];
        second.extend_from_slice(&witness);
        second.extend_from_slice(&[0x81, 0x10]);
        second.extend_from_slice(&challenge);
        let mut expected_card_response = vec![0x7c, 0x12, 0x82, 0x10];
        expected_card_response.extend_from_slice(&encrypted_challenge);
        let mut good = ScriptedTransport(vec![
            (first.clone(), response(&first_response, 0x9000)),
            (second.clone(), response(&expected_card_response, 0x9000)),
        ]);
        authenticate_management_key_with_challenge(&mut good, &management_key, Some(challenge))
            .unwrap();

        let mut wrong_response_data = vec![0x7c, 0x12, 0x82, 0x10];
        wrong_response_data.extend_from_slice(&decode_hex("4a1f4c8e6b2d0a9c7e5f3d1b8a6c2e0f"));
        let wrong_response = response(&wrong_response_data, 0x9000);
        let mut bad = ScriptedTransport(vec![
            (first.clone(), response(&first_response, 0x9000)),
            (second.clone(), wrong_response),
        ]);
        assert_eq!(
            authenticate_management_key_with_challenge(&mut bad, &management_key, Some(challenge)),
            Err(CredentialError::ManagementKeyIncorrect)
        );

        let wrong_82_length = response(&[0x7c, 0x0a, 0x82, 0x08, 1, 2, 3, 4, 5, 6, 7, 8], 0x9000);
        let mut malformed = ScriptedTransport(vec![
            (first.clone(), response(&first_response, 0x9000)),
            (second.clone(), wrong_82_length),
        ]);
        assert_eq!(
            authenticate_management_key_with_challenge(
                &mut malformed,
                &management_key,
                Some(challenge)
            ),
            Err(CredentialError::ManagementKeyIncorrect)
        );

        let mut wrong_algorithm = ScriptedTransport(vec![(first, response(&[], 0x6a80))]);
        assert_eq!(
            authenticate_management_key_with_challenge(
                &mut wrong_algorithm,
                &management_key,
                Some(challenge)
            ),
            Err(CredentialError::ManagementKeyIncorrect)
        );
    }

    #[test]
    fn management_authentication_accepts_the_challenge_under_tag_82_or_80() {
        let management_key = ManagementKey::new(
            ManagementKeyAlgorithm::Aes128,
            decode_hex("000102030405060708090a0b0c0d0e0f"),
        )
        .unwrap();
        let witness = decode_hex("00112233445566778899aabbccddeeff");
        let encrypted_witness = decode_hex("69c4e0d86a7b0430d8cdb78070b4c55a");
        let challenge = [0x00u8; 16];
        let encrypted_challenge = decode_hex("c6a13b37878f5b826f4f8162a1c8d879");
        let first = vec![0x00, 0x87, 0x08, 0x9b, 0x04, 0x7c, 0x02, 0x80, 0x00];
        let mut first_response = vec![0x7c, 0x12, 0x80, 0x10];
        first_response.extend_from_slice(&encrypted_witness);
        let mut second = vec![0x00, 0x87, 0x08, 0x9b, 0x26, 0x7c, 0x24, 0x80, 0x10];
        second.extend_from_slice(&witness);
        second.extend_from_slice(&[0x81, 0x10]);
        second.extend_from_slice(&challenge);
        let answer = |tag: u8, value: &[u8]| {
            let mut data = vec![0x7c, 0x12, tag, 0x10];
            data.extend_from_slice(value);
            response(&data, 0x9000)
        };

        let mut tag_82 = ScriptedTransport(vec![
            (first.clone(), response(&first_response, 0x9000)),
            (second.clone(), answer(0x82, &encrypted_challenge)),
        ]);
        authenticate_management_key_with_challenge(&mut tag_82, &management_key, Some(challenge))
            .unwrap();

        let mut tag_80 = ScriptedTransport(vec![
            (first.clone(), response(&first_response, 0x9000)),
            (second.clone(), answer(0x80, &encrypted_challenge)),
        ]);
        authenticate_management_key_with_challenge(&mut tag_80, &management_key, Some(challenge))
            .unwrap();

        let mut wrong_80 = ScriptedTransport(vec![
            (first.clone(), response(&first_response, 0x9000)),
            (
                second.clone(),
                answer(0x80, &decode_hex("4a1f4c8e6b2d0a9c7e5f3d1b8a6c2e0f")),
            ),
        ]);
        assert_eq!(
            authenticate_management_key_with_challenge(
                &mut wrong_80,
                &management_key,
                Some(challenge)
            ),
            Err(CredentialError::ManagementKeyIncorrect)
        );

        let mut neither = ScriptedTransport(vec![
            (first, response(&first_response, 0x9000)),
            (second, response(&[], 0x9000)),
        ]);
        assert!(matches!(
            authenticate_management_key_with_challenge(&mut neither, &management_key, Some(challenge)),
            Err(CredentialError::SmartCardOperation(message)) if message.contains("tag 82 or 80")
        ));
    }
    #[test]
    fn generate_and_sign_apdus_parse_public_key_and_der_signature() {
        let slot = PivSlot::AUTHENTICATION;
        let command = generate_key_command(
            slot,
            PivKeyAlgorithm::EccP256,
            Some((PinPolicy::Once, TouchPolicy::Never)),
        )
        .unwrap();
        let omitted = generate_key_command(slot, PivKeyAlgorithm::EccP256, None).unwrap();
        let defaults = generate_key_command(
            slot,
            PivKeyAlgorithm::EccP256,
            Some((PinPolicy::Default, TouchPolicy::Default)),
        )
        .unwrap();
        assert_eq!(omitted, defaults);
        assert_eq!(
            omitted,
            vec![0x00, 0x47, 0x00, 0x9a, 0x05, 0xac, 0x03, 0x80, 0x01, 0x11]
        );
        assert_eq!(
            command,
            vec![
                0x00, 0x47, 0x00, 0x9a, 0x0b, 0xac, 0x09, 0x80, 0x01, 0x11, 0xaa, 0x01, 0x02, 0xab,
                0x01, 0x01
            ]
        );
        let point = p256::SecretKey::from_slice(&[7u8; 32])
            .unwrap()
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let template = tlv::encode(0x7f49, &tlv::encode(0x86, &point).unwrap()).unwrap();
        let mut generated = ScriptedTransport(vec![(command.clone(), response(&template, 0x9000))]);
        let (response_data, status) = transceive(&mut generated, &command).unwrap();
        assert_eq!(status, 0x9000);
        let spki = parse_generated_public_key(&response_data, PivKeyAlgorithm::EccP256).unwrap();
        let subject = Name::from_str("CN=Sigil test").unwrap();
        let info = CertReqInfo {
            version: Version::V1,
            subject,
            public_key: SubjectPublicKeyInfo::from_der(&spki).unwrap(),
            attributes: Default::default(),
        };
        let info_der = info.to_der().unwrap();
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let digest = Sha256::digest(&info_der);
        let signature: Signature = signing_key.sign_prehash(&digest).unwrap();
        let csr = assemble_csr(
            &info_der,
            signature.to_der().as_bytes(),
            PivKeyAlgorithm::EccP256,
        )
        .unwrap();
        verify_csr(&csr).unwrap();
        let invalid = assemble_csr(&info_der, &[0x30, 0x00], PivKeyAlgorithm::EccP256).unwrap();
        assert!(verify_csr(&invalid).is_err());

        let digest = [0x55; 32];
        let sign_command = sign_digest_command(slot, PivKeyAlgorithm::EccP256, &digest).unwrap();
        assert_eq!(
            sign_command,
            vec![
                0x00, 0x87, 0x11, 0x9a, 0x26, 0x7c, 0x24, 0x82, 0x00, 0x81, 0x20
            ]
            .into_iter()
            .chain(digest)
            .collect::<Vec<_>>()
        );
        let signature_der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let sign_response = tlv::encode(0x7c, &tlv::encode(0x82, &signature_der).unwrap()).unwrap();
        let mut signer = ScriptedTransport(vec![(sign_command, response(&sign_response, 0x9000))]);
        assert_eq!(
            sign_digest_selected(&mut signer, slot, PivKeyAlgorithm::EccP256, &digest).unwrap(),
            signature_der
        );
    }

    #[test]
    fn certificate_put_delete_and_data_read_build_apdus() {
        let cert = b"certificate";
        let commands = build_put_certificate_commands(PivSlot::AUTHENTICATION, cert).unwrap();
        assert_eq!(commands.len(), 1);
        let command = commands[0].clone();
        assert_eq!(&command[..4], &[0x00, 0xdb, 0x3f, 0xff]);
        assert_eq!(command[4], 0x19);
        let mut put = ScriptedTransport(vec![(command, response(&[], 0x9000))]);
        put_certificate_selected(&mut put, PivSlot::AUTHENTICATION, cert).unwrap();
        let delete = build_delete_certificate_command(PivSlot::AUTHENTICATION).unwrap();
        assert_eq!(
            delete,
            vec![
                0x00, 0xdb, 0x3f, 0xff, 0x07, 0x5c, 0x03, 0x5f, 0xc1, 0x05, 0x53, 0x00
            ]
        );
        let mut delete_transport = ScriptedTransport(vec![(delete, response(&[], 0x9000))]);
        delete_certificate_selected(&mut delete_transport, PivSlot::AUTHENTICATION).unwrap();
        assert_eq!(
            build_get_data_command(&[0x5f, 0xff, 0x01]).unwrap(),
            vec![
                0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xff, 0x01, 0x00
            ]
        );
        let object = tlv::encode(0x53, b"f9 certificate").unwrap();
        let mut transport = ScriptedTransport(vec![(
            build_get_data_command(&[0x5f, 0xff, 0x01]).unwrap(),
            response(&object, 0x9000),
        )]);
        assert_eq!(
            read_data_object_selected(&mut transport, &[0x5f, 0xff, 0x01]).unwrap(),
            Some(b"f9 certificate".to_vec())
        );
    }

    #[test]
    fn large_certificate_put_uses_short_lc_chaining_and_reassembles_exactly() {
        let certificate = vec![0xa5; 600];
        let data = build_put_certificate_data(PivSlot::AUTHENTICATION, &certificate).unwrap();
        let commands =
            build_put_certificate_commands(PivSlot::AUTHENTICATION, &certificate).unwrap();

        assert_eq!(commands.len(), 3);
        assert_eq!(
            commands
                .iter()
                .map(|command| command[0])
                .collect::<Vec<_>>(),
            vec![0x10, 0x10, 0x00]
        );
        assert_eq!(
            commands
                .iter()
                .map(|command| usize::from(command[4]))
                .collect::<Vec<_>>(),
            vec![255, 255, data.len() - 510]
        );
        assert!(
            commands
                .iter()
                .all(|command| command.len() == usize::from(command[4]) + 5)
        );
        let reassembled: Vec<_> = commands
            .iter()
            .flat_map(|command| command[5..].iter().copied())
            .collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn intermediate_chaining_error_stops_before_the_remaining_chunks() {
        let certificate = vec![0x5a; 600];
        let commands =
            build_put_certificate_commands(PivSlot::AUTHENTICATION, &certificate).unwrap();
        let mut transport = ScriptedTransport(vec![
            (commands[0].clone(), response(&[], 0x9000)),
            (commands[1].clone(), response(&[], 0x6a80)),
        ]);

        assert_eq!(
            put_certificate_selected(&mut transport, PivSlot::AUTHENTICATION, &certificate),
            Err(CredentialError::CardStatus(0x6a80))
        );
        assert!(transport.0.is_empty(), "third chunk must not be sent");
    }

    #[test]
    fn metadata_public_key_parser_builds_rsa_spki() {
        let certificate = Certificate::from_der(include_bytes!(
            "../../sigil-mock/fixtures/piv-9d-rsa2048.der"
        ))
        .unwrap();
        let expected_spki = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();
        let rsa_der = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .unwrap();
        let rsa = pkcs1::RsaPublicKey::from_der(rsa_der).unwrap();
        let mut metadata = tlv::encode(0x81, rsa.modulus.as_bytes()).unwrap();
        metadata.extend_from_slice(&tlv::encode(0x82, rsa.public_exponent.as_bytes()).unwrap());
        assert_eq!(
            public_key_spki_from_metadata(PivAlgorithm::Rsa2048, &metadata).unwrap(),
            expected_spki
        );
    }
}
