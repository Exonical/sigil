//! Thales (SafeNet, formerly Gemalto) PIV tokens.
//!
//! This crate holds Thales-specific identity and key-generation preparation. Standard PIV operations live in
//! sigil-piv. The GlobalPlatform CPLC IC serial is available over USB and NFC, unlike USB iSerialNumber.

use sigil_core::{
    CredentialError, ManagementKey, ManagementKeyAlgorithm, PivKeyAlgorithm, PivSlot, Result,
};
use sigil_piv::{
    CardTransport,
    vendor::{PivCapabilities, PivVendor},
};

/// Historical bytes that identify the IDPrime family in the ATR (80 31 80 65 B0). A substring match is enough for this
/// family; the ATR of a non-Thales card does not contain this five-byte sequence.
const IDPRIME_HISTORICAL_BYTES: [u8; 5] = [0x80, 0x31, 0x80, 0x65, 0xb0];
const GP_CARD_MANAGER_SELECT: [u8; 14] = [
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
];
const GET_CPLC: [u8; 5] = [0x80, 0xca, 0x9f, 0x7f, 0x00];
const CPLC_LENGTH: usize = 42;
const CPLC_TAG_AND_LENGTH: [u8; 3] = [0x9f, 0x7f, 0x2a];

/// Whether an ATR belongs to the Thales IDPrime PIV family.
pub fn is_thales_atr(atr: &[u8]) -> bool {
    atr.windows(IDPRIME_HISTORICAL_BYTES.len())
        .any(|window| window == IDPRIME_HISTORICAL_BYTES)
}

/// Card production data from the GlobalPlatform CPLC object. Only the fields Sigil uses are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cplc {
    pub ic_fabricator: [u8; 2],
    pub ic_type: [u8; 2],
    pub os_id: [u8; 2],
    pub os_release_date: [u8; 2],
    pub os_release_level: [u8; 2],
    pub ic_serial: [u8; 4],
    pub ic_batch: [u8; 2],
}

/// The device serial Sigil reports for a Thales token: the IC serial number as uppercase hex, for example `540F9B50`.
/// This matches what the card reports on USB and NFC. If a vendor tool shows a different number, the mapping changes
/// here and the device identifier changes with it.
pub fn serial(cplc: &Cplc) -> String {
    cplc.ic_serial
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

/// Reads the CPLC object, then re-selects the PIV application so the caller's applet selection is unchanged.
pub fn read_cplc<T: CardTransport + ?Sized>(transport: &mut T) -> Result<Cplc> {
    let cplc = read_cplc_object(transport);
    let reselect = sigil_piv::select(transport);
    let cplc = cplc?;
    reselect?;
    Ok(cplc)
}

fn read_cplc_object<T: CardTransport + ?Sized>(transport: &mut T) -> Result<Cplc> {
    let (_, sw) = sigil_piv::transceive(transport, &GP_CARD_MANAGER_SELECT)?;
    if sw != 0x9000 {
        return Err(CredentialError::CardStatus(sw));
    }
    let (data, sw) = sigil_piv::transceive(transport, &GET_CPLC)?;
    if sw != 0x9000 {
        return Err(CredentialError::CardStatus(sw));
    }
    parse_cplc(&data)
}

/// Parses the CPLC object, with or without its 9F 7F 2A wrapper.
pub fn parse_cplc(data: &[u8]) -> Result<Cplc> {
    let body = if data.len() == CPLC_LENGTH + CPLC_TAG_AND_LENGTH.len()
        && data.starts_with(&CPLC_TAG_AND_LENGTH)
    {
        &data[CPLC_TAG_AND_LENGTH.len()..]
    } else if data.len() == CPLC_LENGTH {
        data
    } else {
        return Err(CredentialError::SmartCardOperation(format!(
            "CPLC object has unexpected length {}",
            data.len()
        )));
    };
    let field2 = |start: usize| [body[start], body[start + 1]];
    Ok(Cplc {
        ic_fabricator: field2(0),
        ic_type: field2(2),
        os_id: field2(4),
        os_release_date: field2(6),
        os_release_level: field2(8),
        ic_serial: [body[12], body[13], body[14], body[15]],
        ic_batch: field2(16),
    })
}

/// Checks that the token's CPLC serial matches the expected serial and returns it. Runs inside the caller's
/// transaction.
pub fn verify_serial<T: CardTransport + ?Sized>(
    transport: &mut T,
    expected: &str,
) -> Result<String> {
    let cplc = read_cplc(transport)?;
    let actual = serial(&cplc);
    if actual.eq_ignore_ascii_case(expected) {
        Ok(actual)
    } else {
        Err(CredentialError::DeviceMismatch)
    }
}

/// The Thales IDPrime PIV applet. It uses a vendor-specific CPLC serial and preloads EC domain parameters into a
/// Thales key object before the standard GENERATE instruction.
pub struct ThalesPiv;

impl PivVendor for ThalesPiv {
    fn name(&self) -> &'static str {
        "Thales"
    }

    fn capabilities(&self) -> PivCapabilities {
        PivCapabilities {
            piv_writes: true,
            set_management_key: true,
            p384_generation: false,
            retired_slot_generation: false,
            ..PivCapabilities::default()
        }
    }

    fn set_management_key(
        &self,
        transport: &mut dyn CardTransport,
        new_key: &ManagementKey,
    ) -> Result<()> {
        let command = set_management_key_command(new_key)?;
        let (_, sw) = sigil_piv::transceive(transport, &command)?;
        if sw == 0x9000 {
            Ok(())
        } else {
            Err(CredentialError::CardStatus(sw))
        }
    }

    fn ensure_chuid_on_import(&self) -> bool {
        true
    }

    fn prepare_key_generation(
        &self,
        transport: &mut dyn CardTransport,
        slot: PivSlot,
        algorithm: PivKeyAlgorithm,
    ) -> Result<()> {
        let object_id = thales_key_object_id(slot).ok_or_else(|| {
            CredentialError::UnsupportedOperation(format!(
                "Thales key generation is not supported for slot {slot}"
            ))
        })?;
        // RSA key generation has no captured Thales parameter-preparation sequence.
        let (algorithm_id, parameters) = match algorithm {
            PivKeyAlgorithm::EccP256 => (0x11, p256_parameters()),
            PivKeyAlgorithm::EccP384 => (0x14, p384_parameters()),
        };
        for (tag, value) in parameters {
            put_key_parameter(transport, object_id, algorithm_id, tag, &value)?;
        }
        Ok(())
    }

    fn verify_serial(&self, transport: &mut dyn CardTransport, expected: &str) -> Result<String> {
        verify_serial(transport, expected)
    }
}

fn thales_key_object_id(slot: PivSlot) -> Option<u8> {
    // Only 9C -> FF900C is in the SAC capture. The other standard and retired-slot IDs are inferred from the
    // observed SAC wipe of FF900A/0C/0D/retired objects and read of FF900E.
    match slot.byte() {
        0x9a => Some(0x0a),
        0x9c => Some(0x0c),
        0x9d => Some(0x0d),
        0x9e => Some(0x0e),
        0x82..=0x95 => Some(0x10 + slot.byte() - 0x82),
        _ => None,
    }
}

/// Thales stores the PIV management key in object FF840B. AES-128 is captured in SAC; AES-192 and AES-256 use the
/// standard PIV algorithm identifiers by analogy and have not been verified on hardware.
fn set_management_key_command(new_key: &ManagementKey) -> Result<Vec<u8>> {
    let algorithm_id = match new_key.algorithm() {
        ManagementKeyAlgorithm::Aes128 => 0x08,
        ManagementKeyAlgorithm::Aes192 => 0x0a,
        ManagementKeyAlgorithm::Aes256 => 0x0c,
    };
    let mut fields = sigil_piv::tlv::encode(0x80, &[algorithm_id])?;
    fields.extend_from_slice(&sigil_piv::tlv::encode(0x90, new_key.as_bytes())?);
    let template = sigil_piv::tlv::encode(0x7f4a, &fields)?;
    let mut data = sigil_piv::tlv::encode(0x5c, &[0xff, 0x84, 0x0b])?;
    data.extend_from_slice(&template);
    if data.len() > u8::MAX as usize {
        return Err(CredentialError::SmartCardOperation(
            "Thales management-key APDU exceeds short Lc".into(),
        ));
    }
    let mut command = vec![0x00, 0xdb, 0x3f, 0xff, data.len() as u8];
    command.extend_from_slice(&data);
    command.push(0x00);
    Ok(command)
}

fn p256_parameters() -> Vec<(u8, Vec<u8>)> {
    vec![
        (
            0x81,
            hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
        ),
        (
            0x82,
            hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
        ),
        (
            0x83,
            hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
        ),
        (
            0x84,
            hex(
                "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            ),
        ),
        (
            0x85,
            hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
        ),
        (0x87, vec![0x00, 0x01]),
    ]
}

/// P-384 parameters follow SEC 2 by analogy with the captured P-256 writes; this encoding is untested on hardware.
fn p384_parameters() -> Vec<(u8, Vec<u8>)> {
    vec![
        (
            0x81,
            hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            ),
        ),
        (
            0x82,
            hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
            ),
        ),
        (
            0x83,
            hex(
                "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            ),
        ),
        (
            0x84,
            hex(
                "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            ),
        ),
        (
            0x85,
            hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
            ),
        ),
        (0x87, vec![0x00, 0x01]),
    ]
}

fn put_key_parameter(
    transport: &mut dyn CardTransport,
    object_id: u8,
    algorithm_id: u8,
    tag: u8,
    value: &[u8],
) -> Result<()> {
    let mut key_parameters = sigil_piv::tlv::encode(0x80, &[algorithm_id])?;
    key_parameters.extend_from_slice(&sigil_piv::tlv::encode(tag.into(), value)?);
    let template = sigil_piv::tlv::encode(0x7f49, &key_parameters)?;
    let object = [0xff, 0x90, object_id];
    let mut data = sigil_piv::tlv::encode(0x5c, &object)?;
    data.extend_from_slice(&template);
    if data.len() > u8::MAX as usize {
        return Err(CredentialError::SmartCardOperation(
            "Thales key parameter APDU exceeds short Lc".into(),
        ));
    }
    let mut command = vec![0x00, 0xdb, 0x3f, 0xff, data.len() as u8];
    command.extend_from_slice(&data);
    command.push(0x00);
    let (_, sw) = sigil_piv::transceive(transport, &command)?;
    if sw == 0x9000 {
        Ok(())
    } else {
        Err(CredentialError::CardStatus(sw))
    }
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("valid hex constant"))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use p384::PublicKey as P384PublicKey;
    use sigil_core::KeyStatus;

    use super::*;

    /// The ATR of the SafeNet eToken Fusion NFC PIV token from the round-one probe.
    const THALES_ATR: &str = "3BFF9600008131FE4380318065B088666B3912017882900045";
    /// A YubiKey 5 ATR, which must not match.
    const YUBIKEY_ATR: &str = "3BFD1300008131FE158073C021C0575975626 94B657940";
    /// The probe's CPLC response, including the 9F 7F 2A wrapper.
    const CPLC_WRAPPED: &str = "9F7F2A409000391981122105005094540F9B50B2C3129250941293509412945094000000020000000000000000";

    fn bytes(hex: &str) -> Vec<u8> {
        let digits: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        (0..digits.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&digits[index..index + 2], 16).unwrap())
            .collect()
    }

    struct ScriptedTransport(VecDeque<(Vec<u8>, Vec<u8>)>);

    impl CardTransport for ScriptedTransport {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            let (expected, response) = self.0.pop_front().expect("unexpected APDU");
            assert_eq!(command, expected);
            Ok(response)
        }
    }

    fn piv_select() -> Vec<u8> {
        vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08]
    }

    fn ok(data: &[u8]) -> Vec<u8> {
        [data, &[0x90, 0x00]].concat()
    }

    struct RecordingTransport(Vec<Vec<u8>>);

    impl CardTransport for RecordingTransport {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            self.0.push(command.to_vec());
            Ok(vec![0x90, 0x00])
        }
    }

    #[test]
    fn recognises_the_thales_atr_and_rejects_yubikey() {
        assert!(is_thales_atr(&bytes(THALES_ATR)));
        assert!(!is_thales_atr(&bytes(YUBIKEY_ATR)));
        assert!(!is_thales_atr(&[]));
    }

    #[test]
    fn parses_wrapped_and_bare_cplc_and_formats_the_serial() {
        let wrapped = bytes(CPLC_WRAPPED);
        let cplc = parse_cplc(&wrapped).unwrap();
        assert_eq!(serial(&cplc), "540F9B50");
        assert_eq!(cplc.ic_batch, [0xb2, 0xc3]);
        assert_eq!(cplc.ic_fabricator, [0x40, 0x90]);
        assert_eq!(parse_cplc(&wrapped[3..]).unwrap(), cplc);
        assert!(parse_cplc(&wrapped[..10]).is_err());
    }

    #[test]
    fn reads_cplc_and_reselects_piv() {
        let mut transport = ScriptedTransport(VecDeque::from([
            (GP_CARD_MANAGER_SELECT.to_vec(), ok(&[])),
            (GET_CPLC.to_vec(), ok(&bytes(CPLC_WRAPPED))),
            (piv_select(), ok(&[])),
        ]));
        let cplc = read_cplc(&mut transport).unwrap();
        assert_eq!(serial(&cplc), "540F9B50");
        assert!(transport.0.is_empty(), "PIV must be re-selected last");
    }

    #[test]
    fn reselects_piv_even_when_cplc_fails() {
        let mut transport = ScriptedTransport(VecDeque::from([
            (GP_CARD_MANAGER_SELECT.to_vec(), vec![0x6a, 0x82]),
            (piv_select(), ok(&[])),
        ]));
        assert_eq!(
            read_cplc(&mut transport),
            Err(CredentialError::CardStatus(0x6a82))
        );
        assert!(transport.0.is_empty());
    }

    #[test]
    fn verify_serial_matches_only_the_cplc_serial() {
        let steps = || {
            VecDeque::from([
                (GP_CARD_MANAGER_SELECT.to_vec(), ok(&[])),
                (GET_CPLC.to_vec(), ok(&bytes(CPLC_WRAPPED))),
                (piv_select(), ok(&[])),
            ])
        };
        let mut matching = ScriptedTransport(steps());
        assert_eq!(
            verify_serial(&mut matching, "540f9b50").unwrap(),
            "540F9B50"
        );
        let mut other = ScriptedTransport(steps());
        assert_eq!(
            verify_serial(&mut other, "12345678"),
            Err(CredentialError::DeviceMismatch)
        );
    }

    #[test]
    fn thales_piv_reads_standard_slots_and_takes_the_default_capabilities() {
        struct Answers;
        impl CardTransport for Answers {
            fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
                match command[1] {
                    0xa4 => Ok(vec![0x90, 0x00]),
                    0xcb => Ok(vec![0x6a, 0x80]),
                    _ => Err(CredentialError::SmartCardOperation(
                        "unexpected APDU".into(),
                    )),
                }
            }
        }
        assert_eq!(ThalesPiv.name(), "Thales");
        assert_eq!(
            ThalesPiv.capabilities(),
            sigil_piv::vendor::PivCapabilities {
                piv_writes: true,
                set_management_key: true,
                p384_generation: false,
                retired_slot_generation: false,
                ..sigil_piv::vendor::PivCapabilities::default()
            }
        );
        assert!(ThalesPiv.ensure_chuid_on_import());
        let entries = sigil_piv::ops::read_slots(&mut Answers, &ThalesPiv).unwrap();
        assert_eq!(entries.len(), 4);
        assert!(
            entries
                .iter()
                .all(|entry| entry.certificate.is_none() && entry.key == KeyStatus::Unknown)
        );
    }

    #[test]
    fn prepares_p256_parameters_for_slot_9c_with_the_captured_apdus() {
        let captured = [
            "00DB3FFF2D5C03FF900C7F49258001118120FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF00",
            "00DB3FFF2D5C03FF900C7F49258001118220FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC00",
            "00DB3FFF2D5C03FF900C7F492580011183205AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B00",
            "00DB3FFF4E5C03FF900C7F49468001118441046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F500",
            "00DB3FFF2D5C03FF900C7F49258001118520FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63255100",
            "00DB3FFF0F5C03FF900C7F49078001118702000100",
        ]
        .map(bytes);
        let steps = captured
            .iter()
            .map(|command| (command.clone(), ok(&[])))
            .collect();
        let mut transport = ScriptedTransport(steps);

        ThalesPiv
            .prepare_key_generation(&mut transport, PivSlot::SIGNATURE, PivKeyAlgorithm::EccP256)
            .unwrap();
        assert!(transport.0.is_empty(), "all six captured APDUs were used");
    }

    #[test]
    fn p256_and_p384_parameters_have_expected_lengths_and_valid_generators() {
        for (parameters, coordinate_len) in
            [(p256_parameters(), 32usize), (p384_parameters(), 48usize)]
        {
            assert_eq!(parameters.len(), 6);
            for tag in [0x81, 0x82, 0x83, 0x85] {
                let value = &parameters
                    .iter()
                    .find(|(parameter_tag, _)| *parameter_tag == tag)
                    .unwrap()
                    .1;
                assert_eq!(value.len(), coordinate_len, "parameter tag {tag:02X}");
            }
            let generator = &parameters.iter().find(|(tag, _)| *tag == 0x84).unwrap().1;
            assert_eq!(generator.len(), coordinate_len * 2 + 1);
            assert_eq!(generator[0], 0x04);
            assert_eq!(
                parameters
                    .iter()
                    .find(|(tag, _)| *tag == 0x87)
                    .unwrap()
                    .1
                    .len(),
                2
            );
        }

        let p384 = p384_parameters();
        for (tag, expected) in [
            (
                0x81,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
            ),
            (
                0x83,
                "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
            ),
            (
                0x85,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
            ),
        ] {
            assert_eq!(
                p384.iter()
                    .find(|(actual_tag, _)| *actual_tag == tag)
                    .unwrap()
                    .1,
                hex(expected)
            );
        }

        assert!(
            sigil_piv::management::public_key_spki(
                PivKeyAlgorithm::EccP256,
                &p256_parameters()
                    .into_iter()
                    .find(|(tag, _)| tag == &0x84)
                    .unwrap()
                    .1
            )
            .is_ok()
        );
        assert!(
            P384PublicKey::from_sec1_bytes(
                &p384_parameters()
                    .into_iter()
                    .find(|(tag, _)| tag == &0x84)
                    .unwrap()
                    .1
            )
            .is_ok()
        );
    }

    #[test]
    fn p384_slot_9a_preparation_uses_six_short_lc_apdus() {
        let mut transport = RecordingTransport(Vec::new());
        ThalesPiv
            .prepare_key_generation(
                &mut transport,
                PivSlot::AUTHENTICATION,
                PivKeyAlgorithm::EccP384,
            )
            .unwrap();
        assert_eq!(transport.0.len(), 6);
        for command in &transport.0 {
            assert_eq!(&command[..4], &[0x00, 0xdb, 0x3f, 0xff]);
            assert_eq!(usize::from(command[4]), command.len() - 6);
            assert!(command.len() <= 261);
            assert_eq!(command.last(), Some(&0x00));
            assert_eq!(&command[7..10], &[0xff, 0x90, 0x0a]);
        }
    }

    #[test]
    fn maps_slot_9a_to_thales_key_object_ff900a() {
        let mut transport = RecordingTransport(Vec::new());
        ThalesPiv
            .prepare_key_generation(
                &mut transport,
                PivSlot::AUTHENTICATION,
                PivKeyAlgorithm::EccP256,
            )
            .unwrap();
        assert_eq!(&transport.0[0][7..10], &[0xff, 0x90, 0x0a]);
    }

    #[test]
    fn refused_slot_sends_no_apdu() {
        let mut transport = RecordingTransport(Vec::new());
        assert!(matches!(
            ThalesPiv.prepare_key_generation(
                &mut transport,
                PivSlot::ATTESTATION,
                PivKeyAlgorithm::EccP256,
            ),
            Err(CredentialError::UnsupportedOperation(_))
        ));
        assert!(transport.0.is_empty());
    }

    #[test]
    fn sets_aes128_management_key_with_the_captured_apdu_shape() {
        let key = ManagementKey::new(ManagementKeyAlgorithm::Aes128, vec![0x22; 16]).unwrap();
        let mut expected = bytes("00DB3FFF1D5C03FF840B7F4A158001089010");
        expected.extend_from_slice(&[0x22; 16]);
        expected.push(0x00);
        let mut transport = ScriptedTransport(VecDeque::from([(expected, ok(&[]))]));
        ThalesPiv.set_management_key(&mut transport, &key).unwrap();
        assert!(transport.0.is_empty());
    }

    #[test]
    fn aes256_management_key_uses_algorithm_id_and_short_lc() {
        let key = ManagementKey::new(ManagementKeyAlgorithm::Aes256, vec![0x33; 32]).unwrap();
        let mut transport = RecordingTransport(Vec::new());
        ThalesPiv.set_management_key(&mut transport, &key).unwrap();
        let command = &transport.0[0];
        assert_eq!(
            &command[..18],
            &bytes("00DB3FFF2D5C03FF840B7F4A2580010C9020")
        );
        assert_eq!(&command[18..50], &[0x33; 32]);
        assert_eq!(command[50], 0x00);
        assert_eq!(usize::from(command[4]), command.len() - 6);
    }

    #[test]
    fn management_key_write_maps_non_success_status() {
        let key = ManagementKey::new(ManagementKeyAlgorithm::Aes128, vec![0x44; 16]).unwrap();
        let command = set_management_key_command(&key).unwrap();
        let mut transport = ScriptedTransport(VecDeque::from([(command, vec![0x6a, 0x80])]));
        assert_eq!(
            ThalesPiv.set_management_key(&mut transport, &key),
            Err(CredentialError::CardStatus(0x6a80))
        );
        assert!(transport.0.is_empty());
    }
}
