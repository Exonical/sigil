use sigil_core::{
    CredentialError, FirmwareVersion, KeyOrigin, KeyStatus, ManagementKeyStatus, PinPolicy,
    PivAlgorithm, PivInfo, PivKeyMetadata, PivSlot, PivSlotInfo, Result, RetryStatus, TouchPolicy,
};
use sigil_piv::{
    CardTransport, pin_retries, read_certificate as read_certificate_data, select,
    summarize_certificate, transceive,
};

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
    if serial(transport)?.is_some_and(|serial| serial.to_string() != expected) {
        return Err(CredentialError::DeviceNotFound(expected.into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

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
        let mut s = ScriptedTransport::new([(
            vec![0x00, 0xf8, 0x00, 0x00],
            response(&[0x00, 0xbc, 0x61, 0x4e], 0x9000),
        )]);
        assert_eq!(serial(&mut s).unwrap(), Some(12_345_678));
        let mut mismatch = ScriptedTransport::new([(
            vec![0x00, 0xf8, 0x00, 0x00],
            response(&[0, 0, 0, 1], 0x9000),
        )]);
        assert_eq!(
            verify_serial(&mut mismatch, "12345678"),
            Err(CredentialError::DeviceNotFound("12345678".into()))
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
}
