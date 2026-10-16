//! Vendor-neutral reads for SP 800-73 PIV cards.
//!
//! These use only standard PIV instructions: SELECT, VERIFY with no data (retry counter), and GET DATA for the
//! certificate objects. Nothing here sends vendor instructions, so PUK and management-key status and key metadata
//! are reported as unknown rather than guessed. An absent certificate object is reported as 6A82 or 6A88 (standard)
//! or 6A80, which Thales IDPrime PIV cards return for objects that have not been created.

use sigil_core::{
    CredentialError, KeyStatus, PivCertificate, PivInfo, PivSlot, PivSlotInfo, Result, RetryStatus,
};

use crate::{
    CardTransport, pin_retries, read_certificate as read_certificate_object, select,
    summarize_certificate,
};

/// Reads the PIV PIN retry counter. The PUK and management key are not read.
pub fn read_info<T: CardTransport>(transport: &mut T) -> Result<PivInfo> {
    select(transport)?;
    let pin = pin_retries(transport)?.map(|remaining| RetryStatus {
        remaining,
        total: None,
        default_value: None,
    });
    Ok(PivInfo {
        version: None,
        pin,
        puk: None,
        management_key: None,
    })
}

/// Reads the four standard slots. Key status is unknown for every slot: reading it needs vendor metadata.
pub fn read_slots<T: CardTransport>(transport: &mut T) -> Result<Vec<PivSlotInfo>> {
    select(transport)?;
    let mut entries = Vec::with_capacity(PivSlot::STANDARD.len());
    for slot in PivSlot::STANDARD {
        let certificate = read_certificate(transport, slot)?.map(|certificate| certificate.summary);
        entries.push(PivSlotInfo {
            slot,
            certificate,
            key: KeyStatus::Unknown,
        });
    }
    Ok(entries)
}

/// Reads one slot's certificate. An unparseable certificate is reported as absent rather than as an error.
pub fn read_certificate<T: CardTransport>(
    transport: &mut T,
    slot: PivSlot,
) -> Result<Option<PivCertificate>> {
    let Some(der) = read_certificate_object(transport, slot)? else {
        return Ok(None);
    };
    match summarize_certificate(&der) {
        Ok(summary) => Ok(Some(PivCertificate { slot, summary, der })),
        Err(CredentialError::CertificateParse(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use sigil_core::{PivSlot, Result};

    use super::*;

    const P256_CERT: &[u8] = include_bytes!("../../sigil-mock/fixtures/piv-9a-p256.der");

    struct ScriptedTransport(VecDeque<(Vec<u8>, Vec<u8>)>);

    impl CardTransport for ScriptedTransport {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            let (expected, response) = self.0.pop_front().expect("unexpected APDU");
            assert_eq!(command, expected);
            Ok(response)
        }
    }

    fn select_command() -> Vec<u8> {
        vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08]
    }

    fn get_data(tag: [u8; 3]) -> Vec<u8> {
        vec![
            0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, tag[0], tag[1], tag[2], 0x00,
        ]
    }

    fn response(data: &[u8], sw: u16) -> Vec<u8> {
        [data, &sw.to_be_bytes()].concat()
    }

    fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
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

    fn certificate_object(certificate: &[u8]) -> Vec<u8> {
        encode_tlv(0x53, &encode_tlv(0x70, certificate))
    }

    #[test]
    fn retry_counter_is_reported_without_puk_or_management_key() {
        let mut five_left = ScriptedTransport(VecDeque::from([
            (select_command(), response(&[], 0x9000)),
            (vec![0x00, 0x20, 0x00, 0x80], response(&[], 0x63c5)),
        ]));
        let info = read_info(&mut five_left).unwrap();
        assert_eq!(
            info.pin,
            Some(RetryStatus {
                remaining: 5,
                total: None,
                default_value: None
            })
        );
        assert_eq!(
            (info.version, info.puk, info.management_key),
            (None, None, None)
        );

        let mut blocked = ScriptedTransport(VecDeque::from([
            (select_command(), response(&[], 0x9000)),
            (vec![0x00, 0x20, 0x00, 0x80], response(&[], 0x6983)),
        ]));
        assert_eq!(
            read_info(&mut blocked)
                .unwrap()
                .pin
                .map(|pin| pin.remaining),
            Some(0)
        );
    }

    #[test]
    fn absent_objects_are_reported_as_missing_for_6a80_and_6a82() {
        for status in [0x6a80u16, 0x6a82] {
            let mut transport = ScriptedTransport(VecDeque::from([
                (select_command(), response(&[], 0x9000)),
                (get_data([0x5f, 0xc1, 0x05]), response(&[], status)),
                (get_data([0x5f, 0xc1, 0x0a]), response(&[], status)),
                (get_data([0x5f, 0xc1, 0x0b]), response(&[], status)),
                (get_data([0x5f, 0xc1, 0x01]), response(&[], status)),
            ]));
            let slots = read_slots(&mut transport).unwrap();
            assert_eq!(slots.len(), 4);
            assert!(slots.iter().all(|slot| slot.certificate.is_none()));
            assert!(slots.iter().all(|slot| slot.key == KeyStatus::Unknown));
        }
    }

    #[test]
    fn a_present_certificate_is_summarized_and_keys_stay_unknown() {
        let mut transport = ScriptedTransport(VecDeque::from([
            (select_command(), response(&[], 0x9000)),
            (
                get_data([0x5f, 0xc1, 0x05]),
                response(&certificate_object(P256_CERT), 0x9000),
            ),
            (get_data([0x5f, 0xc1, 0x0a]), response(&[], 0x6a80)),
            (get_data([0x5f, 0xc1, 0x0b]), response(&[], 0x6a82)),
            (get_data([0x5f, 0xc1, 0x01]), response(&[], 0x6a80)),
        ]));
        let slots = read_slots(&mut transport).unwrap();
        let authentication = slots
            .iter()
            .find(|slot| slot.slot == PivSlot::AUTHENTICATION)
            .unwrap();
        let summary = authentication
            .certificate
            .as_ref()
            .expect("certificate summary");
        assert!(summary.subject.contains("Simulated PIV Authentication"));
        assert_eq!(authentication.key, KeyStatus::Unknown);
        assert!(
            slots
                .iter()
                .filter(|slot| slot.slot != PivSlot::AUTHENTICATION)
                .all(|slot| slot.certificate.is_none())
        );
    }
}
