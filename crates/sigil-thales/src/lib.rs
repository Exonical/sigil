//! Thales (SafeNet, formerly Gemalto) PIV tokens.
//!
//! This crate holds the Thales-specific reads. Everything else on these cards goes through the vendor-neutral
//! functions in sigil-piv. The only identity read is the GlobalPlatform CPLC data, which both USB and NFC readers
//! expose. USB iSerialNumber is not available over NFC, so the IC serial from CPLC is the device serial.

use sigil_core::{CredentialError, Result};
use sigil_piv::{CardTransport, vendor::PivVendor};

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

/// The Thales IDPrime PIV applet. Its serial is vendor-specific; every other operation takes the SP 800-73 defaults,
/// which are read-only or unsupported.
pub struct ThalesPiv;

impl PivVendor for ThalesPiv {
    fn name(&self) -> &'static str {
        "Thales"
    }

    fn verify_serial(&self, transport: &mut dyn CardTransport, expected: &str) -> Result<String> {
        verify_serial(transport, expected)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

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
            sigil_piv::vendor::PivCapabilities::default()
        );
        let entries = sigil_piv::ops::read_slots(&mut Answers, &ThalesPiv).unwrap();
        assert_eq!(entries.len(), 4);
        assert!(
            entries
                .iter()
                .all(|entry| entry.certificate.is_none() && entry.key == KeyStatus::Unknown)
        );
    }
}
