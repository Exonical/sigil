//! Read-only parsing of Yubico's management application device information.
//! APDU transport stays private to the platform provider.

use std::collections::BTreeMap;

use sigil_core::{Application, FirmwareVersion, Transport};

const TAG_USB_SUPPORTED: u8 = 0x01;
const TAG_SERIAL: u8 = 0x02;
const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_VERSION: u8 = 0x05;
pub const TAG_MORE_DATA: u8 = 0x10;
const TAG_NFC_SUPPORTED: u8 = 0x0d;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    InvalidLength,
    InvalidTlv,
    MissingCapabilities,
}

pub type Tags = BTreeMap<u8, Vec<u8>>;

/// The first byte is the byte count of the BER-TLV payload. No write commands
/// are exposed through this parser.
pub fn parse_page(encoded: &[u8]) -> std::result::Result<Tags, ParseError> {
    if encoded.is_empty() || encoded.len() > 256 || usize::from(encoded[0]) != encoded.len() - 1 {
        return Err(ParseError::InvalidLength);
    }
    let mut bytes = &encoded[1..];
    let mut tags = Tags::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 {
            return Err(ParseError::InvalidTlv);
        }
        let tag = bytes[0];
        let length = bytes[1];
        bytes = &bytes[2..];
        let length = if length < 0x80 {
            usize::from(length)
        } else {
            let count = usize::from(length & 0x7f);
            if count == 0 || count > 2 || bytes.len() < count {
                return Err(ParseError::InvalidTlv);
            }
            let mut value = 0usize;
            for byte in &bytes[..count] {
                value = (value << 8) | usize::from(*byte);
            }
            bytes = &bytes[count..];
            value
        };
        if length > bytes.len() {
            return Err(ParseError::InvalidTlv);
        }
        tags.insert(tag, bytes[..length].to_vec());
        bytes = &bytes[length..];
    }
    Ok(tags)
}

#[derive(Debug, PartialEq, Eq)]
pub struct ManagementInfo {
    pub serial: Option<String>,
    pub firmware: Option<FirmwareVersion>,
    pub form_factor: Option<String>,
    pub transports: Vec<Transport>,
    pub enabled_applications: Vec<Application>,
    pub supported_applications: Vec<Application>,
}

impl ManagementInfo {
    pub fn from_tags(
        tags: &Tags,
        select_version: Option<FirmwareVersion>,
    ) -> std::result::Result<Self, ParseError> {
        let supported = tags
            .get(&TAG_USB_SUPPORTED)
            .ok_or(ParseError::MissingCapabilities)?;
        let supported_bits = parse_number(supported);
        let enabled_bits = tags.get(&TAG_USB_ENABLED).map(|bytes| parse_number(bytes));
        let serial = tags
            .get(&TAG_SERIAL)
            .map(|value| parse_number(value))
            .filter(|value| *value != 0)
            .map(|value| value.to_string());
        let firmware = tags
            .get(&TAG_VERSION)
            .and_then(|value| {
                (value.len() == 3).then(|| FirmwareVersion {
                    major: value[0],
                    minor: value[1],
                    patch: value[2],
                })
            })
            .or(select_version);
        let form_factor = tags
            .get(&TAG_FORM_FACTOR)
            .and_then(|value| value.first())
            .and_then(|value| match value & 0x0f {
                1 => Some("Keychain (USB-A)"),
                2 => Some("Nano (USB-A)"),
                3 => Some("Keychain (USB-C)"),
                4 => Some("Nano (USB-C)"),
                5 => Some("Keychain (USB-C, Lightning)"),
                6 => Some("Bio (USB-A)"),
                7 => Some("Bio (USB-C)"),
                _ => None,
            })
            .map(str::to_owned);

        let mut transports = vec![Transport::UsbSmartCard];
        if let Some(bits) = enabled_bits {
            if bits & 0x202 != 0 {
                transports.push(Transport::UsbHid);
            }
            if bits & 0x01 != 0 {
                transports.push(Transport::UsbOtp);
            }
        }
        if tags
            .get(&TAG_NFC_SUPPORTED)
            .is_some_and(|value| parse_number(value) != 0)
        {
            transports.push(Transport::Nfc);
        }
        Ok(Self {
            serial,
            firmware,
            form_factor,
            transports,
            enabled_applications: enabled_bits.map(applications).unwrap_or_default(),
            supported_applications: applications(supported_bits),
        })
    }
}

fn parse_number(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |number, byte| (number << 8) | u64::from(*byte))
}

fn applications(bits: u64) -> Vec<Application> {
    let mut apps = Vec::new();
    for (mask, app) in [
        (0x10, Application::Piv),
        (0x200, Application::Fido2),
        (0x02, Application::U2f),
        (0x01, Application::Otp),
        (0x08, Application::OpenPgp),
        (0x20, Application::Oath),
    ] {
        if bits & mask != 0 {
            apps.push(app);
        }
    }
    apps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_serial_version_and_distinct_enabled_capabilities() {
        let page = [
            0x19, 0x01, 0x02, 0x03, 0x3b, 0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e, 0x03, 0x02, 0x02,
            0x11, 0x04, 0x01, 0x03, 0x05, 0x03, 0x05, 0x07, 0x01, 0x0d, 0x01, 0x3b,
        ];
        let tags = parse_page(&page).expect("valid TLV");
        let info = ManagementInfo::from_tags(&tags, None).expect("management info");
        assert_eq!(info.serial.as_deref(), Some("12345678"));
        assert_eq!(info.form_factor.as_deref(), Some("Keychain (USB-C)"));
        assert!(info.supported_applications.contains(&Application::Oath));
        assert!(!info.enabled_applications.contains(&Application::Oath));
        assert!(info.enabled_applications.contains(&Application::Fido2));
    }

    #[test]
    fn rejects_truncated_pages_and_tlvs() {
        assert_eq!(parse_page(&[]), Err(ParseError::InvalidLength));
        assert_eq!(parse_page(&[3, 1, 2]), Err(ParseError::InvalidLength));
        assert_eq!(parse_page(&[2, 1, 8]), Err(ParseError::InvalidTlv));
        assert_eq!(parse_page(&[3, 1, 0x82, 0]), Err(ParseError::InvalidTlv));
    }

    #[test]
    fn allows_extended_length_tlv() {
        assert_eq!(
            parse_page(&[4, 0x13, 0x81, 1, b'A'])
                .expect("extended")
                .get(&0x13),
            Some(&vec![b'A'])
        );
    }
}
