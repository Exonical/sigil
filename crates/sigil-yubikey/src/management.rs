//! Yubico management application protocol. APDU transport stays private to the
//! provider crate.

use std::collections::BTreeMap;

use sigil_core::{Application, CredentialError, FirmwareVersion, Result, Secret, Transport};
use sigil_piv::{CardTransport, transceive};

pub const TAG_USB_SUPPORTED: u8 = 0x01;
const TAG_SERIAL: u8 = 0x02;
pub const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_VERSION: u8 = 0x05;
const TAG_VERSION_QUALIFIER: u8 = 0x19;
pub const TAG_MORE_DATA: u8 = 0x10;
pub const TAG_CONFIG_LOCK: u8 = 0x0a;
pub const TAG_UNLOCK: u8 = 0x0b;
pub const TAG_REBOOT: u8 = 0x0c;
pub const TAG_NFC_SUPPORTED: u8 = 0x0d;
pub const TAG_NFC_ENABLED: u8 = 0x0e;
pub const TAG_FIPS_CAPABLE: u8 = 0x14;
pub const TAG_FIPS_APPROVED: u8 = 0x15;
// yubikit/management.py defines PIN complexity as 0x16 and NFC restricted as 0x17:
// https://github.com/Yubico/yubikey-manager/blob/main/yubikit/management.py.
pub const TAG_PIN_COMPLEXITY: u8 = 0x16;
const INS_WRITE_CONFIG: u8 = 0x1c;
const MANAGEMENT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
pub const MAX_INFO_PAGES: u8 = 4;

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
    sigil_piv::tlv::parse(&encoded[1..])
        .map_err(|_| ParseError::InvalidTlv)?
        .into_iter()
        .map(|(tag, value)| {
            u8::try_from(tag)
                .map(|tag| (tag, value))
                .map_err(|_| ParseError::InvalidTlv)
        })
        .collect()
}

/// The YubiKey form factor: the low nibble of the management form-factor byte (ykman `FORM_FACTOR`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormFactor {
    Unknown,
    UsbAKeychain,
    UsbANano,
    UsbCKeychain,
    UsbCNano,
    UsbCLightning,
    UsbABio,
    UsbCBio,
}

impl FormFactor {
    pub fn from_code(code: u8) -> Self {
        match code & 0x0f {
            1 => Self::UsbAKeychain,
            2 => Self::UsbANano,
            3 => Self::UsbCKeychain,
            4 => Self::UsbCNano,
            5 => Self::UsbCLightning,
            6 => Self::UsbABio,
            7 => Self::UsbCBio,
            _ => Self::Unknown,
        }
    }

    pub fn label(self) -> Option<&'static str> {
        match self {
            Self::Unknown => None,
            Self::UsbAKeychain => Some("Keychain (USB-A)"),
            Self::UsbANano => Some("Nano (USB-A)"),
            Self::UsbCKeychain => Some("Keychain (USB-C)"),
            Self::UsbCNano => Some("Nano (USB-C)"),
            Self::UsbCLightning => Some("Keychain (USB-C, Lightning)"),
            Self::UsbABio => Some("Bio (USB-A)"),
            Self::UsbCBio => Some("Bio (USB-C)"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ManagementInfo {
    pub serial: Option<String>,
    pub firmware: Option<FirmwareVersion>,
    pub form_factor: Option<String>,
    pub form_factor_code: FormFactor,
    /// Form-factor byte bit 0x80: the device is a FIPS series key (ykman `DeviceInfo.is_fips`).
    pub device_fips: bool,
    /// Form-factor byte bit 0x40: the device is a Security Key (ykman `DeviceInfo.is_sky`).
    pub sky: bool,
    pub fips: Option<bool>,
    pub transports: Vec<Transport>,
    pub usb_enabled_applications: Vec<Application>,
    pub usb_supported_applications: Vec<Application>,
    /// Raw USB capability bits (ykman `CAPABILITY`), used to derive the product name.
    pub usb_supported_bits: u64,
    pub nfc_enabled_applications: Vec<Application>,
    pub nfc_supported_applications: Vec<Application>,
    pub config_locked: Option<bool>,
    pub fips_approved_applications: Option<Vec<Application>>,
    pub pin_complexity: Option<bool>,
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
        let nfc_supported_bits = tags
            .get(&TAG_NFC_SUPPORTED)
            .map(|bytes| parse_number(bytes));
        let nfc_enabled_bits = tags.get(&TAG_NFC_ENABLED).map(|bytes| parse_number(bytes));
        let config_locked = tags
            .get(&TAG_CONFIG_LOCK)
            .map(|bytes| bytes.as_slice() == [1]);
        let fips_approved = tags
            .get(&TAG_FIPS_APPROVED)
            .map(|bytes| applications(parse_number(bytes)));
        let pin_complexity = tags
            .get(&TAG_PIN_COMPLEXITY)
            .map(|bytes| bytes.as_slice() == [1]);
        let fips = tags
            .get(&TAG_FIPS_CAPABLE)
            .map(|bytes| parse_number(bytes) & 0x02 != 0);
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
        let firmware = pre_release_version(tags).or(firmware);
        // ykman `DeviceInfo.parse_tlvs`: the low nibble is the form factor, 0x80 is FIPS and 0x40 is SKY.
        let form_factor_byte = tags
            .get(&TAG_FORM_FACTOR)
            .and_then(|value| value.first().copied());
        let form_factor_code = FormFactor::from_code(form_factor_byte.unwrap_or(0));
        let device_fips = form_factor_byte.is_some_and(|value| value & 0x80 != 0);
        let sky = form_factor_byte.is_some_and(|value| value & 0x40 != 0);
        let form_factor = form_factor_code.label().map(str::to_owned);

        let mut transports = vec![Transport::UsbSmartCard];
        if let Some(bits) = enabled_bits {
            if bits & 0x202 != 0 {
                transports.push(Transport::UsbHid);
            }
            if bits & 0x01 != 0 {
                transports.push(Transport::UsbOtp);
            }
        }
        if nfc_supported_bits.is_some_and(|bits| bits != 0) {
            transports.push(Transport::Nfc);
        }
        Ok(Self {
            serial,
            firmware,
            form_factor,
            form_factor_code,
            device_fips,
            sky,
            fips,
            transports,
            usb_enabled_applications: enabled_bits.map(applications).unwrap_or_default(),
            usb_supported_applications: applications(supported_bits),
            usb_supported_bits: supported_bits,
            nfc_enabled_applications: nfc_enabled_bits.map(applications).unwrap_or_default(),
            nfc_supported_applications: nfc_supported_bits.map(applications).unwrap_or_default(),
            config_locked,
            fips_approved_applications: fips_approved,
            pin_complexity,
        })
    }
}

/// ykman `DeviceInfo.parse_tlvs`: a version qualifier whose release type is not FINAL (2) replaces the reported
/// firmware version. Its nested TLVs are version (0x01), release type (0x02) and iteration (0x03).
fn pre_release_version(tags: &Tags) -> Option<FirmwareVersion> {
    let qualifier: BTreeMap<u16, Vec<u8>> =
        sigil_piv::tlv::parse(tags.get(&TAG_VERSION_QUALIFIER)?)
            .ok()?
            .into_iter()
            .collect();
    const RELEASE_FINAL: u8 = 2;
    if qualifier.get(&0x02)?.as_slice() == [RELEASE_FINAL] {
        return None;
    }
    let version = qualifier.get(&0x01)?;
    (version.len() == 3).then(|| FirmwareVersion {
        major: version[0],
        minor: version[1],
        patch: version[2],
    })
}

pub fn read_info<T: CardTransport + ?Sized>(transport: &mut T) -> Result<ManagementInfo> {
    let mut select = vec![0x00, 0xa4, 0x04, 0x00, MANAGEMENT_AID.len() as u8];
    select.extend_from_slice(&MANAGEMENT_AID);
    let (select_data, status) = transceive(transport, &select)?;
    if status != 0x9000 {
        return Err(CredentialError::CardStatus(status));
    }
    let select_version = parse_select_version(&select_data);
    let mut all_tags = Tags::new();
    for page in 0..MAX_INFO_PAGES {
        let (encoded, status) = transceive(transport, &[0x00, 0x1d, page, 0x00, 0x00])?;
        if status != 0x9000 {
            return Err(CredentialError::CardStatus(status));
        }
        let mut tags = parse_page(&encoded)
            .map_err(|error| CredentialError::SmartCardOperation(format!("{error:?}")))?;
        let more = tags
            .remove(&TAG_MORE_DATA)
            .is_some_and(|value| value.iter().any(|byte| *byte != 0));
        all_tags.append(&mut tags);
        if !more {
            return ManagementInfo::from_tags(&all_tags, select_version)
                .map_err(|error| CredentialError::SmartCardOperation(format!("{error:?}")));
        }
    }
    Err(CredentialError::SmartCardOperation(
        "YubiKey management information exceeded the maximum number of pages".into(),
    ))
}

fn parse_select_version(response: &[u8]) -> Option<FirmwareVersion> {
    let text = std::str::from_utf8(response).ok()?;
    let mut parts = text.split('.');
    Some(FirmwareVersion {
        major: parts.next()?.parse().ok()?,
        minor: parts.next()?.parse().ok()?,
        patch: parts.next()?.parse().ok()?,
    })
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
        (0x0100, Application::YubiHsmAuth),
    ] {
        if bits & mask != 0 {
            apps.push(app);
        }
    }
    apps
}

fn application_mask(applications: &[Application]) -> u16 {
    applications.iter().fold(0u16, |mask, application| {
        mask | match application {
            Application::Piv => 0x0010,
            Application::Fido2 => 0x0200,
            Application::U2f => 0x0002,
            Application::Otp => 0x0001,
            Application::OpenPgp => 0x0008,
            Application::Oath => 0x0020,
            Application::YubiHsmAuth => 0x0100,
        }
    })
}

/// Write enabled USB/NFC capabilities and reboot using Yubico's management
/// applet configuration encoding (`DeviceConfig.get_bytes` in yubikit).
/// See https://github.com/Yubico/yubikey-manager/blob/main/yubikit/management.py.
pub fn write_config<T: CardTransport + ?Sized>(
    transport: &mut T,
    usb: &[Application],
    nfc: Option<&[Application]>,
    lock_code: Option<&Secret>,
) -> Result<()> {
    if lock_code.is_some_and(|code| code.expose().len() != 16) {
        return Err(CredentialError::SmartCardOperation(
            "configuration lock code must be 16 bytes".into(),
        ));
    }

    let mut tlvs = sigil_piv::tlv::encode(u16::from(TAG_REBOOT), &[])?;
    if let Some(lock_code) = lock_code {
        tlvs.extend(sigil_piv::tlv::encode(
            u16::from(TAG_UNLOCK),
            lock_code.expose(),
        )?);
    }
    tlvs.extend(sigil_piv::tlv::encode(
        u16::from(TAG_USB_ENABLED),
        &application_mask(usb).to_be_bytes(),
    )?);
    if let Some(nfc) = nfc {
        tlvs.extend(sigil_piv::tlv::encode(
            u16::from(TAG_NFC_ENABLED),
            &application_mask(nfc).to_be_bytes(),
        )?);
    }
    if tlvs.len() > u8::MAX as usize {
        return Err(CredentialError::SmartCardOperation(
            "management configuration exceeds 255 bytes".into(),
        ));
    }
    let mut data = Vec::with_capacity(tlvs.len() + 1);
    data.push(tlvs.len() as u8);
    data.extend_from_slice(&tlvs);
    let mut command = vec![0x00, INS_WRITE_CONFIG, 0x00, 0x00, data.len() as u8];
    command.extend_from_slice(&data);
    let (_, status) = transceive(transport, &command)?;
    if status == 0x9000 {
        Ok(())
    } else {
        Err(CredentialError::CardStatus(status))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    struct ScriptedTransport {
        commands: VecDeque<Vec<u8>>,
        responses: VecDeque<Vec<u8>>,
    }

    impl CardTransport for ScriptedTransport {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            assert_eq!(self.commands.pop_front().as_deref(), Some(command));
            Ok(self.responses.pop_front().expect("scripted response"))
        }
    }

    fn encoded_page(tags: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let payload = tags
            .iter()
            .flat_map(|(tag, value)| sigil_piv::tlv::encode(u16::from(*tag), value).unwrap())
            .collect::<Vec<_>>();
        let mut page = vec![payload.len() as u8];
        page.extend(payload);
        page
    }

    #[test]
    fn parses_serial_version_and_distinct_enabled_capabilities() {
        let page = [
            0x1f, 0x01, 0x02, 0x03, 0x3b, 0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e, 0x03, 0x02, 0x02,
            0x11, 0x04, 0x01, 0x03, 0x05, 0x03, 0x05, 0x07, 0x01, 0x0d, 0x01, 0x3b, 0x0e, 0x01,
            0x10, 0x14, 0x01, 0x02,
        ];
        let tags = parse_page(&page).expect("valid TLV");
        let info = ManagementInfo::from_tags(&tags, None).expect("management info");
        assert_eq!(info.serial.as_deref(), Some("12345678"));
        assert_eq!(info.form_factor.as_deref(), Some("Keychain (USB-C)"));
        assert!(info.usb_supported_applications.contains(&Application::Oath));
        assert!(!info.usb_enabled_applications.contains(&Application::Oath));
        assert!(info.usb_enabled_applications.contains(&Application::Fido2));
        assert!(info.nfc_supported_applications.contains(&Application::Oath));
        assert_eq!(info.nfc_enabled_applications, vec![Application::Piv]);
        assert!(!info.nfc_enabled_applications.contains(&Application::Fido2));
        assert!(info.transports.contains(&Transport::Nfc));
        assert_eq!(info.fips, Some(true));
    }

    #[test]
    fn parses_all_configuration_and_approval_metadata() {
        let tags = [
            (TAG_USB_SUPPORTED, vec![0x03, 0x3b]),
            (TAG_USB_ENABLED, vec![0x02, 0x10]),
            (TAG_NFC_SUPPORTED, vec![0x03, 0x39]),
            (TAG_NFC_ENABLED, vec![0x00, 0x20]),
            (TAG_CONFIG_LOCK, vec![0x01]),
            (TAG_FIPS_APPROVED, vec![0x02, 0x10]),
            (TAG_PIN_COMPLEXITY, vec![0x01]),
        ]
        .into_iter()
        .collect();
        let info = ManagementInfo::from_tags(&tags, None).unwrap();

        assert_eq!(
            info.usb_supported_applications,
            vec![
                Application::Piv,
                Application::Fido2,
                Application::U2f,
                Application::Otp,
                Application::OpenPgp,
                Application::Oath,
                Application::YubiHsmAuth,
            ]
        );
        assert_eq!(
            info.usb_enabled_applications,
            vec![Application::Piv, Application::Fido2]
        );
        assert_eq!(
            info.nfc_supported_applications,
            vec![
                Application::Piv,
                Application::Fido2,
                Application::Otp,
                Application::OpenPgp,
                Application::Oath,
                Application::YubiHsmAuth,
            ]
        );
        assert_eq!(info.nfc_enabled_applications, vec![Application::Oath]);
        assert_eq!(
            info.fips_approved_applications,
            Some(vec![Application::Piv, Application::Fido2])
        );
        assert_eq!(info.config_locked, Some(true));
        assert_eq!(info.pin_complexity, Some(true));
    }

    #[test]
    fn parses_missing_configuration_metadata_as_unknown() {
        let tags = [(TAG_USB_SUPPORTED, vec![0x00, 0x10])]
            .into_iter()
            .collect();
        let info = ManagementInfo::from_tags(&tags, None).unwrap();
        assert!(info.usb_enabled_applications.is_empty());
        assert!(info.nfc_supported_applications.is_empty());
        assert_eq!(info.config_locked, None);
        assert_eq!(info.fips_approved_applications, None);
        assert_eq!(info.pin_complexity, None);
    }

    #[test]
    fn application_mask_covers_all_yubico_management_bits() {
        assert_eq!(
            application_mask(&[
                Application::Otp,
                Application::U2f,
                Application::OpenPgp,
                Application::Piv,
                Application::Oath,
                Application::YubiHsmAuth,
                Application::Fido2,
            ]),
            0x033b
        );
    }

    #[test]
    fn read_info_selects_management_applet_and_collects_pages() {
        let mut select = vec![0x00, 0xa4, 0x04, 0x00, MANAGEMENT_AID.len() as u8];
        select.extend_from_slice(&MANAGEMENT_AID);
        let page0 = encoded_page(&[
            (TAG_MORE_DATA, vec![0x01]),
            (TAG_USB_SUPPORTED, vec![0x00, 0x10]),
        ]);
        let page1 = encoded_page(&[
            (TAG_USB_ENABLED, vec![0x00, 0x10]),
            (TAG_SERIAL, vec![0x00, 0xbc, 0x61, 0x4e]),
            (TAG_CONFIG_LOCK, vec![0x00]),
            (TAG_PIN_COMPLEXITY, vec![0x01]),
        ]);
        let mut page0_response = page0;
        page0_response.extend_from_slice(&[0x90, 0x00]);
        let mut page1_response = page1;
        page1_response.extend_from_slice(&[0x90, 0x00]);
        let mut select_response = b"5.7.4".to_vec();
        select_response.extend_from_slice(&[0x90, 0x00]);
        let mut transport = ScriptedTransport {
            commands: [
                select,
                vec![0x00, 0x1d, 0x00, 0x00, 0x00],
                vec![0x00, 0x1d, 0x01, 0x00, 0x00],
            ]
            .into(),
            responses: [select_response, page0_response, page1_response].into(),
        };

        let info = read_info(&mut transport).unwrap();

        assert_eq!(info.serial.as_deref(), Some("12345678"));
        assert_eq!(info.firmware.as_ref().map(|version| version.major), Some(5));
        assert_eq!(info.config_locked, Some(false));
        assert_eq!(info.pin_complexity, Some(true));
        assert_eq!(info.usb_enabled_applications, vec![Application::Piv]);
        assert!(transport.commands.is_empty());
        assert!(transport.responses.is_empty());
    }

    #[test]
    fn fips_capability_tracks_piv_flag_and_missing_metadata() {
        let base = [(TAG_USB_SUPPORTED, vec![0x10])].into_iter().collect();
        assert_eq!(ManagementInfo::from_tags(&base, None).unwrap().fips, None);
        for (flag, expected) in [(0x00, false), (0x01, false), (0x02, true), (0x12, true)] {
            let tags = [
                (TAG_USB_SUPPORTED, vec![0x10]),
                (TAG_FIPS_CAPABLE, vec![flag]),
            ]
            .into_iter()
            .collect();
            assert_eq!(
                ManagementInfo::from_tags(&tags, None).unwrap().fips,
                Some(expected)
            );
        }
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

    #[test]
    fn write_config_encodes_reboot_usb_and_nfc_applications() {
        let expected = vec![
            0x00, 0x1c, 0x00, 0x00, 0x0b, 0x0a, 0x0c, 0x00, 0x03, 0x02, 0x02, 0x10, 0x0e, 0x02,
            0x00, 0x20,
        ];
        let mut transport = ScriptedTransport {
            commands: [expected.clone()].into(),
            responses: [vec![0x90, 0x00]].into(),
        };

        write_config(
            &mut transport,
            &[Application::Piv, Application::Fido2],
            Some(&[Application::Oath]),
            None,
        )
        .unwrap();

        assert!(transport.commands.is_empty());
    }

    #[test]
    fn write_config_encodes_unlock_lock_code_and_omits_unspecified_nfc() {
        let lock_code = Secret::new(vec![0x5a; 16]);
        let mut expected = vec![0x00, 0x1c, 0x00, 0x00, 0x19, 0x18, 0x0c, 0x00, 0x0b, 0x10];
        expected.extend([0x5a; 16]);
        expected.extend_from_slice(&[0x03, 0x02, 0x00, 0x10]);
        let mut transport = ScriptedTransport {
            commands: [expected].into(),
            responses: [vec![0x90, 0x00]].into(),
        };

        write_config(&mut transport, &[Application::Piv], None, Some(&lock_code)).unwrap();

        assert!(transport.commands.is_empty());
    }

    #[test]
    fn write_config_rejects_invalid_lock_code_and_preserves_card_status() {
        let mut unused_transport = ScriptedTransport {
            commands: VecDeque::new(),
            responses: VecDeque::new(),
        };
        let short_lock_code = Secret::new(vec![0x33; 15]);
        assert!(
            write_config(
                &mut unused_transport,
                &[Application::Piv],
                None,
                Some(&short_lock_code)
            )
            .is_err()
        );
        assert!(unused_transport.commands.is_empty());

        let expected = vec![
            0x00, 0x1c, 0x00, 0x00, 0x07, 0x06, 0x0c, 0x00, 0x03, 0x02, 0x00, 0x10,
        ];
        let mut rejected = ScriptedTransport {
            commands: [expected].into(),
            responses: [vec![0x69, 0x85]].into(),
        };
        assert_eq!(
            write_config(&mut rejected, &[Application::Piv], None, None),
            Err(CredentialError::CardStatus(0x6985))
        );
    }
}
