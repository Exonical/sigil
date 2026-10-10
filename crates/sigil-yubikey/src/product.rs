//! YubiKey product names, derived the way Yubico's tooling derives them.
//!
//! This ports `get_name` from yubikey-manager `yubikit/support.py`, together with the `read_info` tweaks that
//! change the name (FIPS for 4.4.x, NFC removal for form factors without NFC), and the PID table in
//! `yubikit/core/__init__.py`. Reference: <https://github.com/Yubico/yubikey-manager> (BSD-2-Clause).
//!
//! The inputs are the management-applet fields that ykman reads: the firmware version, the form-factor byte
//! (whose `0x80` and `0x40` bits are FIPS and SKY, see `ManagementInfo::from_tags`), the USB and NFC capability
//! bits, the serial, and the PIN complexity flag.

use sigil_core::{FirmwareVersion, Transport};

use crate::management::{FormFactor, ManagementInfo};

// ykman `CAPABILITY` bits, as reported in the management TLVs.
const CAP_OTP: u64 = 0x01;
const CAP_U2F: u64 = 0x02;
const CAP_OPENPGP: u64 = 0x08;
const CAP_PIV: u64 = 0x10;
const CAP_OATH: u64 = 0x20;
const CAP_HSMAUTH: u64 = 0x100;
const CAP_FIDO2: u64 = 0x200;

/// ykman `YUBIKEY`, the hardware platform. Its display value is the generic name for the platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Yks,
    Neo,
    Sky,
    Ykp,
    Yk4,
}

impl KeyType {
    fn value(self) -> &'static str {
        match self {
            Self::Yks => "YubiKey Standard",
            Self::Neo => "YubiKey NEO",
            Self::Sky => "Security Key by Yubico",
            Self::Ykp => "YubiKey Plus",
            // ykman's YK4 value is "YubiKey" and covers the YubiKey 5 series.
            Self::Yk4 => "YubiKey",
        }
    }
}

/// The platform for a USB product ID, from ykman's `PID` enum. Other PIDs are unknown.
pub fn key_type_for_pid(pid: u16) -> Option<KeyType> {
    match pid {
        0x0010 => Some(KeyType::Yks),
        0x0110..=0x0116 => Some(KeyType::Neo),
        0x0120 => Some(KeyType::Sky),
        0x0401..=0x0407 => Some(KeyType::Yk4),
        0x0410 => Some(KeyType::Ykp),
        _ => None,
    }
}

/// ykman `_fido_only`: FIDO applications only, with no OTP, OATH, PIV, OpenPGP or HSM Auth.
fn fido_only(usb: u64) -> bool {
    usb & (CAP_OTP | CAP_OATH | CAP_PIV | CAP_OPENPGP | CAP_HSMAUTH) == 0
        && usb & (CAP_U2F | CAP_FIDO2) != 0
}

/// ykman `_is_preview`.
/// A firmware version as (major, minor, patch).
type Version = (u8, u8, u8);

fn is_preview(version: Version) -> bool {
    const RANGES: [(Version, Version); 3] = [
        ((5, 0, 0), (5, 1, 0)),
        ((5, 2, 0), (5, 2, 3)),
        ((5, 5, 0), (5, 5, 2)),
    ];
    RANGES
        .iter()
        .any(|(start, end)| (*start..*end).contains(&version))
}

/// The product name, or `None` when the firmware version is unknown.
///
/// `key_type` is the platform from the USB PID when Sigil knows it. Without a PID, as with PC/SC and NFC,
/// the platform is guessed exactly as ykman does for NFC connections.
pub fn product_name(info: &ManagementInfo, key_type: Option<KeyType>) -> Option<String> {
    let FirmwareVersion {
        major,
        minor,
        patch,
    } = *info.firmware.as_ref()?;
    let version = (major, minor, patch);
    let usb = info.usb_supported_bits;
    let form = info.form_factor_code;

    // read_info tweaks that affect the name. Firmware 4.4.x is the FIPS series.
    let is_fips = info.device_fips || ((4, 4, 0)..(4, 5, 0)).contains(&version);
    // Nano, Lightning and USB-C keychains before 5.2.4 have no NFC. ykman's `replace(...)` result is discarded,
    // so it only removes the enabled-NFC entry; this port removes NFC from the name's inputs as ykman intends.
    let lacks_nfc = matches!(
        form,
        FormFactor::UsbANano | FormFactor::UsbCNano | FormFactor::UsbCLightning
    ) || (form == FormFactor::UsbCKeychain && version < (5, 2, 4));
    let has_nfc = info.transports.contains(&Transport::Nfc) && !lacks_nfc;
    let is_sky = info.sky || key_type == Some(KeyType::Sky);

    let key_type = key_type.unwrap_or(if major == 3 {
        KeyType::Neo
    } else if info.serial.is_none() && fido_only(usb) {
        if version < (5, 2, 8) {
            KeyType::Sky
        } else {
            KeyType::Yk4
        }
    } else {
        KeyType::Yk4
    });

    let name = match key_type {
        KeyType::Sky => {
            if has_nfc {
                "Security Key NFC".to_owned()
            } else if usb & CAP_FIDO2 == 0 {
                "FIDO U2F Security Key".to_owned()
            } else {
                key_type.value().to_owned()
            }
        }
        KeyType::Yk4 => {
            if major < 4 {
                return Some(if major == 0 {
                    format!("YubiKey ({major}.{minor}.{patch})")
                } else {
                    "YubiKey".to_owned()
                });
            }
            let base = if major == 4 {
                if is_fips {
                    "YubiKey FIPS (4 Series)".to_owned()
                } else if usb == CAP_OTP | CAP_U2F {
                    "YubiKey Edge".to_owned()
                } else {
                    "YubiKey 4".to_owned()
                }
            } else {
                key_type.value().to_owned()
            };
            if is_preview(version) {
                "YubiKey Preview".to_owned()
            } else if version >= (5, 1, 0) {
                yubikey5_name(info, usb, is_fips, is_sky, has_nfc)
            } else {
                base
            }
        }
        other => other.value().to_owned(),
    };
    Some(name)
}

/// ykman's dynamic YubiKey 5 name: base, form factor, then edition or PIN suffix.
fn yubikey5_name(
    info: &ManagementInfo,
    usb: u64,
    is_fips: bool,
    is_sky: bool,
    has_nfc: bool,
) -> String {
    let form = info.form_factor_code;
    let is_nano = matches!(form, FormFactor::UsbANano | FormFactor::UsbCNano);
    let is_bio = matches!(form, FormFactor::UsbABio | FormFactor::UsbCBio);
    // Does not include Lightning (Ci).
    let is_c = matches!(
        form,
        FormFactor::UsbCKeychain | FormFactor::UsbCNano | FormFactor::UsbCBio
    );

    let mut parts: Vec<&str> = if is_sky {
        vec!["Security Key"]
    } else if is_bio {
        vec!["YubiKey"]
    } else {
        vec!["YubiKey", "5"]
    };
    if is_c {
        parts.push("C");
    } else if form == FormFactor::UsbCLightning {
        parts.push("Ci");
    }
    if is_nano {
        parts.push("Nano");
    } else if has_nfc {
        parts.push("NFC");
    } else if form == FormFactor::UsbAKeychain {
        // Only for a non-NFC USB-A keychain.
        parts.push("A");
    } else if is_bio {
        parts.push("Bio");
    }

    let mut name = parts.join(" ");
    if is_fips {
        name.push_str(" FIPS");
    } else if is_bio {
        if fido_only(usb) {
            name.push_str(" - FIDO Edition");
        } else if usb & CAP_PIV != 0 {
            name.push_str(" - Multi-protocol Edition");
        }
    } else if is_sky && info.serial.is_some() {
        name.push_str(" - Enterprise Edition");
    } else if info.pin_complexity.unwrap_or(false) && !is_sky {
        name.push_str(" - Enhanced PIN");
    }
    name.replace("5 C", "5C").replace("5 A", "5A")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sigil_core::{FirmwareVersion, Transport};

    use super::{KeyType, key_type_for_pid, product_name};
    use crate::management::{FormFactor, ManagementInfo, Tags};

    const ALL: u64 = 0xFF;

    fn version(major: u8, minor: u8, patch: u8) -> Option<FirmwareVersion> {
        Some(FirmwareVersion {
            major,
            minor,
            patch,
        })
    }

    /// Mirrors ykman's `DEFAULT_INFO` in tests/test_device.py: firmware 5.3.0, capabilities 0xFF, serial None.
    fn info(form: FormFactor) -> ManagementInfo {
        ManagementInfo {
            serial: None,
            firmware: version(5, 3, 0),
            form_factor: form.label().map(str::to_owned),
            form_factor_code: form,
            device_fips: false,
            sky: false,
            fips: None,
            transports: vec![Transport::UsbSmartCard],
            usb_enabled_applications: Vec::new(),
            usb_supported_applications: Vec::new(),
            usb_supported_bits: ALL,
            nfc_enabled_applications: Vec::new(),
            nfc_supported_applications: Vec::new(),
            config_locked: None,
            fips_approved_applications: None,
            pin_complexity: None,
        }
    }

    fn nfc(form: FormFactor) -> ManagementInfo {
        let mut info = info(form);
        info.transports.push(Transport::Nfc);
        info
    }

    fn name(info: &ManagementInfo) -> String {
        product_name(info, Some(KeyType::Yk4)).expect("version is known")
    }

    fn with(mut info: ManagementInfo, edit: impl FnOnce(&mut ManagementInfo)) -> ManagementInfo {
        edit(&mut info);
        info
    }

    fn fido(info: ManagementInfo) -> ManagementInfo {
        with(info, |info| info.usb_supported_bits = 0x2 | 0x200)
    }

    fn sky(info: ManagementInfo) -> ManagementInfo {
        with(info, |info| info.sky = true)
    }

    fn skyep(info: ManagementInfo) -> ManagementInfo {
        with(sky(info), |info| info.serial = Some("123456".into()))
    }

    fn fips(info: ManagementInfo) -> ManagementInfo {
        with(info, |info| info.device_fips = true)
    }

    fn epin(info: ManagementInfo) -> ManagementInfo {
        with(info, |info| info.pin_complexity = Some(true))
    }

    // ykman tests/test_device.py::test_yk5_formfactors
    #[test]
    fn yk5_form_factors_match_ykman() {
        assert_eq!(name(&info(FormFactor::UsbAKeychain)), "YubiKey 5A");
        assert_eq!(name(&nfc(FormFactor::UsbAKeychain)), "YubiKey 5 NFC");
        assert_eq!(name(&info(FormFactor::UsbANano)), "YubiKey 5 Nano");
        assert_eq!(name(&info(FormFactor::UsbCKeychain)), "YubiKey 5C");
        assert_eq!(name(&nfc(FormFactor::UsbCKeychain)), "YubiKey 5C NFC");
        assert_eq!(name(&info(FormFactor::UsbCNano)), "YubiKey 5C Nano");
        assert_eq!(name(&info(FormFactor::UsbCLightning)), "YubiKey 5Ci");
        assert_eq!(
            name(&info(FormFactor::UsbABio)),
            "YubiKey Bio - Multi-protocol Edition"
        );
        assert_eq!(
            name(&info(FormFactor::UsbCBio)),
            "YubiKey C Bio - Multi-protocol Edition"
        );
        assert_eq!(name(&info(FormFactor::Unknown)), "YubiKey 5");
        assert_eq!(name(&nfc(FormFactor::Unknown)), "YubiKey 5 NFC");
    }

    // ykman tests/test_device.py::test_yk5_fido
    #[test]
    fn yk5_fido_editions_match_ykman() {
        assert_eq!(
            name(&fido(info(FormFactor::UsbABio))),
            "YubiKey Bio - FIDO Edition"
        );
        assert_eq!(
            name(&fido(info(FormFactor::UsbCBio))),
            "YubiKey C Bio - FIDO Edition"
        );
    }

    // ykman tests/test_device.py::test_yk5_fips_formfactors
    #[test]
    fn yk5_fips_form_factors_match_ykman() {
        assert_eq!(
            name(&fips(info(FormFactor::UsbAKeychain))),
            "YubiKey 5A FIPS"
        );
        assert_eq!(
            name(&fips(nfc(FormFactor::UsbAKeychain))),
            "YubiKey 5 NFC FIPS"
        );
        assert_eq!(
            name(&fips(info(FormFactor::UsbANano))),
            "YubiKey 5 Nano FIPS"
        );
        assert_eq!(
            name(&fips(info(FormFactor::UsbCKeychain))),
            "YubiKey 5C FIPS"
        );
        assert_eq!(
            name(&fips(nfc(FormFactor::UsbCKeychain))),
            "YubiKey 5C NFC FIPS"
        );
        assert_eq!(
            name(&fips(info(FormFactor::UsbCNano))),
            "YubiKey 5C Nano FIPS"
        );
        assert_eq!(
            name(&fips(info(FormFactor::UsbCLightning))),
            "YubiKey 5Ci FIPS"
        );
        assert_eq!(name(&fips(info(FormFactor::Unknown))), "YubiKey 5 FIPS");
        assert_eq!(name(&fips(nfc(FormFactor::Unknown))), "YubiKey 5 NFC FIPS");
    }

    // ykman tests/test_device.py::test_sky_formfactors
    #[test]
    fn sky_form_factors_match_ykman() {
        assert_eq!(name(&sky(info(FormFactor::UsbAKeychain))), "Security Key A");
        assert_eq!(
            name(&sky(nfc(FormFactor::UsbAKeychain))),
            "Security Key NFC"
        );
        assert_eq!(name(&sky(info(FormFactor::UsbANano))), "Security Key Nano");
        assert_eq!(name(&sky(info(FormFactor::UsbCKeychain))), "Security Key C");
        assert_eq!(
            name(&sky(nfc(FormFactor::UsbCKeychain))),
            "Security Key C NFC"
        );
        assert_eq!(
            name(&sky(info(FormFactor::UsbCNano))),
            "Security Key C Nano"
        );
        assert_eq!(
            name(&sky(info(FormFactor::UsbCLightning))),
            "Security Key Ci"
        );
        assert_eq!(name(&sky(info(FormFactor::Unknown))), "Security Key");
        assert_eq!(name(&sky(nfc(FormFactor::Unknown))), "Security Key NFC");
    }

    // ykman tests/test_device.py::test_sky_enterprise_formfactors
    #[test]
    fn sky_enterprise_form_factors_match_ykman() {
        assert_eq!(
            name(&skyep(info(FormFactor::UsbAKeychain))),
            "Security Key A - Enterprise Edition"
        );
        assert_eq!(
            name(&skyep(nfc(FormFactor::UsbAKeychain))),
            "Security Key NFC - Enterprise Edition"
        );
        assert_eq!(
            name(&skyep(info(FormFactor::UsbANano))),
            "Security Key Nano - Enterprise Edition"
        );
        assert_eq!(
            name(&skyep(info(FormFactor::UsbCKeychain))),
            "Security Key C - Enterprise Edition"
        );
        assert_eq!(
            name(&skyep(nfc(FormFactor::UsbCKeychain))),
            "Security Key C NFC - Enterprise Edition"
        );
        assert_eq!(
            name(&skyep(info(FormFactor::UsbCNano))),
            "Security Key C Nano - Enterprise Edition"
        );
        assert_eq!(
            name(&skyep(info(FormFactor::UsbCLightning))),
            "Security Key Ci - Enterprise Edition"
        );
        assert_eq!(
            name(&skyep(info(FormFactor::Unknown))),
            "Security Key - Enterprise Edition"
        );
        assert_eq!(
            name(&skyep(nfc(FormFactor::Unknown))),
            "Security Key NFC - Enterprise Edition"
        );
    }

    // ykman tests/test_device.py::test_enhanced_pin
    #[test]
    fn enhanced_pin_suffix_matches_ykman() {
        assert_eq!(
            name(&epin(info(FormFactor::UsbAKeychain))),
            "YubiKey 5A - Enhanced PIN"
        );
        assert_eq!(
            name(&epin(nfc(FormFactor::UsbAKeychain))),
            "YubiKey 5 NFC - Enhanced PIN"
        );
        assert_eq!(
            name(&epin(nfc(FormFactor::UsbCKeychain))),
            "YubiKey 5C NFC - Enhanced PIN"
        );
    }

    // ykman tests/test_device.py::test_device_info: encoded management TLVs (no length prefix) with expected names.
    const DEVICE_INFO_TESTDATA: [(&str, &str); 8] = [
        (
            "YubiKey 5C NFC - Enhanced PIN",
            "0102033f0302033f0204020b885b04010305030507040602000007010f0801000d02033f0e02033f0a01000f010020030000002103000000100101110400000000120100130c3738434c5546583530303050140200001502000016010117010018020000",
        ),
        (
            "YubiKey 5C NFC FIPS",
            "0102033d0302033d020401ea505104018305030507040602000007010f0801000d02033d0e02033d0a01000f010020030000002103000000100101110400000000120100130c3738434c55465835303030501402001f1502001f16010117010018020000",
        ),
        (
            "YubiKey 5 Nano",
            "0102033f0302033e020401c234c404010205030507010602000007010f0801000a01000f010020030000002103000000100101110400000000120100130c3738434c55465835303030501402000015020008160100170100",
        ),
        (
            "YubiKey Bio - FIDO Edition",
            "0102020203020202020401afba5c04010605030507020602000007010f0801000a01000f010020030005012103030001100101110400000000120100130c3738434c5546583530303050140200001502000016010017010018020000",
        ),
        (
            "YubiKey C Bio - Multi-protocol Edition",
            "0102061203020612020401afcfff04010705030507020602000007010f0801000a01000f010020030005012103030001100101110400000000120100130c3738434c5546583530303050140200001502000016010017010018020200",
        ),
        (
            "Security Key C NFC - Enterprise Edition",
            "01020202030202020204017b306c04014305030504030602000007010f0801000d0202060e0202060a01000f0100",
        ),
        (
            "YubiKey 5Ci",
            "0102023f0302023f020400a0392204010505030502030602000007010f0801000a01000f010c",
        ),
        (
            "YubiKey C Bio - FIDO Edition",
            "01021206030212060204023251e904010705030000010602000007010f0801000a01000f010020030100002103030001100101110400000000120100130c3738434c5546583530303050140200001502000016010017010018020000190e0103050800020101030400000003",
        ),
    ];

    fn tags_from_hex(hex: &str) -> Tags {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
            .collect();
        let parsed: BTreeMap<u8, Vec<u8>> = sigil_piv::tlv::parse(&bytes)
            .expect("tlv")
            .into_iter()
            .map(|(tag, value)| (u8::try_from(tag).expect("tag"), value))
            .collect();
        parsed
    }

    #[test]
    fn device_info_vectors_match_ykman_names() {
        for (expected, hex) in DEVICE_INFO_TESTDATA {
            let info = ManagementInfo::from_tags(&tags_from_hex(hex), None).expect("parse");
            assert_eq!(name(&info), expected, "vector {expected}");
        }
    }

    #[test]
    fn user_key_is_usb_c_nfc_fips_on_firmware_5_7_4() {
        // USB-C keychain, NFC enabled, FIPS form-factor bit set, firmware 5.7.4, PIN complexity on.
        let info = with(nfc(FormFactor::UsbCKeychain), |info| {
            info.firmware = version(5, 7, 4);
            info.device_fips = true;
            info.serial = Some("39192733".into());
            info.pin_complexity = Some(true);
        });
        assert_eq!(name(&info), "YubiKey 5C NFC FIPS");
    }

    #[test]
    fn form_factor_bits_come_from_the_low_nibble_and_flags_from_the_top_bits() {
        // 0xC3: SKY (0x40) and FIPS (0x80) with USB-C keychain. Parsed through the TLV path.
        let tags = tags_from_hex("0102033f0302033f0204020b885b0401c30503050307");
        let info = ManagementInfo::from_tags(&tags, None).expect("parse");
        assert_eq!(info.form_factor_code, FormFactor::UsbCKeychain);
        assert!(info.device_fips);
        assert!(info.sky);
    }

    #[test]
    fn nano_and_lightning_keys_never_report_nfc_in_the_name() {
        let mut nano = nfc(FormFactor::UsbANano);
        nano.firmware = version(5, 7, 4);
        assert_eq!(name(&nano), "YubiKey 5 Nano");
        let mut lightning = nfc(FormFactor::UsbCLightning);
        lightning.firmware = version(5, 7, 4);
        assert_eq!(name(&lightning), "YubiKey 5Ci");
    }

    #[test]
    fn old_usb_c_keychain_without_nfc_before_5_2_4() {
        let mut old = nfc(FormFactor::UsbCKeychain);
        old.firmware = version(5, 2, 3);
        assert_eq!(name(&old), "YubiKey 5C");
        let mut newer = nfc(FormFactor::UsbCKeychain);
        newer.firmware = version(5, 2, 4);
        assert_eq!(name(&newer), "YubiKey 5C NFC");
    }

    #[test]
    fn firmware_4_4_is_the_fips_series() {
        let mut key = info(FormFactor::Unknown);
        key.firmware = version(4, 4, 1);
        assert_eq!(name(&key), "YubiKey FIPS (4 Series)");
    }

    #[test]
    fn preview_firmware_is_named_preview() {
        let mut key = info(FormFactor::UsbAKeychain);
        key.firmware = version(5, 2, 1);
        assert_eq!(name(&key), "YubiKey Preview");
    }

    #[test]
    fn unknown_firmware_gives_no_name() {
        let mut key = info(FormFactor::UsbAKeychain);
        key.firmware = None;
        assert_eq!(product_name(&key, Some(KeyType::Yk4)), None);
    }

    #[test]
    fn pid_maps_to_platform_like_ykman() {
        assert_eq!(key_type_for_pid(0x0120), Some(KeyType::Sky));
        assert_eq!(key_type_for_pid(0x0407), Some(KeyType::Yk4));
        assert_eq!(key_type_for_pid(0x0113), Some(KeyType::Neo));
        assert_eq!(key_type_for_pid(0x9999), None);
    }
}
