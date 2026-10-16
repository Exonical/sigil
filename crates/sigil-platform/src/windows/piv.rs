//! Platform glue for PIV: finds the token, opens one shared transaction, selects the vendor, verifies the serial, and
//! hands the card to a `sigil_piv::ops` operation. PIV logic lives in `sigil-piv`; vendors live in their crates.

use std::ffi::CString;

use pcsc::{Card, Error as PcscError, Transaction};
use sigil_core::{
    Application, CredentialError, DeviceId, DeviceInfo, ManagedPivInitializationOutcome,
    ManagementKey, PivAttestation, PivCertificate, PivInfo, PivKeyConfiguration, PivPin, PivPuk,
    PivSlot, PivSlotInfo, Result, Secret,
};
use sigil_piv::{CardTransport, ops, vendor::PivVendor};
use sigil_thales::ThalesPiv;
use sigil_yubikey::{management as yubikey_management, vendor::YubiKeyPiv};

use super::{connect_shared, establish, list};

pub(super) struct PcscTransport<'tx, 'card> {
    transaction: &'tx Transaction<'card>,
}

impl<'tx, 'card> PcscTransport<'tx, 'card> {
    pub(super) fn new(transaction: &'tx Transaction<'card>) -> Self {
        Self { transaction }
    }
}

impl CardTransport for PcscTransport<'_, '_> {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = [0u8; 4096];
        let response = self
            .transaction
            .transmit(command, &mut buffer)
            .map_err(map_pcsc_error)?;
        Ok(response.to_vec())
    }
}

fn map_pcsc_error(error: PcscError) -> CredentialError {
    match error {
        PcscError::RemovedCard | PcscError::ResetCard | PcscError::NoSmartcard => {
            CredentialError::DeviceRemoved
        }
        other => CredentialError::SmartCardOperation(other.to_string()),
    }
}

pub(super) fn parse_device_id(id: &DeviceId) -> Result<(String, Option<String>)> {
    let rest =
        id.0.strip_prefix("windows-pcsc:")
            .ok_or(CredentialError::UnsupportedOperation(
                "PIV inspection requires a smart-card interface".into(),
            ))?;
    let (reader, serial) = rest
        .rsplit_once(':')
        .ok_or(CredentialError::UnsupportedOperation(
            "PIV inspection requires a smart-card interface".into(),
        ))?;
    if reader.is_empty() || serial.is_empty() {
        return Err(CredentialError::UnsupportedOperation(
            "PIV inspection requires a smart-card interface".into(),
        ));
    }
    Ok((
        reader.to_owned(),
        (serial != "unknown").then(|| serial.to_owned()),
    ))
}

fn find_device(id: &DeviceId) -> Result<DeviceInfo> {
    list()?
        .into_iter()
        .find(|device| device.id == *id)
        .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))
}

/// The vendor implementation for a discovered token. Tokens from other vendors are refused before any APDU.
fn vendor_for(device: &DeviceInfo) -> Result<&'static dyn PivVendor> {
    match device.vendor.as_str() {
        "Yubico" => Ok(&YubiKeyPiv),
        "Thales" => Ok(&ThalesPiv),
        other => Err(CredentialError::UnsupportedOperation(format!(
            "PIV is not supported on {other} tokens"
        ))),
    }
}

/// Runs `operation` in one shared card transaction. The serial the caller requires is verified first; when none is
/// given, the serial embedded in the device identifier is checked. The verified serial is passed to `operation`, or
/// is empty when nothing was checked.
fn session<T>(
    id: &DeviceId,
    expected_serial: Option<&str>,
    operation: impl FnOnce(&mut dyn CardTransport, &dyn PivVendor, &DeviceInfo, &str) -> Result<T>,
) -> Result<T> {
    let (reader_name, serial_in_id) = parse_device_id(id)?;
    if let Some(expected) = expected_serial
        && (expected.is_empty()
            || serial_in_id
                .as_deref()
                .is_some_and(|serial| serial != expected))
    {
        return Err(CredentialError::DeviceMismatch);
    }
    let device = find_device(id).map_err(|error| match expected_serial {
        Some(_) => CredentialError::DeviceMismatch,
        None => error,
    })?;
    let vendor = vendor_for(&device)?;
    let context =
        establish().map_err(|error| CredentialError::PcscUnavailable(error.to_string()))?;
    let reader = CString::new(reader_name).map_err(|_| {
        CredentialError::SmartCardOperation("reader name contains a NUL byte".into())
    })?;
    let mut card: Card = connect_shared(&context, &reader).map_err(map_pcsc_error)?;
    let transaction = card.transaction().map_err(map_pcsc_error)?;
    let mut transport = PcscTransport::new(&transaction);
    let verify_against = expected_serial.map(str::to_owned).or(serial_in_id);
    let verified = match verify_against {
        Some(serial) => vendor.verify_serial(&mut transport, &serial)?,
        None => String::new(),
    };
    operation(&mut transport, vendor, &device, &verified)
}

/// Application settings live in the YubiKey management applet, not in PIV, so only YubiKeys support them.
pub(crate) fn set_enabled_applications(
    id: &DeviceId,
    expected_serial: &str,
    usb: &[Application],
    nfc: Option<&[Application]>,
    lock_code: Option<&Secret>,
) -> Result<()> {
    let device = find_device(id)?;
    if device.vendor != "Yubico" {
        return Err(CredentialError::UnsupportedOperation(format!(
            "application settings are not supported on {} tokens",
            device.vendor
        )));
    }
    let (reader_name, serial_in_id) = parse_device_id(id)?;
    if expected_serial.is_empty()
        || serial_in_id
            .as_deref()
            .is_some_and(|serial| serial != expected_serial)
    {
        return Err(CredentialError::DeviceMismatch);
    }
    let context =
        establish().map_err(|error| CredentialError::PcscUnavailable(error.to_string()))?;
    let reader = CString::new(reader_name).map_err(|_| {
        CredentialError::SmartCardOperation("reader name contains a NUL byte".into())
    })?;
    let mut card: Card = connect_shared(&context, &reader).map_err(map_pcsc_error)?;
    let transaction = card.transaction().map_err(map_pcsc_error)?;
    let mut transport = PcscTransport::new(&transaction);
    let info = yubikey_management::read_info(&mut transport)?;
    if info.serial.as_deref() != Some(expected_serial) {
        return Err(CredentialError::DeviceMismatch);
    }
    // Do not query the card after a successful rebooting write; discovery events refresh it.
    yubikey_management::write_config(&mut transport, usb, nfc, lock_code)
}

pub(crate) fn piv_serial(id: &DeviceId, expected_serial: &str) -> Result<String> {
    session(id, Some(expected_serial), |_, _, _, verified| {
        Ok(verified.to_owned())
    })
}

pub(crate) fn piv_info(id: &DeviceId) -> Result<PivInfo> {
    session(id, None, |transport, vendor, _, _| {
        ops::read_info(transport, vendor)
    })
}

pub(crate) fn piv_slots(id: &DeviceId) -> Result<Vec<PivSlotInfo>> {
    session(id, None, |transport, vendor, _, _| {
        ops::read_slots(transport, vendor)
    })
}

pub(crate) fn piv_certificate(id: &DeviceId, slot: PivSlot) -> Result<Option<PivCertificate>> {
    session(id, None, |transport, _, _, _| {
        ops::read_certificate(transport, slot)
    })
}

pub(crate) fn change_pin(
    id: &DeviceId,
    expected_serial: &str,
    old_pin: &PivPin,
    new_pin: &PivPin,
) -> Result<()> {
    session(id, Some(expected_serial), |transport, vendor, device, _| {
        ops::change_pin(transport, vendor, device, old_pin, new_pin)
    })
}

pub(crate) fn change_puk(
    id: &DeviceId,
    expected_serial: &str,
    old_puk: &PivPuk,
    new_puk: &PivPuk,
) -> Result<()> {
    session(id, Some(expected_serial), |transport, vendor, device, _| {
        ops::change_puk(transport, vendor, device, old_puk, new_puk)
    })
}

pub(crate) fn unblock_pin(
    id: &DeviceId,
    expected_serial: &str,
    puk: &PivPuk,
    new_pin: &PivPin,
) -> Result<()> {
    session(id, Some(expected_serial), |transport, vendor, device, _| {
        ops::unblock_pin(transport, vendor, device, puk, new_pin)
    })
}

pub(crate) fn change_management_key(
    id: &DeviceId,
    expected_serial: &str,
    current: &ManagementKey,
    new_key: &ManagementKey,
) -> Result<()> {
    session(id, Some(expected_serial), |transport, vendor, _, _| {
        ops::change_management_key(transport, vendor, current, new_key)
    })
}

pub(crate) fn managed_initialize(
    id: &DeviceId,
    expected_serial: &str,
    new_management_key: &ManagementKey,
    new_puk: &PivPuk,
) -> Result<ManagedPivInitializationOutcome> {
    session(id, Some(expected_serial), |transport, vendor, device, _| {
        ops::managed_initialize(transport, vendor, device, new_management_key, new_puk)
    })
}

pub(crate) fn generate_key(
    id: &DeviceId,
    expected_serial: &str,
    management_key: &ManagementKey,
    configuration: PivKeyConfiguration,
) -> Result<Vec<u8>> {
    session(id, Some(expected_serial), |transport, vendor, device, _| {
        ops::generate_key(transport, vendor, device, management_key, configuration)
    })
}

pub(crate) fn attest(
    id: &DeviceId,
    expected_serial: &str,
    slot: PivSlot,
) -> Result<PivAttestation> {
    session(id, Some(expected_serial), |transport, vendor, _, _| {
        ops::attest(transport, vendor, slot)
    })
}

pub(crate) fn sign_csr(
    id: &DeviceId,
    expected_serial: &str,
    pin: &PivPin,
    slot: PivSlot,
    subject_dn: &str,
    expected_public_key: Option<&[u8]>,
) -> Result<Vec<u8>> {
    session(id, Some(expected_serial), |transport, vendor, device, _| {
        ops::sign_csr(
            transport,
            vendor,
            device,
            pin,
            slot,
            subject_dn,
            expected_public_key,
        )
    })
}

pub(crate) fn import_certificate(
    id: &DeviceId,
    expected_serial: &str,
    management_key: &ManagementKey,
    slot: PivSlot,
    certificate_der: &[u8],
    expected_public_key: Option<&[u8]>,
) -> Result<()> {
    session(id, Some(expected_serial), |transport, vendor, device, _| {
        ops::import_certificate(
            transport,
            vendor,
            device,
            management_key,
            slot,
            certificate_der,
            expected_public_key,
        )
    })
}

pub(crate) fn delete_certificate(
    id: &DeviceId,
    expected_serial: &str,
    management_key: &ManagementKey,
    slot: PivSlot,
) -> Result<()> {
    session(id, Some(expected_serial), |transport, vendor, device, _| {
        ops::delete_certificate(transport, vendor, device, management_key, slot)
    })
}

pub(crate) fn delete_key(
    id: &DeviceId,
    expected_serial: &str,
    management_key: &ManagementKey,
    slot: PivSlot,
) -> Result<()> {
    session(id, Some(expected_serial), |transport, vendor, _, _| {
        ops::delete_key(transport, vendor, management_key, slot)
    })
}

pub(crate) fn reset(id: &DeviceId, expected_serial: &str) -> Result<()> {
    session(id, Some(expected_serial), |transport, vendor, _, _| {
        ops::reset(transport, vendor)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pcsc_device_ids_with_last_colon_as_serial_separator() {
        assert_eq!(
            parse_device_id(&DeviceId("windows-pcsc:Reader: Name:12345678".into())).unwrap(),
            ("Reader: Name".into(), Some("12345678".into()))
        );
        assert_eq!(
            parse_device_id(&DeviceId("windows-pcsc:Reader:unknown".into())).unwrap(),
            ("Reader".into(), None)
        );
        assert!(matches!(
            parse_device_id(&DeviceId("windows-hid:device".into())),
            Err(CredentialError::UnsupportedOperation(_))
        ));
    }

    #[test]
    fn only_known_vendors_resolve_to_a_piv_implementation() {
        let device = |vendor: &str| DeviceInfo {
            vendor: vendor.into(),
            ..test_device()
        };
        assert_eq!(vendor_for(&device("Yubico")).unwrap().name(), "Yubico");
        assert_eq!(vendor_for(&device("Thales")).unwrap().name(), "Thales");
        assert!(matches!(
            vendor_for(&device("Acme")),
            Err(CredentialError::UnsupportedOperation(_))
        ));
    }

    fn test_device() -> DeviceInfo {
        DeviceInfo {
            id: DeviceId("windows-pcsc:Reader:1".into()),
            vendor: "Yubico".into(),
            model: "Test".into(),
            serial: Some("1".into()),
            firmware: None,
            form_factor: None,
            fips: None,
            usb_enabled: Vec::new(),
            usb_supported: Vec::new(),
            nfc_enabled: Vec::new(),
            nfc_supported: Vec::new(),
            config_locked: None,
            fips_approved: None,
            pin_complexity: None,
            connection: None,
            transports: Vec::new(),
            applications: Vec::new(),
            supported_applications: Vec::new(),
            simulated: false,
            metadata_access: sigil_core::MetadataAccess::Unknown,
        }
    }
}
