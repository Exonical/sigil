use std::ffi::CString;

use pcsc::{Card, Error as PcscError, Transaction};
use sha2::{Digest, Sha256, Sha384};
use sigil_core::{
    Application, CredentialError, DeviceId, ManagementKey, PinPolicy, PivAttestation,
    PivCertificate, PivInfo, PivKeyAlgorithm, PivKeyConfiguration, PivPin, PivPuk, PivSlot,
    PivSlotInfo, Result, Secret,
};
use sigil_piv::CardTransport;
use sigil_yubikey::{management as yubikey_management, piv as yubikey_piv};

use super::{connect_shared, establish, list};

pub(super) struct PcscTransport<'tx, 'card> {
    transaction: &'tx Transaction<'card>,
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

fn with_transport<T>(
    id: &DeviceId,
    operation: impl FnOnce(&mut PcscTransport<'_, '_>) -> Result<T>,
) -> Result<T> {
    let (reader_name, expected_serial) = parse_device_id(id)?;
    if !list()?.iter().any(|device| device.id == *id) {
        return Err(CredentialError::DeviceNotFound(id.0.clone()));
    }
    let context =
        establish().map_err(|error| CredentialError::PcscUnavailable(error.to_string()))?;
    let reader = CString::new(reader_name).map_err(|_| {
        CredentialError::SmartCardOperation("reader name contains a NUL byte".into())
    })?;
    let mut card: Card = connect_shared(&context, &reader).map_err(map_pcsc_error)?;
    let transaction = card.transaction().map_err(map_pcsc_error)?;
    let mut transport = PcscTransport {
        transaction: &transaction,
    };
    if let Some(serial) = expected_serial {
        yubikey_piv::verify_serial(&mut transport, &serial)?;
    }
    operation(&mut transport)
}

fn with_transport_expected<T>(
    id: &DeviceId,
    expected_serial: &str,
    operation: impl FnOnce(&mut PcscTransport<'_, '_>) -> Result<T>,
) -> Result<T> {
    with_transport_and_serial(id, expected_serial, |transport, _| operation(transport))
}

fn with_transport_and_serial<T>(
    id: &DeviceId,
    expected_serial: &str,
    operation: impl FnOnce(&mut PcscTransport<'_, '_>, &str) -> Result<T>,
) -> Result<T> {
    let (reader_name, serial_in_id) = parse_device_id(id)?;
    if expected_serial.is_empty()
        || serial_in_id
            .as_deref()
            .is_some_and(|serial| serial != expected_serial)
        || !list()?.iter().any(|device| device.id == *id)
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
    let mut transport = PcscTransport {
        transaction: &transaction,
    };
    let verified_serial = yubikey_piv::read_expected_serial(&mut transport, expected_serial)?;
    operation(&mut transport, &verified_serial)
}

fn with_management_info<T>(
    id: &DeviceId,
    expected_serial: &str,
    operation: impl FnOnce(
        &mut PcscTransport<'_, '_>,
        &sigil_yubikey::management::ManagementInfo,
    ) -> Result<T>,
) -> Result<T> {
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
    let mut transport = PcscTransport {
        transaction: &transaction,
    };
    let info = yubikey_management::read_info(&mut transport)?;
    let serial = info
        .serial
        .as_deref()
        .ok_or(CredentialError::DeviceMismatch)?;
    if serial != expected_serial {
        return Err(CredentialError::DeviceMismatch);
    }
    operation(&mut transport, &info)
}

pub(crate) fn set_enabled_applications(
    id: &DeviceId,
    expected_serial: &str,
    usb: &[Application],
    nfc: Option<&[Application]>,
    lock_code: Option<&Secret>,
) -> Result<()> {
    with_management_info(id, expected_serial, |transport, _| {
        // Do not query the card after a successful rebooting write; discovery events refresh it.
        yubikey_management::write_config(transport, usb, nfc, lock_code)
    })
}

pub(crate) fn piv_serial(id: &DeviceId, expected_serial: &str) -> Result<String> {
    with_transport_and_serial(id, expected_serial, |_, serial| Ok(serial.to_owned()))
}

pub(crate) fn piv_info(id: &DeviceId) -> Result<PivInfo> {
    with_transport(id, |transport| yubikey_piv::read_info(transport))
}

pub(crate) fn piv_slots(id: &DeviceId) -> Result<Vec<PivSlotInfo>> {
    with_transport(id, |transport| yubikey_piv::read_slots(transport))
}

pub(crate) fn piv_certificate(id: &DeviceId, slot: PivSlot) -> Result<Option<PivCertificate>> {
    with_transport(id, |transport| {
        yubikey_piv::read_certificate(transport, slot)
    })
}

fn device_is_fips(id: &DeviceId) -> Result<bool> {
    list()?
        .into_iter()
        .find(|device| device.id == *id)
        .map(|device| device.fips.unwrap_or(false))
        .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))
}

fn validate_fips_code(fips: bool, bytes: &[u8]) -> Result<()> {
    if fips && bytes.len() < 8 {
        return Err(CredentialError::PivFipsNotApproved);
    }
    Ok(())
}

fn validate_fips_pin_policy(fips: bool, pin_policy: PinPolicy) -> Result<()> {
    if fips && pin_policy == PinPolicy::Never {
        return Err(CredentialError::PivFipsNotApproved);
    }
    Ok(())
}

fn map_fips_status<T>(fips: bool, result: Result<T>) -> Result<T> {
    match result {
        Err(CredentialError::CardStatus(0x6985)) if fips => {
            Err(CredentialError::PivFipsNotApproved)
        }
        other => other,
    }
}

pub(crate) fn change_pin(
    id: &DeviceId,
    expected_serial: &str,
    old_pin: &PivPin,
    new_pin: &PivPin,
) -> Result<()> {
    validate_fips_code(device_is_fips(id)?, new_pin.as_bytes())?;
    with_transport_expected(id, expected_serial, |transport| {
        sigil_piv::management::change_pin(transport, old_pin, new_pin)
    })
}

pub(crate) fn change_puk(
    id: &DeviceId,
    expected_serial: &str,
    old_puk: &PivPuk,
    new_puk: &PivPuk,
) -> Result<()> {
    validate_fips_code(device_is_fips(id)?, new_puk.as_bytes())?;
    with_transport_expected(id, expected_serial, |transport| {
        sigil_piv::management::change_puk(transport, old_puk, new_puk)
    })
}

pub(crate) fn unblock_pin(
    id: &DeviceId,
    expected_serial: &str,
    puk: &PivPuk,
    new_pin: &PivPin,
) -> Result<()> {
    let fips = device_is_fips(id)?;
    validate_fips_code(fips, puk.as_bytes())?;
    validate_fips_code(fips, new_pin.as_bytes())?;
    with_transport_expected(id, expected_serial, |transport| {
        sigil_piv::management::unblock_pin(transport, puk, new_pin)
    })
}

pub(crate) fn change_management_key(
    id: &DeviceId,
    expected_serial: &str,
    current: &ManagementKey,
    new_key: &ManagementKey,
) -> Result<()> {
    with_transport_expected(id, expected_serial, |transport| {
        yubikey_piv::change_management_key(transport, current, new_key)
    })
}

pub(crate) fn generate_key(
    id: &DeviceId,
    expected_serial: &str,
    management_key: &ManagementKey,
    configuration: PivKeyConfiguration,
) -> Result<Vec<u8>> {
    let fips = device_is_fips(id)?;
    validate_fips_pin_policy(fips, configuration.pin_policy)?;
    with_transport_expected(id, expected_serial, |transport| {
        let result = sigil_piv::management::generate_key_pair(
            transport,
            management_key,
            configuration.slot,
            configuration.algorithm,
            configuration.pin_policy,
            configuration.touch_policy,
        );
        map_fips_status(fips, result)
    })
}

pub(crate) fn attest(
    id: &DeviceId,
    expected_serial: &str,
    slot: PivSlot,
) -> Result<PivAttestation> {
    with_transport_expected(id, expected_serial, |transport| {
        yubikey_piv::attest(transport, slot)
    })
}

pub(crate) fn sign_csr(
    id: &DeviceId,
    expected_serial: &str,
    pin: &PivPin,
    slot: PivSlot,
    subject_dn: &str,
) -> Result<Vec<u8>> {
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "slot F9 cannot sign arbitrary CSR data".into(),
        ));
    }
    validate_fips_code(device_is_fips(id)?, pin.as_bytes())?;
    with_transport_expected(id, expected_serial, |transport| {
        sigil_piv::select(transport)?;
        sigil_piv::management::verify_pin_selected(transport, pin)?;
        let spki = yubikey_piv::slot_public_key_spki(transport, slot)?;
        let (info_der, algorithm) = sigil_piv::management::build_csr_info(subject_dn, &spki)?;
        let digest = match algorithm {
            PivKeyAlgorithm::EccP256 => Sha256::digest(&info_der).to_vec(),
            PivKeyAlgorithm::EccP384 => Sha384::digest(&info_der).to_vec(),
        };
        let signature =
            sigil_piv::management::sign_digest_selected(transport, slot, algorithm, &digest)?;
        let csr = sigil_piv::management::assemble_csr(&info_der, &signature, algorithm)?;
        sigil_piv::management::verify_csr(&csr)?;
        Ok(csr)
    })
}

pub(crate) fn import_certificate(
    id: &DeviceId,
    expected_serial: &str,
    management_key: &ManagementKey,
    slot: PivSlot,
    certificate_der: &[u8],
) -> Result<()> {
    reject_attestation_slot(slot)?;
    let fips = device_is_fips(id)?;
    with_transport_expected(id, expected_serial, |transport| {
        sigil_piv::select(transport)?;
        sigil_piv::management::authenticate_management_key_selected(transport, management_key)?;
        let slot_spki = yubikey_piv::slot_public_key_spki(transport, slot)?;
        yubikey_piv::verify_certificate_matches_key(certificate_der, &slot_spki)?;
        let result =
            sigil_piv::management::put_certificate_selected(transport, slot, certificate_der);
        map_fips_status(fips, result)
    })
}

pub(crate) fn delete_certificate(
    id: &DeviceId,
    expected_serial: &str,
    management_key: &ManagementKey,
    slot: PivSlot,
) -> Result<()> {
    reject_attestation_slot(slot)?;
    let fips = device_is_fips(id)?;
    with_transport_expected(id, expected_serial, |transport| {
        sigil_piv::select(transport)?;
        sigil_piv::management::authenticate_management_key_selected(transport, management_key)?;
        let result = sigil_piv::management::delete_certificate_selected(transport, slot);
        map_fips_status(fips, result)
    })
}

pub(crate) fn delete_key(
    id: &DeviceId,
    expected_serial: &str,
    management_key: &ManagementKey,
    slot: PivSlot,
) -> Result<()> {
    reject_attestation_slot(slot)?;
    with_transport_expected(id, expected_serial, |transport| {
        sigil_piv::select(transport)?;
        sigil_piv::management::authenticate_management_key_selected(transport, management_key)?;
        yubikey_piv::delete_key_selected(transport, slot)
    })
}

pub(crate) fn reset(id: &DeviceId, expected_serial: &str) -> Result<()> {
    with_transport_expected(id, expected_serial, |transport| {
        sigil_piv::select(transport)?;
        yubikey_piv::reset_piv_selected(transport)
    })
}

fn reject_attestation_slot(slot: PivSlot) -> Result<()> {
    if slot == PivSlot::ATTESTATION {
        Err(CredentialError::UnsupportedOperation(
            "slot F9 is reserved for the YubiKey attestation key".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod fips_tests {
    use super::*;

    #[test]
    fn fips_requires_eight_character_codes_and_a_pin_policy() {
        assert_eq!(
            validate_fips_code(true, b"1234567"),
            Err(CredentialError::PivFipsNotApproved)
        );
        assert_eq!(validate_fips_code(true, b"12345678"), Ok(()));
        assert_eq!(validate_fips_code(false, b"123456"), Ok(()));
        assert_eq!(
            validate_fips_pin_policy(true, PinPolicy::Never),
            Err(CredentialError::PivFipsNotApproved)
        );
        assert_eq!(validate_fips_pin_policy(true, PinPolicy::Once), Ok(()));
        assert_eq!(validate_fips_pin_policy(false, PinPolicy::Never), Ok(()));
    }

    #[test]
    fn fips_maps_conditions_of_use_to_initialization_error_only_for_fips_devices() {
        assert_eq!(
            map_fips_status::<()>(true, Err(CredentialError::CardStatus(0x6985))),
            Err(CredentialError::PivFipsNotApproved)
        );
        assert_eq!(
            map_fips_status::<()>(false, Err(CredentialError::CardStatus(0x6985))),
            Err(CredentialError::CardStatus(0x6985))
        );
    }
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
}
