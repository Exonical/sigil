use std::ffi::CString;

use pcsc::{Card, Error as PcscError, Protocols, ShareMode, Transaction};
use sigil_core::{
    CredentialError, DeviceId, PivCertificate, PivInfo, PivSlot, PivSlotInfo, Result,
};
use sigil_piv::CardTransport;
use sigil_yubikey::piv as yubikey_piv;

use super::{establish, list};

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

fn parse_device_id(id: &DeviceId) -> Result<(String, Option<String>)> {
    let rest =
        id.0.strip_prefix("windows-pcsc:")
            .ok_or(CredentialError::UnsupportedOperation(
                "PIV inspection requires a smart-card interface",
            ))?;
    let (reader, serial) = rest
        .rsplit_once(':')
        .ok_or(CredentialError::UnsupportedOperation(
            "PIV inspection requires a smart-card interface",
        ))?;
    if reader.is_empty() || serial.is_empty() {
        return Err(CredentialError::UnsupportedOperation(
            "PIV inspection requires a smart-card interface",
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
    let mut card: Card = context
        .connect(&reader, ShareMode::Shared, Protocols::ANY)
        .map_err(map_pcsc_error)?;
    let transaction = card.transaction().map_err(map_pcsc_error)?;
    let mut transport = PcscTransport {
        transaction: &transaction,
    };
    if let Some(serial) = expected_serial {
        yubikey_piv::verify_serial(&mut transport, &serial)?;
    }
    operation(&mut transport)
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
