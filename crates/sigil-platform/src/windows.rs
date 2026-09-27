//! Windows CCID discovery using WinSCard through pcsc. Only read-only
//! management APDUs are sent; no arbitrary APDU interface escapes this module.

use std::{
    ffi::{CStr, CString},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

use pcsc::{Context, Error as PcscError, Protocols, ReaderState, Scope, ShareMode, State};
use sigil_core::{
    CredentialError, DeviceEvent, DeviceId, DeviceInfo, FirmwareVersion, Result, Transport,
};
use sigil_yubikey::management::{self, ManagementInfo, TAG_MORE_DATA, Tags};

use crate::reconcile;

const MANAGEMENT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
const MAX_INFO_PAGES: u8 = 4;

pub(super) fn list() -> Result<Vec<DeviceInfo>> {
    match establish() {
        Ok(context) => scan(&context),
        Err(pcsc_error) => match scan_hid() {
            Ok(devices) if !devices.is_empty() => Ok(devices),
            _ => Err(pcsc_error),
        },
    }
}

pub(super) fn subscribe() -> Result<Receiver<DeviceEvent>> {
    let context = establish().ok();
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("sigil-device-events".into())
        .spawn(move || match context {
            Some(context) => watch(context, sender),
            None => watch_hid_only(sender),
        })
        .map_err(|_| {
            CredentialError::BackendUnavailable("could not start the smart-card event watcher")
        })?;
    Ok(receiver)
}

fn establish() -> Result<Context> {
    Context::establish(Scope::User)
        .map_err(|error| CredentialError::PcscUnavailable(error.to_string()))
}

fn reader_names(context: &Context) -> Result<Vec<CString>> {
    match context.list_readers_owned() {
        Ok(readers) => Ok(readers
            .into_iter()
            .filter(|reader| is_yubikey_reader(reader))
            .collect()),
        Err(PcscError::NoReadersAvailable) => Ok(Vec::new()),
        Err(error) => Err(CredentialError::PcscUnavailable(error.to_string())),
    }
}

fn is_yubikey_reader(reader: &CStr) -> bool {
    let name = reader.to_string_lossy().to_ascii_lowercase();
    name.contains("yubikey") || name.contains("yubico")
}

fn scan(context: &Context) -> Result<Vec<DeviceInfo>> {
    let mut devices = Vec::new();
    for reader in reader_names(context)? {
        let name = reader.to_string_lossy().into_owned();
        let card = match context.connect(&reader, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => card,
            Err(PcscError::NoSmartcard | PcscError::UnknownReader) => continue,
            Err(error) => {
                tracing::warn!(reader = %name, error = %error, "could not inspect smart-card reader");
                devices.push(device_for_reader(&name, None));
                continue;
            }
        };
        let details = read_management_info(&card);
        if details.is_none() {
            tracing::debug!(reader = %name, "YubiKey management information unavailable");
        }
        devices.push(device_for_reader(&name, details));
    }
    // FIDO-only product IDs have no CCID interface, so these cannot duplicate
    // a PC/SC result. HID presence does not prove CTAP2 or a firmware version.
    match scan_hid() {
        Ok(hid_devices) => devices.extend(hid_devices),
        Err(error) => tracing::warn!(%error, "FIDO HID enumeration unavailable"),
    }
    devices.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    Ok(devices)
}

fn scan_hid() -> std::result::Result<Vec<DeviceInfo>, hidapi::HidError> {
    let hid = hidapi::HidApi::new()?;
    Ok(hid.device_list().filter_map(fido_only_device).collect())
}

fn watch_hid_only(sender: Sender<DeviceEvent>) {
    let mut previous = Vec::new();
    loop {
        if let Ok(current) = scan_hid()
            && !reconcile(&mut previous, current, &sender)
        {
            return;
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn fido_only_device(info: &hidapi::DeviceInfo) -> Option<DeviceInfo> {
    const YUBICO_VENDOR_ID: u16 = 0x1050;
    if info.vendor_id() != YUBICO_VENDOR_ID
        || !is_fido_only_pid(info.product_id())
        || info.usage_page() != 0xf1d0
        || info.usage() != 1
    {
        return None;
    }
    let path = info.path().to_string_lossy();
    Some(DeviceInfo {
        id: DeviceId(format!("windows-hid:{path}")),
        vendor: "Yubico".into(),
        model: info
            .product_string()
            .unwrap_or("Yubico FIDO security key")
            .into(),
        serial: info.serial_number().map(str::to_owned),
        firmware: None,
        form_factor: None,
        transports: vec![Transport::UsbHid],
        applications: Vec::new(),
        supported_applications: Vec::new(),
        simulated: false,
    })
}

fn is_fido_only_pid(pid: u16) -> bool {
    // Yubico's USB product IDs with FIDO but no CCID interface.
    matches!(pid, 0x0113 | 0x0114 | 0x0120 | 0x0402 | 0x0403 | 0x0410)
}

fn device_for_reader(reader: &str, details: Option<ManagementInfo>) -> DeviceInfo {
    let serial = details.as_ref().and_then(|info| info.serial.clone());
    let firmware = details.as_ref().and_then(|info| info.firmware.clone());
    let form_factor = details.as_ref().and_then(|info| info.form_factor.clone());
    let id = DeviceId(format!(
        "windows-pcsc:{reader}:{}",
        serial.as_deref().unwrap_or("unknown")
    ));
    DeviceInfo {
        id,
        vendor: "Yubico".into(),
        // Do not fabricate a retail model from a form factor or reader name.
        model: "YubiKey (CCID)".into(),
        serial,
        firmware,
        form_factor,
        transports: details
            .as_ref()
            .map(|info| info.transports.clone())
            .unwrap_or_else(|| vec![Transport::UsbSmartCard]),
        applications: details
            .as_ref()
            .map(|info| info.enabled_applications.clone())
            .unwrap_or_default(),
        supported_applications: details
            .map(|info| info.supported_applications)
            .unwrap_or_default(),
        simulated: false,
    }
}

fn read_management_info(card: &pcsc::Card) -> Option<ManagementInfo> {
    let mut select = vec![0x00, 0xa4, 0x04, 0x00, MANAGEMENT_AID.len() as u8];
    select.extend_from_slice(&MANAGEMENT_AID);
    let select_response = send_read_only(card, &select)?;
    let select_version = parse_select_version(&select_response);
    let mut all_tags = Tags::new();
    let mut page = 0;
    loop {
        if page >= MAX_INFO_PAGES {
            return None;
        }
        let encoded = send_read_only(card, &[0x00, 0x1d, page, 0x00, 0x00])?;
        let mut tags = management::parse_page(&encoded).ok()?;
        let more = tags
            .remove(&TAG_MORE_DATA)
            .is_some_and(|value| value.iter().any(|byte| *byte != 0));
        all_tags.append(&mut tags);
        if !more {
            break;
        }
        page += 1;
    }
    ManagementInfo::from_tags(&all_tags, select_version).ok()
}

fn send_read_only(card: &pcsc::Card, command: &[u8]) -> Option<Vec<u8>> {
    let mut buffer = [0u8; 1024];
    let response = card.transmit(command, &mut buffer).ok()?;
    if response.len() < 2 || response[response.len() - 2..] != [0x90, 0x00] {
        return None;
    }
    Some(response[..response.len() - 2].to_vec())
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

fn watch(context: Context, sender: Sender<DeviceEvent>) {
    let mut previous = Vec::new();
    let mut names = Vec::new();
    let mut states = vec![ReaderState::new(
        pcsc::PNP_NOTIFICATION().to_owned(),
        State::UNAWARE,
    )];
    loop {
        let current_names = match reader_names(&context) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "smart-card watcher stopped");
                return;
            }
        };
        if names != current_names {
            names = current_names;
            states = std::iter::once(ReaderState::new(
                pcsc::PNP_NOTIFICATION().to_owned(),
                State::UNAWARE,
            ))
            .chain(
                names
                    .iter()
                    .cloned()
                    .map(|name| ReaderState::new(name, State::UNAWARE)),
            )
            .collect();
        }
        let current = match scan(&context) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "smart-card watcher stopped");
                return;
            }
        };
        if !reconcile(&mut previous, current, &sender) {
            return;
        }
        match context.get_status_change(Duration::from_secs(5), &mut states) {
            Ok(()) => states.iter_mut().for_each(ReaderState::sync_current_state),
            Err(PcscError::Timeout) => {}
            Err(error) => {
                tracing::warn!(%error, "smart-card watcher stopped");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fido_only_products_cannot_duplicate_ccid_readers() {
        assert!(is_fido_only_pid(0x0120));
        assert!(is_fido_only_pid(0x0403));
        assert!(!is_fido_only_pid(0x0407));
        assert!(!is_fido_only_pid(0x0406));
    }

    #[test]
    fn unavailable_metadata_does_not_invent_capabilities() {
        let device = device_for_reader("Yubico YubiKey 0", None);
        assert!(!device.simulated);
        assert!(device.serial.is_none());
        assert!(device.applications.is_empty());
        assert_eq!(device.transports, vec![Transport::UsbSmartCard]);
    }
}
