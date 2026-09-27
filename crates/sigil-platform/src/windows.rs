//! Windows CCID discovery using WinSCard through pcsc. Only read-only
//! management APDUs are sent; no arbitrary APDU interface escapes this module.

use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    mem::{size_of, size_of_val},
    ptr::{null, null_mut},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

use pcsc::{Context, Error as PcscError, Protocols, ReaderState, Scope, ShareMode, State};
use sigil_core::{
    CredentialError, DeviceEvent, DeviceId, DeviceInfo, FirmwareVersion, Result, Transport,
};
use sigil_yubikey::management::{self, ManagementInfo, TAG_MORE_DATA, Tags};
use windows_sys::Win32::{
    Devices::{
        DeviceAndDriverInstallation::{
            DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO, SP_DEVICE_INTERFACE_DATA,
            SP_DEVICE_INTERFACE_DETAIL_DATA_W, SetupDiDestroyDeviceInfoList,
            SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
        },
        HumanInterfaceDevice::HidD_GetHidGuid,
    },
    Foundation::ERROR_NO_MORE_ITEMS,
};

use crate::reconcile;

mod ctap;

const MANAGEMENT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
const MAX_INFO_PAGES: u8 = 4;

pub(super) fn list() -> Result<Vec<DeviceInfo>> {
    match establish() {
        Ok(context) => scan(&context),
        Err(error) if service_stopped(error) => {
            tracing::warn!(%error, "Windows Smart Card resource manager is unavailable; CCID details are unavailable");
            scan_hid(true).map_err(|hid_error| {
                CredentialError::PcscUnavailable(format!(
                    "{error}; HID enumeration also failed: {hid_error}"
                ))
            })
        }
        Err(error) => Err(CredentialError::PcscUnavailable(error.to_string())),
    }
}

pub(super) fn subscribe() -> Result<Receiver<DeviceEvent>> {
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("sigil-device-events".into())
        .spawn(move || watch_devices(sender))
        .map_err(|_| {
            CredentialError::BackendUnavailable("could not start the smart-card event watcher")
        })?;
    Ok(receiver)
}

fn establish() -> std::result::Result<Context, PcscError> {
    Context::establish(Scope::User)
}

fn service_stopped(error: PcscError) -> bool {
    matches!(error, PcscError::NoService | PcscError::ServiceStopped)
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
    match scan_hid(false) {
        Ok(hid_devices) => devices.extend(hid_devices),
        Err(error) => tracing::warn!(%error, "FIDO HID enumeration unavailable"),
    }
    devices.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    Ok(devices)
}

fn scan_hid(include_ccid: bool) -> std::result::Result<Vec<DeviceInfo>, String> {
    let hid_result = hidapi::HidApi::new();
    let non_fido_paths: HashSet<_> = hid_result
        .as_ref()
        .map(|hid| {
            hid.device_list()
                .filter(|info| {
                    info.vendor_id() == 0x1050
                        && info.usage_page() != 0
                        && (info.usage_page(), info.usage()) != (0xf1d0, 1)
                })
                .map(|info| info.path().to_string_lossy().to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let mut devices: Vec<_> = hid_result
        .as_ref()
        .map(|hid| {
            hid.device_list()
                .filter_map(|info| {
                    let mut device = fido_device(info, include_ccid)?;
                    enrich_hid(&mut device, hid, info.path());
                    Some(device)
                })
                .collect()
        })
        .unwrap_or_default();

    // Windows may expose a FIDO HID interface but deny even read-only access
    // to its descriptor. Enumerate present HID interface paths as a fallback;
    // the known Yubico PID proves HID presence, not CTAP2 capability.
    match hid_interface_paths() {
        Ok(paths) => {
            for path in paths {
                if non_fido_paths.contains(&path) {
                    continue;
                }
                let Some(pid) = yubico_pid_from_path(&path) else {
                    continue;
                };
                if !(is_fido_only_pid(pid) || (include_ccid && is_fido_ccid_pid(pid))) {
                    continue;
                }
                let id = DeviceId(format!("windows-hid:{path}"));
                if devices.iter().any(|device| device.id == id) {
                    continue;
                }
                let mut device = DeviceInfo {
                    id,
                    vendor: "Yubico".into(),
                    model: "Yubico FIDO security key".into(),
                    serial: None,
                    firmware: None,
                    form_factor: None,
                    transports: vec![Transport::UsbHid],
                    applications: Vec::new(),
                    supported_applications: Vec::new(),
                    simulated: false,
                };
                if let (Ok(hid), Ok(path)) = (&hid_result, CString::new(path)) {
                    enrich_hid(&mut device, hid, &path);
                }
                devices.push(device);
            }
        }
        Err(error) if hid_result.is_err() => {
            return Err(format!("HID enumeration failed: {error}"));
        }
        Err(error) => tracing::warn!(%error, "HID interface path enumeration unavailable"),
    }
    devices.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    Ok(devices)
}

fn enrich_hid(device: &mut DeviceInfo, hid: &hidapi::HidApi, path: &CStr) {
    let handle = match hid.open_path(path) {
        Ok(handle) => handle,
        Err(error) => {
            tracing::debug!(%error, id = %device.id.0, "FIDO metadata access unavailable");
            return;
        }
    };
    if let Some(metadata) = ctap::read_info(&handle) {
        device.firmware = metadata.firmware;
        if let Some(details) = metadata.details {
            device.serial = details.serial;
            device.firmware = details.firmware.or(device.firmware.take());
            device.form_factor = details.form_factor;
            device.applications = details.enabled_applications;
            device.supported_applications = details.supported_applications;
            if details.transports.contains(&Transport::UsbOtp) {
                device.transports.push(Transport::UsbOtp);
            }
            if details.transports.contains(&Transport::Nfc) {
                device.transports.push(Transport::Nfc);
            }
        }
    } else {
        tracing::debug!(id = %device.id.0, "FIDO management metadata unavailable from device");
    }
}

fn yubico_pid_from_path(path: &str) -> Option<u16> {
    let lowercase = path.to_ascii_lowercase();
    let mut parts = lowercase.split(['#', '&']);
    if !parts.next()?.ends_with("hid") || parts.next()? != "vid_1050" {
        return None;
    }
    u16::from_str_radix(parts.next()?.strip_prefix("pid_")?, 16).ok()
}

struct HidInterfaceSet(HDEVINFO);

impl Drop for HidInterfaceSet {
    fn drop(&mut self) {
        // SAFETY: The handle came from SetupDiGetClassDevsW and is owned here.
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

fn hid_interface_paths() -> std::io::Result<Vec<String>> {
    let mut guid = windows_sys::core::GUID::from_u128(0);
    // SAFETY: All pointers below refer to initialized, sized buffers. The
    // interface set stays alive until enumeration completes.
    unsafe {
        HidD_GetHidGuid(&mut guid);
        let handle = SetupDiGetClassDevsW(
            &guid,
            null(),
            null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );
        if handle == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let set = HidInterfaceSet(handle);
        let mut paths = Vec::new();
        let mut index = 0;
        loop {
            let mut interface = SP_DEVICE_INTERFACE_DATA::default();
            interface.cbSize = size_of_val(&interface) as u32;
            if SetupDiEnumDeviceInterfaces(set.0, null(), &guid, index, &mut interface) == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                    return Ok(paths);
                }
                return Err(error);
            }
            index += 1;
            let mut bytes = 0;
            SetupDiGetDeviceInterfaceDetailW(
                set.0,
                &interface,
                null_mut(),
                0,
                &mut bytes,
                null_mut(),
            );
            if bytes < size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32 {
                continue;
            }
            let mut buffer = vec![0u64; (bytes as usize).div_ceil(size_of::<u64>())];
            let detail = buffer
                .as_mut_ptr()
                .cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
            (*detail).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
            if SetupDiGetDeviceInterfaceDetailW(
                set.0,
                &interface,
                detail,
                bytes,
                null_mut(),
                null_mut(),
            ) == 0
            {
                continue;
            }
            let offset = 4usize; // DevicePath follows the DWORD cbSize.
            let path_ptr = std::ptr::addr_of!((*detail).DevicePath).cast::<u16>();
            let path_buffer = std::slice::from_raw_parts(path_ptr, (bytes as usize - offset) / 2);
            let length = path_buffer
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(path_buffer.len());
            paths.push(String::from_utf16_lossy(&path_buffer[..length]).to_ascii_lowercase());
        }
    }
}

fn watch_devices(sender: Sender<DeviceEvent>) {
    let mut previous = Vec::new();
    loop {
        match establish() {
            Ok(context) => {
                if !watch(context, &sender, &mut previous) {
                    return;
                }
            }
            Err(error) if service_stopped(error) => {
                if let Ok(current) = scan_hid(true)
                    && !reconcile(&mut previous, current, &sender)
                {
                    return;
                }
            }
            Err(error) => tracing::warn!(%error, "smart-card watcher could not connect"),
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn fido_device(info: &hidapi::DeviceInfo, include_ccid: bool) -> Option<DeviceInfo> {
    const YUBICO_VENDOR_ID: u16 = 0x1050;
    if info.vendor_id() != YUBICO_VENDOR_ID
        || !(is_fido_only_pid(info.product_id())
            || (include_ccid && is_fido_ccid_pid(info.product_id())))
        || info.usage_page() != 0xf1d0
        || info.usage() != 1
    {
        return None;
    }
    let path = info.path().to_string_lossy();
    Some(DeviceInfo {
        id: DeviceId(format!("windows-hid:{}", path.to_ascii_lowercase())),
        vendor: "Yubico".into(),
        model: info
            .product_string()
            .filter(|value| !value.is_empty())
            .unwrap_or("Yubico FIDO security key")
            .into(),
        serial: info
            .serial_number()
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
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

fn is_fido_ccid_pid(pid: u16) -> bool {
    // These products expose both interfaces; use HID only while PC/SC is down.
    matches!(pid, 0x0115 | 0x0116 | 0x0406 | 0x0407)
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

// Return to the supervisor when PC/SC stops so HID monitoring can continue.
fn watch(context: Context, sender: &Sender<DeviceEvent>, previous: &mut Vec<DeviceInfo>) -> bool {
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
                return true;
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
                return true;
            }
        };
        if !reconcile(previous, current, sender) {
            return false;
        }
        match context.get_status_change(Duration::from_secs(5), &mut states) {
            Ok(()) => states.iter_mut().for_each(ReaderState::sync_current_state),
            Err(PcscError::Timeout) => {}
            Err(error) => {
                tracing::warn!(%error, "smart-card watcher stopped");
                return true;
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
        assert!(is_fido_ccid_pid(0x0407));
        assert!(!is_fido_ccid_pid(0x0403));
    }

    #[test]
    fn stopped_service_is_a_distinct_recoverable_condition() {
        assert!(service_stopped(PcscError::NoService));
        assert!(service_stopped(PcscError::ServiceStopped));
        assert!(!service_stopped(PcscError::NoReadersAvailable));
    }

    #[test]
    fn hid_path_identifies_the_fido_only_key_seen_on_windows() {
        let path = r"\\?\HID#VID_1050&PID_0402#9&1FEDC092&0&0000#{guid}";
        assert_eq!(yubico_pid_from_path(path), Some(0x0402));
        assert!(is_fido_only_pid(0x0402));
        assert_eq!(yubico_pid_from_path(r"\\?\hid#vid_1234&pid_0402#x"), None);
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
