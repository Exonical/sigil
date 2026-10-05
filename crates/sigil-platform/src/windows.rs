//! Windows PC/SC discovery using WinSCard through pcsc. Only read-only
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

use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory, HidParam};
use pcsc::{Context, Error as PcscError, Protocols, ReaderState, Scope, ShareMode, State};
use sigil_core::{
    CredentialError, DeviceEvent, DeviceId, DeviceInfo, DiscoverableCredential, FidoStatus,
    Fingerprint, FingerprintProgress, FirmwareVersion, MetadataAccess, Result, Transport,
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

use crate::{FidoHidResolution, reconcile};

mod ctap;
mod fido_resolver;
pub(super) mod piv;

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
            CredentialError::BackendUnavailable(
                "could not start the smart-card event watcher".into(),
            )
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
        Ok(readers) => Ok(readers),
        Err(PcscError::NoReadersAvailable) => Ok(Vec::new()),
        Err(error) => Err(CredentialError::PcscUnavailable(error.to_string())),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReaderKind {
    YubiKeyUsb,
    Other,
}

fn reader_kind(name: &CStr) -> ReaderKind {
    let name = name.to_string_lossy().to_ascii_lowercase();
    if name.contains("yubikey") || name.contains("yubico") {
        ReaderKind::YubiKeyUsb
    } else {
        ReaderKind::Other
    }
}

fn scan(context: &Context) -> Result<Vec<DeviceInfo>> {
    let mut devices = Vec::new();
    for reader in reader_names(context)? {
        let name = reader.to_string_lossy().into_owned();
        match reader_kind(&reader) {
            ReaderKind::YubiKeyUsb => {
                let card = match context.connect(&reader, ShareMode::Shared, Protocols::ANY) {
                    Ok(card) => card,
                    Err(PcscError::NoSmartcard | PcscError::UnknownReader) => continue,
                    Err(error) => {
                        tracing::warn!(reader = %name, error = %error, "could not inspect smart-card reader");
                        devices.push(device_for_reader(&name, None, Transport::UsbSmartCard));
                        continue;
                    }
                };
                let details = read_management_info(&card);
                if details.is_none() {
                    tracing::debug!(reader = %name, "YubiKey management information unavailable");
                }
                devices.push(device_for_reader(&name, details, Transport::UsbSmartCard));
            }
            ReaderKind::Other => {
                let card = match context.connect(&reader, ShareMode::Shared, Protocols::ANY) {
                    Ok(card) => card,
                    Err(error) => {
                        tracing::debug!(reader = %name, error = %error, "could not probe non-YubiKey smart-card reader");
                        continue;
                    }
                };
                let Some(details) = read_management_info(&card) else {
                    tracing::debug!(reader = %name, "non-YubiKey smart-card ignored");
                    continue;
                };
                devices.push(device_for_reader(&name, Some(details), Transport::Nfc));
            }
        }
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
                    fips: None,
                    connection: Some(Transport::UsbHid),
                    transports: vec![Transport::UsbHid],
                    applications: Vec::new(),
                    supported_applications: Vec::new(),
                    simulated: false,
                    metadata_access: MetadataAccess::Unknown,
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
            device.metadata_access = MetadataAccess::Restricted;
            return;
        }
    };
    if let Some(metadata) = ctap::read_info(&handle) {
        device.metadata_access = MetadataAccess::Available;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FidoRoute<'a> {
    Hid(&'a str),
    PcscUsb,
}

fn fido_route<'a>(id: &'a DeviceId, connection: Option<&Transport>) -> Result<FidoRoute<'a>> {
    if let Some(path) = id.0.strip_prefix("windows-hid:") {
        return Ok(FidoRoute::Hid(path));
    }
    if id.0.starts_with("windows-pcsc:") {
        return match connection {
            Some(Transport::UsbSmartCard) => Ok(FidoRoute::PcscUsb),
            Some(Transport::Nfc) => Err(CredentialError::UnsupportedOperation(
                "FIDO over NFC is not supported yet".into(),
            )),
            _ => Err(CredentialError::UnsupportedOperation(
                "FIDO inspection requires a USB HID or CCID device".into(),
            )),
        };
    }
    Err(CredentialError::UnsupportedOperation(
        "FIDO inspection requires a supported HID or USB CCID device".into(),
    ))
}

fn resolve_fido_hid_for_pcsc_device(device: &DeviceInfo) -> Result<Option<FidoHidResolution>> {
    let (reader, _) = piv::parse_device_id(&device.id)?;
    let reader = CString::new(reader).map_err(|_| {
        CredentialError::SmartCardOperation("reader name contains a NUL byte".into())
    })?;
    fido_resolver::resolve_fido_hid_for_reader(&reader).map_err(CredentialError::SmartCardOperation)
}

fn fido_hid_path_for_reader(reader: &CStr) -> Result<Option<String>> {
    fido_resolver::fido_hid_path_for_reader(reader).map_err(CredentialError::SmartCardOperation)
}

pub(super) fn resolve_fido_hid_for_device(id: &DeviceId) -> Result<Option<FidoHidResolution>> {
    let device = list()?
        .into_iter()
        .find(|device| device.id == *id)
        .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))?;
    if !matches!(
        fido_route(id, device.connection.as_ref())?,
        FidoRoute::PcscUsb
    ) {
        return Ok(None);
    }
    resolve_fido_hid_for_pcsc_device(&device)
}

fn map_hid_open_error(error: hidapi::HidError) -> CredentialError {
    let detail = error.to_string();
    let access_denied = matches!(
        &error,
        hidapi::HidError::IoError { error }
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(5)
    ) || error_detail_is_access_denied(&detail);
    if access_denied {
        CredentialError::FidoAccessRestricted
    } else {
        CredentialError::FidoOperation(detail)
    }
}

fn map_fido_factory_error(error: impl std::fmt::Display) -> CredentialError {
    let detail = error.to_string();
    if error_detail_is_access_denied(&detail) {
        CredentialError::FidoAccessRestricted
    } else {
        CredentialError::FidoOperation(detail)
    }
}

fn error_detail_is_access_denied(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("access is denied")
        || detail.contains("access denied")
        || detail.contains("os error 5")
        || detail.contains("win32error(5)")
}

fn open_hid_fido(path: &str, expected_serial: Option<&str>) -> Result<FidoKeyHid> {
    let hid =
        hidapi::HidApi::new().map_err(|error| CredentialError::FidoOperation(error.to_string()))?;
    let hid_path = CString::new(path).map_err(|_| {
        CredentialError::SmartCardOperation("FIDO HID path contains a NUL byte".into())
    })?;
    let handle = hid.open_path(&hid_path).map_err(map_hid_open_error)?;
    if let Some(expected_serial) = expected_serial
        && let Some(actual_serial) = ctap::read_info(&handle)
            .and_then(|metadata| metadata.details)
            .and_then(|details| details.serial)
        && actual_serial != expected_serial
    {
        return Err(CredentialError::DeviceNotFound(format!(
            "PC/SC serial {expected_serial} does not match FIDO HID serial {actual_serial}"
        )));
    }
    drop(handle);
    let mut config = Cfg::init();
    config.keep_alive_msg.clear(); // Library diagnostics must not corrupt CLI JSON output.
    FidoKeyHidFactory::create_by_params(&[HidParam::Path(path.to_owned())], &config)
        .map_err(map_fido_factory_error)
}

fn open_fido(id: &DeviceId) -> Result<FidoKeyHid> {
    // Only open a present device we discovered. An opaque ID is not a general HID path API.
    let device = list()?
        .into_iter()
        .find(|device| device.id == *id)
        .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))?;
    let route = fido_route(id, device.connection.as_ref())?;
    if matches!(route, FidoRoute::Hid(_)) && device.metadata_access == MetadataAccess::Restricted {
        return Err(CredentialError::FidoAccessRestricted);
    }
    match route {
        FidoRoute::Hid(path) => open_hid_fido(path, None),
        FidoRoute::PcscUsb => {
            let (reader, _) = piv::parse_device_id(id)?;
            let reader = CString::new(reader).map_err(|_| {
                CredentialError::SmartCardOperation("reader name contains a NUL byte".into())
            })?;
            let Some(path) = fido_hid_path_for_reader(&reader)? else {
                return Err(CredentialError::UnsupportedOperation(
                    "this device has no FIDO HID interface".into(),
                ));
            };
            open_hid_fido(&path, device.serial.as_deref())
        }
    }
}

pub(super) fn fido_status(id: &DeviceId) -> Result<FidoStatus> {
    let key = open_fido(id)?;
    let info = key
        .get_info()
        .map_err(|error| CredentialError::FidoOperation(error.to_string()))?;
    let pin_set = key
        .enable_info_option(&InfoOption::ClientPin)
        .map_err(|error| CredentialError::FidoOperation(error.to_string()))?;
    let pin_retries = if pin_set == Some(true) {
        key.get_pin_retries().ok()
    } else {
        None
    };
    let credential_management = key
        .enable_info_option(&InfoOption::CredMgmt)
        .map_err(|error| CredentialError::FidoOperation(error.to_string()))?
        == Some(true)
        || key
            .enable_info_option(&InfoOption::CredentialMgmtPreview)
            .map_err(|error| CredentialError::FidoOperation(error.to_string()))?
            == Some(true);
    let standard_bio = key
        .enable_info_option(&InfoOption::BioEnroll)
        .map_err(|error| CredentialError::FidoOperation(error.to_string()))?
        .is_some();
    let preview_bio = key
        .enable_info_option(&InfoOption::UserVerificationMgmtPreview)
        .map_err(|error| CredentialError::FidoOperation(error.to_string()))?
        .is_some();
    let fingerprint_enrollment = standard_bio
        || (info
            .versions
            .iter()
            .any(|version| version == "FIDO_2_1_PRE")
            && preview_bio);
    Ok(FidoStatus {
        versions: info.versions,
        pin_set,
        pin_retries,
        credential_management,
        fingerprint_enrollment,
    })
}

fn map_fido_pin_error(error: impl std::fmt::Display) -> CredentialError {
    let detail = error.to_string();
    // ctap-hid-fido2 exposes CTAP status responses as anyhow message text, not a typed status.
    if detail.contains("0x35 CTAP2_ERR_PIN_NOT_SET") {
        CredentialError::FidoPinNotSet
    } else {
        CredentialError::FidoOperation(detail)
    }
}

fn require_fido_pin_set(key: &FidoKeyHid) -> Result<()> {
    let pin_set = key
        .enable_info_option(&InfoOption::ClientPin)
        .map_err(map_fido_pin_error)?;
    require_fido_pin_configured(pin_set)
}

fn require_fido_pin_configured(pin_set: Option<bool>) -> Result<()> {
    if pin_set == Some(false) {
        Err(CredentialError::FidoPinNotSet)
    } else {
        Ok(())
    }
}

fn open_bio(id: &DeviceId) -> Result<FidoKeyHid> {
    let mut key = open_fido(id)?;
    require_fido_pin_set(&key)?;
    let standard = key
        .enable_info_option(&InfoOption::BioEnroll)
        .map_err(|error| CredentialError::FidoOperation(error.to_string()))?
        .is_some();
    let preview = key
        .enable_info_option(&InfoOption::UserVerificationMgmtPreview)
        .map_err(|error| CredentialError::FidoOperation(error.to_string()))?
        .is_some();
    let versions = key
        .get_info()
        .map_err(|error| CredentialError::FidoOperation(error.to_string()))?
        .versions;
    if !standard && !(preview && versions.iter().any(|version| version == "FIDO_2_1_PRE")) {
        return Err(CredentialError::UnsupportedOperation(
            "FIDO fingerprint enrollment".into(),
        ));
    }
    key.use_pre_bio_enrollment = !standard;
    Ok(key)
}

fn hex_id(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn fingerprints(id: &DeviceId, pin: &str) -> Result<Vec<Fingerprint>> {
    if pin.is_empty() {
        return Err(CredentialError::FidoOperation("enter the FIDO2 PIN".into()));
    }
    let key = open_bio(id)?;
    let templates = key
        .bio_enrollment_enumerate_enrollments(pin)
        .map_err(map_fido_pin_error)?;
    Ok(templates
        .into_iter()
        .map(|template| Fingerprint {
            id: hex_id(&template.template_id),
            name: template.template_friendly_name,
        })
        .collect())
}

pub(super) fn enroll_fingerprint(
    id: &DeviceId,
    pin: &str,
    on_progress: &mut dyn FnMut(FingerprintProgress),
) -> Result<Fingerprint> {
    if pin.is_empty() {
        return Err(CredentialError::FidoOperation("enter the FIDO2 PIN".into()));
    }
    let key = open_bio(id)?;
    on_progress(FingerprintProgress {
        message: "Touch the sensor with the finger to enroll.".into(),
        remaining_samples: 0,
    });
    let (session, mut step) = key
        .bio_enrollment_begin(pin, Some(30_000))
        .map_err(map_fido_pin_error)?;
    let result = (|| {
        for _ in 0..40 {
            on_progress(FingerprintProgress {
                message: step.message.clone(),
                remaining_samples: step.remaining_samples,
            });
            if step.is_finish {
                return Ok(Fingerprint {
                    id: hex_id(&session.template_id),
                    name: None,
                });
            }
            on_progress(FingerprintProgress {
                message: "Lift your finger, then touch the sensor again.".into(),
                remaining_samples: step.remaining_samples,
            });
            step = key
                .bio_enrollment_next(&session, Some(30_000))
                .map_err(map_fido_pin_error)?;
        }
        Err(CredentialError::FidoOperation(
            "fingerprint capture limit reached".into(),
        ))
    })();
    if result.is_err() {
        let _ = key.bio_enrollment_cancel();
    }
    result
}

pub(super) fn remove_fingerprint(id: &DeviceId, pin: &str, fingerprint_id: &str) -> Result<()> {
    if pin.is_empty() {
        return Err(CredentialError::FidoOperation("enter the FIDO2 PIN".into()));
    }
    if fingerprint_id.is_empty() || !fingerprint_id.len().is_multiple_of(2) {
        return Err(CredentialError::FidoOperation(
            "invalid fingerprint ID".into(),
        ));
    }
    let bytes: Vec<u8> = fingerprint_id
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|value| u8::from_str_radix(value, 16).ok())
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| CredentialError::FidoOperation("invalid fingerprint ID".into()))?;
    let key = open_bio(id)?;
    let templates = key
        .bio_enrollment_enumerate_enrollments(pin)
        .map_err(map_fido_pin_error)?;
    if !templates
        .iter()
        .any(|template| template.template_id == bytes)
    {
        return Err(CredentialError::FidoOperation(
            "fingerprint ID was not found on this key".into(),
        ));
    }
    key.bio_enrollment_remove(pin, &bytes)
        .map_err(map_fido_pin_error)
}

pub(super) fn discoverable_credentials(
    id: &DeviceId,
    pin: &str,
) -> Result<Vec<DiscoverableCredential>> {
    if pin.is_empty() {
        return Err(CredentialError::FidoOperation("enter the FIDO2 PIN".into()));
    }
    let mut key = open_fido(id)?;
    require_fido_pin_set(&key)?;
    let standard = key
        .enable_info_option(&InfoOption::CredMgmt)
        .map_err(|error| CredentialError::FidoOperation(error.to_string()))?
        == Some(true);
    if !standard
        && key
            .enable_info_option(&InfoOption::CredentialMgmtPreview)
            .map_err(|error| CredentialError::FidoOperation(error.to_string()))?
            != Some(true)
    {
        return Err(CredentialError::UnsupportedOperation(
            "FIDO credential management".into(),
        ));
    }
    key.use_pre_credential_management = !standard;
    let count = key
        .credential_management_get_creds_metadata(Some(pin))
        .map_err(map_fido_pin_error)?;
    if count.existing_resident_credentials_count == 0 {
        return Ok(Vec::new());
    }
    let rps = key
        .credential_management_enumerate_rps(Some(pin))
        .map_err(map_fido_pin_error)?;
    let mut credentials = Vec::new();
    for rp in rps {
        let entries = key
            .credential_management_enumerate_credentials(Some(pin), &rp.rpid_hash)
            .map_err(map_fido_pin_error)?;
        for entry in entries {
            credentials.push(DiscoverableCredential {
                rp_id: rp.public_key_credential_rp_entity.id.clone(),
                rp_name: rp.public_key_credential_rp_entity.name.clone(),
                user_name: entry.public_key_credential_user_entity.name,
                user_display_name: entry.public_key_credential_user_entity.display_name,
                credential_id: entry
                    .public_key_credential_descriptor
                    .id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            });
        }
    }
    Ok(credentials)
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
        fips: None,
        connection: Some(Transport::UsbHid),
        transports: vec![Transport::UsbHid],
        applications: Vec::new(),
        supported_applications: Vec::new(),
        simulated: false,
        metadata_access: MetadataAccess::Unknown,
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

fn device_for_reader(
    reader: &str,
    details: Option<ManagementInfo>,
    connection: Transport,
) -> DeviceInfo {
    let metadata_access = if details.is_some() {
        MetadataAccess::Available
    } else {
        MetadataAccess::Unknown
    };
    let is_nfc = connection == Transport::Nfc;
    let serial = details.as_ref().and_then(|info| info.serial.clone());
    let firmware = details.as_ref().and_then(|info| info.firmware.clone());
    let form_factor = details.as_ref().and_then(|info| info.form_factor.clone());
    let fips = details.as_ref().and_then(|info| info.fips);
    let mut transports = details
        .as_ref()
        .map(|info| info.transports.clone())
        .unwrap_or_else(|| vec![Transport::UsbSmartCard]);
    if is_nfc && !transports.contains(&Transport::Nfc) {
        transports.push(Transport::Nfc);
    }
    let applications = details
        .as_ref()
        .map(|info| {
            if is_nfc {
                info.nfc_enabled_applications.clone()
            } else {
                info.enabled_applications.clone()
            }
        })
        .unwrap_or_default();
    let supported_applications = details
        .as_ref()
        .map(|info| {
            if is_nfc {
                info.nfc_supported_applications.clone()
            } else {
                info.supported_applications.clone()
            }
        })
        .unwrap_or_default();
    let id = DeviceId(format!(
        "windows-pcsc:{reader}:{}",
        serial.as_deref().unwrap_or("unknown")
    ));
    DeviceInfo {
        id,
        vendor: "Yubico".into(),
        // Do not fabricate a retail model from a form factor or reader name.
        model: if is_nfc {
            "YubiKey (NFC)".into()
        } else {
            "YubiKey (CCID)".into()
        },
        serial,
        firmware,
        form_factor,
        fips,
        connection: Some(connection),
        transports,
        applications,
        supported_applications,
        simulated: false,
        metadata_access,
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
    use sigil_core::Application;

    fn reader_kind_from_name(name: &str) -> ReaderKind {
        let reader = CString::new(name).expect("reader name");
        reader_kind(reader.as_c_str())
    }

    fn management_info_for_reader() -> ManagementInfo {
        ManagementInfo {
            serial: Some("12345678".into()),
            firmware: Some(FirmwareVersion {
                major: 5,
                minor: 7,
                patch: 1,
            }),
            form_factor: Some("Keychain (USB-A)".into()),
            fips: Some(false),
            transports: vec![
                Transport::UsbSmartCard,
                Transport::UsbHid,
                Transport::UsbOtp,
            ],
            enabled_applications: vec![Application::Fido2],
            supported_applications: vec![Application::Fido2, Application::Piv],
            nfc_enabled_applications: vec![Application::Piv],
            nfc_supported_applications: vec![Application::Piv, Application::Oath],
        }
    }

    #[test]
    fn classifies_yubico_readers_and_external_pcsc_readers() {
        for name in ["Yubico YubiKey OTP+FIDO+CCID 0", "YubiKey 5 NFC"] {
            assert_eq!(reader_kind_from_name(name), ReaderKind::YubiKeyUsb);
        }
        for name in [
            "ACS ACR1252 1S CL Reader PICC 0",
            "HID Global OMNIKEY 5022 Smart Card Reader 0",
            "Identiv uTrust 3700 F CL Reader 0",
        ] {
            assert_eq!(reader_kind_from_name(name), ReaderKind::Other);
        }
    }

    #[test]
    fn fido_dispatch_accepts_hid_and_pcsc_usb_ids() {
        assert_eq!(
            fido_route(
                &DeviceId("windows-hid:fido-path".into()),
                Some(&Transport::UsbHid),
            )
            .unwrap(),
            FidoRoute::Hid("fido-path")
        );
        assert_eq!(
            fido_route(
                &DeviceId("windows-pcsc:Reader:39192733".into()),
                Some(&Transport::UsbSmartCard),
            )
            .unwrap(),
            FidoRoute::PcscUsb
        );
    }

    #[test]
    fn fido_dispatch_rejects_nfc_before_resolving_hid() {
        assert!(matches!(
            fido_route(
                &DeviceId("windows-pcsc:Reader:39192733".into()),
                Some(&Transport::Nfc),
            ),
            Err(CredentialError::UnsupportedOperation(message))
                if message == "FIDO over NFC is not supported yet"
        ));
    }

    #[test]
    fn maps_pin_not_set_ctap_error_and_fails_fast_from_get_info() {
        assert_eq!(
            map_fido_pin_error(
                "response_status err = 0x35 CTAP2_ERR_PIN_NOT_SET No PIN has been set."
            ),
            CredentialError::FidoPinNotSet
        );
        assert_eq!(
            map_fido_pin_error("response_status err = 0x31 CTAP2_ERR_PIN_INVALID"),
            CredentialError::FidoOperation(
                "response_status err = 0x31 CTAP2_ERR_PIN_INVALID".into()
            )
        );
        assert_eq!(
            require_fido_pin_configured(Some(false)),
            Err(CredentialError::FidoPinNotSet)
        );
        assert_eq!(require_fido_pin_configured(Some(true)), Ok(()));
        assert_eq!(require_fido_pin_configured(None), Ok(()));
    }

    #[test]
    fn reader_connection_selects_nfc_or_usb_management_capabilities() {
        let nfc = device_for_reader(
            "ACS ACR1252 Reader 0",
            Some(management_info_for_reader()),
            Transport::Nfc,
        );
        assert_eq!(nfc.model, "YubiKey (NFC)");
        assert_eq!(nfc.connection, Some(Transport::Nfc));
        assert_eq!(nfc.fips, Some(false));
        assert_eq!(nfc.applications, vec![Application::Piv]);
        assert_eq!(
            nfc.supported_applications,
            vec![Application::Piv, Application::Oath]
        );
        assert!(nfc.transports.contains(&Transport::Nfc));
        assert_eq!(nfc.id.0, "windows-pcsc:ACS ACR1252 Reader 0:12345678");

        let usb = device_for_reader(
            "Yubico YubiKey 0",
            Some(management_info_for_reader()),
            Transport::UsbSmartCard,
        );
        assert_eq!(usb.model, "YubiKey (CCID)");
        assert_eq!(usb.connection, Some(Transport::UsbSmartCard));
        assert_eq!(usb.fips, Some(false));
        assert_eq!(usb.applications, vec![Application::Fido2]);
        assert_eq!(
            usb.supported_applications,
            vec![Application::Fido2, Application::Piv]
        );
        assert_eq!(
            usb.transports,
            vec![
                Transport::UsbSmartCard,
                Transport::UsbHid,
                Transport::UsbOtp
            ]
        );
    }

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
        let device = device_for_reader("Yubico YubiKey 0", None, Transport::UsbSmartCard);
        assert!(!device.simulated);
        assert!(device.serial.is_none());
        assert!(device.fips.is_none());
        assert!(device.applications.is_empty());
        assert_eq!(device.connection, Some(Transport::UsbSmartCard));
        assert_eq!(device.transports, vec![Transport::UsbSmartCard]);
    }
}
