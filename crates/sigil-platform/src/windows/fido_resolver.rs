use std::{
    collections::HashSet,
    ffi::CStr,
    mem::size_of,
    ptr::{null, null_mut},
};

use hidapi::HidApi;
use windows_sys::Win32::{
    Devices::{
        DeviceAndDriverInstallation::{
            CM_Get_Device_IDW, CM_Get_Device_Interface_PropertyW, CM_Get_Parent,
            CM_LOCATE_DEVNODE_NORMAL, CM_Locate_DevNodeW, CR_BUFFER_SMALL, CR_SUCCESS,
        },
        Properties::{DEVPKEY_Device_InstanceId, DEVPROP_TYPE_STRING},
    },
    Foundation::SCARD_E_INSUFFICIENT_BUFFER,
    Security::Credentials::{
        SCARD_SCOPE_USER, SCardEstablishContext, SCardGetReaderDeviceInstanceIdW,
        SCardReleaseContext,
    },
};

const MAX_DEVICE_ID_CHARS: usize = 512;
const MAX_PARENT_DEPTH: usize = 32;

struct SmartCardContext(usize);

impl Drop for SmartCardContext {
    fn drop(&mut self) {
        // SAFETY: The context is owned by this guard and was returned by SCardEstablishContext.
        unsafe { SCardReleaseContext(self.0) };
    }
}

pub(super) fn fido_hid_path_for_reader(
    reader: &CStr,
) -> std::result::Result<Option<String>, String> {
    Ok(resolve_fido_hid_for_reader(reader)?.map(|resolution| resolution.hid_path))
}

pub(super) fn resolve_fido_hid_for_reader(
    reader: &CStr,
) -> std::result::Result<Option<crate::FidoHidResolution>, String> {
    let reader_instance_id = reader_device_instance_id(reader)?;
    let Some(reader_composite_id) = usb_composite_parent_id(&reader_instance_id) else {
        return Ok(None);
    };
    let non_fido_paths: HashSet<_> = HidApi::new()
        .ok()
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
    let mut matches = Vec::new();
    // Match scan_hid's usage-page filtering and its known-PID fallback when
    // HIDAPI cannot expose a device descriptor to this unprivileged process.
    for path in super::hid_interface_paths().map_err(|error| error.to_string())? {
        if non_fido_paths.contains(&path) {
            continue;
        }
        let Some(pid) = super::yubico_pid_from_path(&path) else {
            continue;
        };
        if !super::is_fido_ccid_pid(pid) {
            continue;
        }
        let Some(instance_id) = device_interface_instance_id(&path) else {
            continue;
        };
        let Some(hid_composite_id) = usb_composite_parent_id(&instance_id) else {
            continue;
        };
        if same_usb_composite_parent(&reader_composite_id, &hid_composite_id) {
            matches.push(crate::FidoHidResolution {
                hid_path: path,
                reader_composite_id: reader_composite_id.clone(),
                hid_composite_id,
            });
        }
    }
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        count => Err(format!(
            "multiple FIDO HID interfaces ({count}) match the PC/SC reader's USB parent"
        )),
    }
}

pub(super) fn same_usb_composite_parent(left: &str, right: &str) -> bool {
    is_usb_composite_id(left) && is_usb_composite_id(right) && left.eq_ignore_ascii_case(right)
}

fn is_usb_composite_id(device_instance_id: &str) -> bool {
    let mut components = device_instance_id.split('\\');
    let Some(bus) = components.next() else {
        return false;
    };
    let Some(hardware) = components.next() else {
        return false;
    };
    let Some(instance) = components.next() else {
        return false;
    };
    bus.eq_ignore_ascii_case("USB")
        && hardware.to_ascii_uppercase().starts_with("VID_1050&PID_")
        && !hardware.to_ascii_uppercase().contains("&MI_")
        && !instance.is_empty()
}

fn reader_device_instance_id(reader: &CStr) -> std::result::Result<String, String> {
    let mut context = 0usize;
    // SAFETY: Reserved pointers are null as required; context is a writable output slot.
    let result = unsafe { SCardEstablishContext(SCARD_SCOPE_USER, null(), null(), &mut context) };
    if result != 0 || context == 0 {
        return Err(format!(
            "could not establish a PC/SC context for reader identity (SCARD 0x{:08X})",
            result as u32
        ));
    }
    let context = SmartCardContext(context);
    let reader_wide: Vec<u16> = reader
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut characters = 0u32;
    // SAFETY: The null buffer is the documented size-query form and characters is writable.
    let result = unsafe {
        SCardGetReaderDeviceInstanceIdW(
            context.0,
            reader_wide.as_ptr(),
            null_mut(),
            &mut characters,
        )
    };
    if result != 0 && result != SCARD_E_INSUFFICIENT_BUFFER {
        return Err(format!(
            "could not get PC/SC reader device instance ID (SCARD 0x{:08X})",
            result as u32
        ));
    }
    if characters == 0 {
        return Err("PC/SC reader returned an empty device instance ID".into());
    }
    let mut buffer = vec![0u16; characters as usize];
    // SAFETY: buffer has the character count returned by the size query.
    let result = unsafe {
        SCardGetReaderDeviceInstanceIdW(
            context.0,
            reader_wide.as_ptr(),
            buffer.as_mut_ptr(),
            &mut characters,
        )
    };
    if result != 0 {
        return Err(format!(
            "could not read PC/SC reader device instance ID (SCARD 0x{:08X})",
            result as u32
        ));
    }
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

fn device_interface_instance_id(path: &str) -> Option<String> {
    let interface_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut property_type = 0u32;
    let mut required_bytes = 0u32;
    // SAFETY: interface_path is NUL-terminated; null buffer queries the required size.
    let result = unsafe {
        CM_Get_Device_Interface_PropertyW(
            interface_path.as_ptr(),
            &DEVPKEY_Device_InstanceId,
            &mut property_type,
            null_mut(),
            &mut required_bytes,
            0,
        )
    };
    if result != CR_BUFFER_SMALL || required_bytes < size_of::<u16>() as u32 {
        return None;
    }
    let mut buffer = vec![0u16; (required_bytes as usize).div_ceil(size_of::<u16>())];
    let mut buffer_bytes = (buffer.len() * size_of::<u16>()) as u32;
    // SAFETY: buffer is aligned UTF-16 storage large enough for required_bytes.
    let result = unsafe {
        CM_Get_Device_Interface_PropertyW(
            interface_path.as_ptr(),
            &DEVPKEY_Device_InstanceId,
            &mut property_type,
            buffer.as_mut_ptr().cast::<u8>(),
            &mut buffer_bytes,
            0,
        )
    };
    if result != CR_SUCCESS || property_type != DEVPROP_TYPE_STRING {
        return None;
    }
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..length]))
}

fn usb_composite_parent_id(device_instance_id: &str) -> Option<String> {
    let device_id: Vec<u16> = device_instance_id
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut devnode = 0u32;
    // SAFETY: device_id is NUL-terminated and devnode is a writable output slot.
    if unsafe { CM_Locate_DevNodeW(&mut devnode, device_id.as_ptr(), CM_LOCATE_DEVNODE_NORMAL) }
        != CR_SUCCESS
    {
        return None;
    }
    for _ in 0..MAX_PARENT_DEPTH {
        let current_id = devnode_instance_id(devnode)?;
        if is_usb_composite_id(&current_id) {
            return Some(current_id);
        }
        let mut parent = 0u32;
        // SAFETY: devnode is a valid node and parent is a writable output slot.
        if unsafe { CM_Get_Parent(&mut parent, devnode, 0) } != CR_SUCCESS {
            return None;
        }
        devnode = parent;
    }
    None
}

fn devnode_instance_id(devnode: u32) -> Option<String> {
    let mut buffer = [0u16; MAX_DEVICE_ID_CHARS];
    // SAFETY: buffer is a writable UTF-16 buffer with a bounded capacity.
    if unsafe { CM_Get_Device_IDW(devnode, buffer.as_mut_ptr(), buffer.len() as u32, 0) }
        != CR_SUCCESS
    {
        return None;
    }
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..length]))
}

#[cfg(test)]
mod tests {
    use super::{is_usb_composite_id, same_usb_composite_parent};

    #[test]
    fn compares_usb_composite_parent_ids_not_interface_ids() {
        let reader_parent = r"USB\VID_1050&PID_0407\8&15CD6C09&0&6";
        let hid_parent = r"usb\vid_1050&pid_0407\8&15cd6c09&0&6";
        let reader_interface = r"USB\VID_1050&PID_0407&MI_02\9&124791D7&0&0002";
        let other_pid = r"USB\VID_1050&PID_0406\8&15CD6C09&0&6";

        assert!(is_usb_composite_id(reader_parent));
        assert!(same_usb_composite_parent(reader_parent, hid_parent));
        assert!(!is_usb_composite_id(reader_interface));
        assert!(!same_usb_composite_parent(reader_parent, reader_interface));
        assert!(!same_usb_composite_parent(reader_parent, other_pid));
    }
}
