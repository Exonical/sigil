//! Boundary for OS discovery and transport. Windows CCID discovery is native.

#[cfg(not(target_os = "windows"))]
use sigil_core::CredentialError;
use sigil_core::{DeviceDiscovery, DeviceEvent, DeviceInfo, Result};
use std::sync::mpsc::Receiver;
#[cfg(any(target_os = "windows", test))]
use std::sync::mpsc::Sender;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

pub struct NativeDiscovery;

/// Diff snapshots by opaque identity, including changes in reported metadata.
/// Used by the Windows watcher and exercised without smart-card hardware.
#[cfg(any(target_os = "windows", test))]
fn reconcile(
    previous: &mut Vec<DeviceInfo>,
    current: Vec<DeviceInfo>,
    sender: &Sender<DeviceEvent>,
) -> bool {
    for old in previous.iter() {
        if !current.iter().any(|item| item.id == old.id)
            && sender
                .send(DeviceEvent::Disconnected(old.id.clone()))
                .is_err()
        {
            return false;
        }
    }
    for device in &current {
        let event = match previous.iter().find(|old| old.id == device.id) {
            None => Some(DeviceEvent::Connected(device.clone())),
            Some(old) if old != device => Some(DeviceEvent::Updated(device.clone())),
            Some(_) => None,
        };
        if let Some(event) = event
            && sender.send(event).is_err()
        {
            return false;
        }
    }
    *previous = current;
    true
}

impl DeviceDiscovery for NativeDiscovery {
    fn list(&self) -> Result<Vec<DeviceInfo>> {
        #[cfg(target_os = "windows")]
        return windows::list();

        #[cfg(not(target_os = "windows"))]
        Err(CredentialError::BackendUnavailable(
            "native device discovery is not implemented for this platform",
        ))
    }

    fn subscribe(&self) -> Result<Receiver<DeviceEvent>> {
        #[cfg(target_os = "windows")]
        return windows::subscribe();

        #[cfg(not(target_os = "windows"))]
        Err(CredentialError::BackendUnavailable(
            "native device events are not implemented for this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{Application, DeviceId, FirmwareVersion, Transport};

    fn fixture(id: &str) -> DeviceInfo {
        DeviceInfo {
            id: DeviceId(id.into()),
            vendor: "Yubico".into(),
            model: "YubiKey".into(),
            serial: None,
            firmware: Some(FirmwareVersion {
                major: 5,
                minor: 7,
                patch: 1,
            }),
            form_factor: None,
            transports: vec![Transport::UsbSmartCard],
            applications: vec![Application::Piv],
            supported_applications: vec![Application::Piv],
            simulated: false,
        }
    }

    #[test]
    fn replacement_and_metadata_change_are_reconciled() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut previous = Vec::new();
        assert!(reconcile(
            &mut previous,
            vec![fixture("first"), fixture("second")],
            &sender
        ));
        assert!(matches!(receiver.try_recv(), Ok(DeviceEvent::Connected(_))));
        assert!(matches!(receiver.try_recv(), Ok(DeviceEvent::Connected(_))));
        let mut changed = fixture("second");
        changed.serial = Some("123".into());
        assert!(reconcile(
            &mut previous,
            vec![changed.clone(), fixture("third")],
            &sender
        ));
        assert_eq!(
            receiver.try_recv(),
            Ok(DeviceEvent::Disconnected(DeviceId("first".into())))
        );
        assert_eq!(receiver.try_recv(), Ok(DeviceEvent::Updated(changed)));
        assert!(matches!(receiver.try_recv(), Ok(DeviceEvent::Connected(_))));
        assert!(receiver.try_recv().is_err());
    }
}
