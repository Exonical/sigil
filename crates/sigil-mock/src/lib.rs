//! Hardware-free fixture backend. Never use this for enrollment or issuance.

use std::sync::{
    Mutex,
    mpsc::{self, Receiver, Sender},
};

use sigil_core::{
    Application, CredentialError, DeviceDiscovery, DeviceEvent, DeviceId, DeviceInfo,
    FirmwareVersion, Result, Transport,
};

#[derive(Default)]
pub struct MockDiscovery {
    devices: Mutex<Vec<DeviceInfo>>,
    listeners: Mutex<Vec<Sender<DeviceEvent>>>,
}

impl MockDiscovery {
    pub fn with_example() -> Self {
        Self::with_devices(vec![DeviceInfo {
            id: DeviceId("mock-yubikey-12345678".into()),
            vendor: "Yubico (simulated)".into(),
            model: "YubiKey 5 NFC (simulated)".into(),
            serial: Some("12345678".into()),
            firmware: Some(FirmwareVersion {
                major: 5,
                minor: 7,
                patch: 1,
            }),
            form_factor: Some("Keychain (USB-A)".into()),
            transports: vec![
                Transport::UsbSmartCard,
                Transport::UsbHid,
                Transport::UsbOtp,
                Transport::Nfc,
            ],
            applications: vec![
                Application::Piv,
                Application::Fido2,
                Application::U2f,
                Application::Otp,
                Application::OpenPgp,
                Application::Oath,
            ],
            supported_applications: vec![
                Application::Piv,
                Application::Fido2,
                Application::U2f,
                Application::Otp,
                Application::OpenPgp,
                Application::Oath,
            ],
            simulated: true,
        }])
    }

    pub fn with_devices(devices: Vec<DeviceInfo>) -> Self {
        Self {
            devices: Mutex::new(devices),
            listeners: Mutex::new(Vec::new()),
        }
    }

    pub fn connect(&self, mut device: DeviceInfo) -> Result<()> {
        device.simulated = true;
        let event = {
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| CredentialError::InventoryUnavailable)?;
            if let Some(existing) = devices.iter_mut().find(|item| item.id == device.id) {
                *existing = device.clone();
                DeviceEvent::Updated(device)
            } else {
                devices.push(device.clone());
                DeviceEvent::Connected(device)
            }
        };
        self.publish(event)
    }

    pub fn disconnect(&self, id: &DeviceId) -> Result<()> {
        let removed = {
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| CredentialError::InventoryUnavailable)?;
            let len = devices.len();
            devices.retain(|device| &device.id != id);
            devices.len() != len
        };
        if removed {
            self.publish(DeviceEvent::Disconnected(id.clone()))?;
        }
        Ok(())
    }

    fn publish(&self, event: DeviceEvent) -> Result<()> {
        self.listeners
            .lock()
            .map_err(|_| CredentialError::InventoryUnavailable)?
            .retain(|listener| listener.send(event.clone()).is_ok());
        Ok(())
    }
}

impl DeviceDiscovery for MockDiscovery {
    fn list(&self) -> Result<Vec<DeviceInfo>> {
        Ok(self
            .devices
            .lock()
            .map_err(|_| CredentialError::InventoryUnavailable)?
            .clone())
    }

    fn subscribe(&self) -> Result<Receiver<DeviceEvent>> {
        let (sender, receiver) = mpsc::channel();
        self.listeners
            .lock()
            .map_err(|_| CredentialError::InventoryUnavailable)?
            .push(sender);
        Ok(receiver)
    }
}
