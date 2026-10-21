use sigil_core::{Application, DeviceDiscovery, DeviceManagement};
use sigil_platform::NativeDiscovery;

const AUTHORIZED_SERIAL: &str = "39192733";

struct RestoreConfiguration<'a> {
    native: &'a NativeDiscovery,
    device_id: sigil_core::DeviceId,
    serial: String,
    usb: Vec<Application>,
    nfc: Vec<Application>,
    armed: bool,
}

impl Drop for RestoreConfiguration<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.native.set_enabled_applications(
                &self.device_id,
                &self.serial,
                &self.usb,
                Some(&self.nfc),
                None,
            );
        }
    }
}

#[test]
fn authorized_management_write_restores_nfc_openpgp() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("SIGIL_HARDWARE_TESTS").as_deref() != Ok("1")
        || std::env::var("SIGIL_HARDWARE_MUTATION_SERIAL").as_deref() != Ok(AUTHORIZED_SERIAL)
    {
        return Ok(());
    }

    let native = NativeDiscovery;
    let device = native
        .list()?
        .into_iter()
        .find(|device| device.serial.as_deref() == Some(AUTHORIZED_SERIAL))
        .ok_or("authorized hardware serial is not connected")?;
    if device.config_locked == Some(true) {
        eprintln!("configuration is locked; application-toggle hardware test skipped");
        return Ok(());
    }
    if !device.nfc_enabled.contains(&Application::OpenPgp) {
        eprintln!("NFC OpenPGP is not enabled; application-toggle hardware test skipped");
        return Ok(());
    }

    let serial = device
        .serial
        .clone()
        .ok_or("device serial is unavailable")?;
    let mut restore = RestoreConfiguration {
        native: &native,
        device_id: device.id.clone(),
        serial: serial.clone(),
        usb: device.usb_enabled.clone(),
        nfc: device.nfc_enabled.clone(),
        armed: false,
    };
    let disabled_nfc = device
        .nfc_enabled
        .iter()
        .filter(|application| **application != Application::OpenPgp)
        .cloned()
        .collect::<Vec<_>>();
    native.set_enabled_applications(
        &device.id,
        &serial,
        &device.usb_enabled,
        Some(&disabled_nfc),
        None,
    )?;
    restore.armed = true;
    native.set_enabled_applications(
        &device.id,
        &serial,
        &device.usb_enabled,
        Some(&device.nfc_enabled),
        None,
    )?;
    restore.armed = false;

    let restored = native
        .list()?
        .into_iter()
        .find(|current| current.id == device.id)
        .ok_or("device disappeared after restoring applications")?;
    assert!(restored.nfc_enabled.contains(&Application::OpenPgp));
    Ok(())
}
