//! Future YubiKey-specific protocol provider. No hardware communication in M1.

use sigil_core::{Application, CredentialDevice, DeviceInfo, FidoDevice, PivDevice, Result};

pub mod management;

pub struct YubiKeyDevice {
    info: DeviceInfo,
}

impl YubiKeyDevice {
    pub fn from_discovery(info: DeviceInfo) -> Self {
        Self { info }
    }
}

impl CredentialDevice for YubiKeyDevice {
    fn info(&self) -> Result<DeviceInfo> {
        Ok(self.info.clone())
    }
}

impl PivDevice for YubiKeyDevice {
    fn piv_available(&self) -> Result<bool> {
        Ok(self.info.applications.contains(&Application::Piv))
    }
}

impl FidoDevice for YubiKeyDevice {
    fn fido2_available(&self) -> Result<bool> {
        Ok(self.info.applications.contains(&Application::Fido2))
    }
}
