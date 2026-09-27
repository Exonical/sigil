//! Shared application service used by CLI and desktop UI.

use std::sync::{Arc, mpsc::Receiver};

use sigil_core::{
    CredentialError, DeviceDiscovery, DeviceEvent, DeviceId, DeviceInfo, DiscoverableCredential,
    FidoStatus, Result,
};

#[derive(Clone)]
pub struct CredentialService {
    discovery: Arc<dyn DeviceDiscovery>,
}

impl CredentialService {
    pub fn new(discovery: Arc<dyn DeviceDiscovery>) -> Self {
        Self { discovery }
    }

    pub fn devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut devices = self.discovery.list()?;
        devices.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        tracing::debug!(count = devices.len(), "device inventory retrieved");
        Ok(devices)
    }

    pub fn device(&self, id: &DeviceId) -> Result<DeviceInfo> {
        self.devices()?
            .into_iter()
            .find(|device| device.id == *id)
            .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))
    }

    pub fn watch_devices(&self) -> Result<Receiver<DeviceEvent>> {
        self.discovery.subscribe()
    }

    pub fn fido_status(&self, id: &DeviceId) -> Result<FidoStatus> {
        self.discovery.fido_status(id)
    }

    pub fn discoverable_credentials(
        &self,
        id: &DeviceId,
        pin: &str,
    ) -> Result<Vec<DiscoverableCredential>> {
        self.discovery.discoverable_credentials(id, pin)
    }
}
