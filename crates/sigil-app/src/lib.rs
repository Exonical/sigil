//! Shared application service used by CLI and desktop UI.

use std::sync::{Arc, mpsc::Receiver};

use sigil_core::{
    CertificateFormat, CredentialError, DeviceDiscovery, DeviceEvent, DeviceId, DeviceInfo,
    DiscoverableCredential, FidoStatus, Fingerprint, FingerprintProgress, ManagementKey,
    PivAttestation, PivCertificate, PivInfo, PivKeyConfiguration, PivManagement, PivPin, PivPuk,
    PivSlot, PivSlotInfo, Result,
};

#[derive(Clone)]
pub struct CredentialService {
    discovery: Arc<dyn DeviceDiscovery>,
    piv_management: Option<Arc<dyn PivManagement>>,
}

impl CredentialService {
    pub fn new(discovery: Arc<dyn DeviceDiscovery>) -> Self {
        Self {
            discovery,
            piv_management: None,
        }
    }

    pub fn new_with_piv_management(
        discovery: Arc<dyn DeviceDiscovery>,
        piv_management: Arc<dyn PivManagement>,
    ) -> Self {
        Self {
            discovery,
            piv_management: Some(piv_management),
        }
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

    pub fn fingerprints(&self, id: &DeviceId, pin: &str) -> Result<Vec<Fingerprint>> {
        self.discovery.fingerprints(id, pin)
    }

    pub fn enroll_fingerprint(
        &self,
        id: &DeviceId,
        pin: &str,
        on_progress: &mut dyn FnMut(FingerprintProgress),
    ) -> Result<Fingerprint> {
        self.discovery.enroll_fingerprint(id, pin, on_progress)
    }

    pub fn remove_fingerprint(&self, id: &DeviceId, pin: &str, fingerprint_id: &str) -> Result<()> {
        self.discovery.remove_fingerprint(id, pin, fingerprint_id)
    }

    pub fn piv_info(&self, id: &DeviceId) -> Result<PivInfo> {
        self.discovery.piv_info(id)
    }

    pub fn piv_slots(&self, id: &DeviceId) -> Result<Vec<PivSlotInfo>> {
        self.discovery.piv_slots(id)
    }

    pub fn piv_certificate(&self, id: &DeviceId, slot: PivSlot) -> Result<Option<PivCertificate>> {
        self.discovery.piv_certificate(id, slot)
    }

    pub fn export_certificate(
        &self,
        id: &DeviceId,
        slot: PivSlot,
        format: CertificateFormat,
    ) -> Result<Vec<u8>> {
        let certificate = self
            .piv_certificate(id, slot)?
            .ok_or_else(|| CredentialError::CertificateNotFound(slot.to_string()))?;
        Ok(sigil_piv::encode_certificate(&certificate.der, format))
    }

    pub fn change_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_pin: &PivPin,
        new_pin: &PivPin,
    ) -> Result<()> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .change_pin(id, expected_serial, old_pin, new_pin)
    }

    pub fn change_puk(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_puk: &PivPuk,
        new_puk: &PivPuk,
    ) -> Result<()> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .change_puk(id, expected_serial, old_puk, new_puk)
    }

    pub fn unblock_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        puk: &PivPuk,
        new_pin: &PivPin,
    ) -> Result<()> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .unblock_pin(id, expected_serial, puk, new_pin)
    }

    pub fn change_management_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        current: &ManagementKey,
        new: &ManagementKey,
    ) -> Result<()> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .change_management_key(id, expected_serial, current, new)
    }

    pub fn generate_management_key(
        algorithm: sigil_core::ManagementKeyAlgorithm,
    ) -> Result<ManagementKey> {
        let mut key = zeroize::Zeroizing::new(vec![0u8; algorithm.key_len()]);
        getrandom::fill(key.as_mut_slice()).map_err(|_| {
            CredentialError::BackendUnavailable("OS random source unavailable".into())
        })?;
        ManagementKey::new(algorithm, std::mem::take(&mut *key))
    }

    pub fn generate_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        configuration: PivKeyConfiguration,
    ) -> Result<Vec<u8>> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .generate_key(id, expected_serial, management_key, configuration)
    }

    pub fn attest(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        slot: PivSlot,
    ) -> Result<PivAttestation> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .attest(id, expected_serial, slot)
    }

    pub fn sign_csr(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        pin: &PivPin,
        slot: PivSlot,
        subject_dn: &str,
    ) -> Result<Vec<u8>> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .sign_csr(id, expected_serial, pin, slot, subject_dn)
    }

    pub fn import_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
        certificate_der: &[u8],
    ) -> Result<()> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .import_certificate(id, expected_serial, management_key, slot, certificate_der)
    }

    pub fn delete_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .delete_certificate(id, expected_serial, management_key, slot)
    }

    pub fn delete_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .delete_key(id, expected_serial, management_key, slot)
    }

    pub fn reset(&self, id: &DeviceId, expected_serial: &str) -> Result<()> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .reset(id, expected_serial)
    }
}
