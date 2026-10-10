//! Shared application service used by CLI and desktop UI.

use std::sync::{Arc, mpsc::Receiver};

use sigil_core::{
    CertificateFormat, CredentialError, DeviceDiscovery, DeviceEvent, DeviceId, DeviceInfo,
    DeviceManagement, DiscoverableCredential, FidoStatus, Fingerprint, FingerprintProgress,
    ManagedPivInitializationOutcome, ManagementKey, PivAttestation, PivCertificate, PivInfo,
    PivKeyConfiguration, PivManagement, PivPin, PivPuk, PivSlot, PivSlotInfo, Result, Secret,
};

#[derive(Clone)]
pub struct CredentialService {
    discovery: Arc<dyn DeviceDiscovery>,
    piv_management: Option<Arc<dyn PivManagement>>,
    device_management: Option<Arc<dyn DeviceManagement>>,
}

impl CredentialService {
    pub fn new(discovery: Arc<dyn DeviceDiscovery>) -> Self {
        Self {
            discovery,
            piv_management: None,
            device_management: None,
        }
    }

    pub fn new_with_piv_management(
        discovery: Arc<dyn DeviceDiscovery>,
        piv_management: Arc<dyn PivManagement>,
    ) -> Self {
        Self {
            discovery,
            piv_management: Some(piv_management),
            device_management: None,
        }
    }

    pub fn new_with_device_management(
        discovery: Arc<dyn DeviceDiscovery>,
        piv_management: Arc<dyn PivManagement>,
        device_management: Arc<dyn DeviceManagement>,
    ) -> Self {
        Self {
            discovery,
            piv_management: Some(piv_management),
            device_management: Some(device_management),
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

    pub fn set_enabled_applications(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        usb: &[sigil_core::Application],
        nfc: Option<&[sigil_core::Application]>,
        lock_code: Option<&Secret>,
    ) -> Result<()> {
        let device = self.device(id)?;
        validate_enabled_applications(&device, usb, nfc, lock_code)?;
        self.device_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "application configuration is unavailable through this credential service"
                        .into(),
                )
            })?
            .set_enabled_applications(id, expected_serial, usb, nfc, lock_code)
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

    pub fn managed_initialize(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        new_management_key: &ManagementKey,
        new_puk: &PivPuk,
    ) -> Result<ManagedPivInitializationOutcome> {
        self.piv_management
            .as_ref()
            .ok_or_else(|| {
                CredentialError::UnsupportedOperation(
                    "PIV mutation is unavailable through this credential service".into(),
                )
            })?
            .managed_initialize(id, expected_serial, new_management_key, new_puk)
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

fn validate_enabled_applications(
    device: &DeviceInfo,
    usb: &[sigil_core::Application],
    nfc: Option<&[sigil_core::Application]>,
    lock_code: Option<&Secret>,
) -> Result<()> {
    use sigil_core::Application;

    if usb.is_empty() {
        return Err(CredentialError::SmartCardOperation(
            "at least one USB application must remain enabled".into(),
        ));
    }
    if !usb.iter().any(|application| {
        matches!(
            application,
            Application::Piv | Application::Oath | Application::OpenPgp | Application::YubiHsmAuth
        )
    }) {
        return Err(CredentialError::SmartCardOperation(
            "keep PIV, OATH, OpenPGP, or YubiHSM Auth enabled over USB so Sigil can still reach the key"
                .into(),
        ));
    }
    if usb
        .iter()
        .any(|application| !device.usb_supported.contains(application))
    {
        return Err(CredentialError::SmartCardOperation(
            "an unsupported USB application cannot be enabled".into(),
        ));
    }
    if let Some(nfc) = nfc
        && nfc
            .iter()
            .any(|application| !device.nfc_supported.contains(application))
    {
        return Err(CredentialError::SmartCardOperation(
            "an unsupported NFC application cannot be enabled".into(),
        ));
    }
    if device.config_locked == Some(true) && lock_code.is_none() {
        return Err(CredentialError::SmartCardOperation(
            "the YubiKey configuration lock code is required".into(),
        ));
    }
    if lock_code.is_some_and(|code| code.expose().len() != 16) {
        return Err(CredentialError::SmartCardOperation(
            "configuration lock code must be 16 bytes (32 hexadecimal characters)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod device_management_tests {
    use super::*;
    use sigil_core::{Application, FirmwareVersion, MetadataAccess, Transport};

    fn device(config_locked: Option<bool>) -> DeviceInfo {
        let supported = vec![
            Application::Piv,
            Application::Fido2,
            Application::Otp,
            Application::OpenPgp,
            Application::Oath,
            Application::YubiHsmAuth,
        ];
        DeviceInfo {
            id: DeviceId("mock-device".into()),
            vendor: "Yubico".into(),
            model: "YubiKey".into(),
            serial: Some("12345678".into()),
            firmware: Some(FirmwareVersion {
                major: 5,
                minor: 7,
                patch: 4,
            }),
            form_factor: Some("USB-C".into()),
            fips: None,
            connection: Some(Transport::UsbSmartCard),
            transports: vec![Transport::UsbSmartCard, Transport::Nfc],
            applications: supported.clone(),
            supported_applications: supported.clone(),
            usb_enabled: supported.clone(),
            usb_supported: supported.clone(),
            nfc_enabled: supported.clone(),
            nfc_supported: supported,
            config_locked,
            fips_approved: None,
            pin_complexity: None,
            simulated: true,
            metadata_access: MetadataAccess::Available,
        }
    }

    fn error_text(result: Result<()>) -> String {
        match result {
            Ok(()) => panic!("configuration unexpectedly passed validation"),
            Err(CredentialError::SmartCardOperation(message)) => message,
            Err(error) => panic!("unexpected validation error: {error}"),
        }
    }

    #[test]
    fn configuration_requires_a_usb_application_and_a_sigil_access_path() {
        let device = device(Some(false));
        assert!(
            error_text(validate_enabled_applications(&device, &[], None, None))
                .contains("at least one USB application")
        );
        assert!(
            error_text(validate_enabled_applications(
                &device,
                &[Application::Fido2, Application::Otp],
                None,
                None,
            ))
            .contains("keep PIV, OATH, OpenPGP, or YubiHSM Auth enabled over USB")
        );
    }

    #[test]
    fn configuration_only_enables_supported_applications() {
        let mut device = device(Some(false));
        device.usb_supported = vec![Application::Piv];
        assert!(
            error_text(validate_enabled_applications(
                &device,
                &[Application::Piv, Application::Fido2],
                None,
                None,
            ))
            .contains("unsupported USB")
        );

        device.usb_supported = vec![Application::Piv];
        device.nfc_supported = vec![Application::Piv];
        assert!(
            error_text(validate_enabled_applications(
                &device,
                &[Application::Piv],
                Some(&[Application::Oath]),
                None,
            ))
            .contains("unsupported NFC")
        );
    }

    #[test]
    fn locked_configuration_requires_a_sixteen_byte_lock_code() {
        let device = device(Some(true));
        assert!(
            error_text(validate_enabled_applications(
                &device,
                &[Application::Piv],
                None,
                None,
            ))
            .contains("configuration lock code is required")
        );

        let short = Secret::new(vec![0x5a; 15]);
        assert!(
            error_text(validate_enabled_applications(
                &device,
                &[Application::Piv],
                None,
                Some(&short),
            ))
            .contains("16 bytes (32 hexadecimal characters)")
        );
    }

    #[test]
    fn valid_configuration_passes_safety_validation() {
        let device = device(Some(true));
        let code = Secret::new(vec![0x5a; 16]);
        assert!(
            validate_enabled_applications(
                &device,
                &[Application::Piv, Application::Fido2],
                Some(&[Application::Oath]),
                Some(&code),
            )
            .is_ok()
        );
    }
}
