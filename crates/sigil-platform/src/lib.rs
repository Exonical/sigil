//! Boundary for OS discovery and transport. Windows CCID discovery is native.

#[cfg(not(target_os = "windows"))]
use sigil_core::CredentialError;
use sigil_core::{
    Application, DeviceDiscovery, DeviceEvent, DeviceId, DeviceInfo, DeviceManagement,
    DiscoverableCredential, FidoInspection, FidoStatus, Fingerprint, FingerprintProgress,
    ManagedPivInitializationOutcome, ManagementKey, PivAttestation, PivCertificate, PivInfo,
    PivInspection, PivKeyConfiguration, PivManagement, PivPin, PivPuk, PivSlot, PivSlotInfo,
    Result, Secret,
};
use std::sync::mpsc::Receiver;
#[cfg(any(target_os = "windows", test))]
use std::sync::mpsc::Sender;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

pub struct NativeDiscovery;

#[cfg(target_os = "windows")]
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FidoHidResolution {
    pub hid_path: String,
    pub reader_composite_id: String,
    pub hid_composite_id: String,
}

#[cfg(target_os = "windows")]
impl NativeDiscovery {
    #[doc(hidden)]
    pub fn resolve_fido_hid_for_device(&self, id: &DeviceId) -> Result<Option<FidoHidResolution>> {
        windows::resolve_fido_hid_for_device(id)
    }

    #[doc(hidden)]
    pub fn piv_serial(&self, id: &DeviceId, expected_serial: &str) -> Result<String> {
        windows::piv::piv_serial(id, expected_serial)
    }
}

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
            "native device discovery is not implemented for this platform".into(),
        ))
    }

    fn subscribe(&self) -> Result<Receiver<DeviceEvent>> {
        #[cfg(target_os = "windows")]
        return windows::subscribe();

        #[cfg(not(target_os = "windows"))]
        Err(CredentialError::BackendUnavailable(
            "native device events are not implemented for this platform".into(),
        ))
    }
}

impl FidoInspection for NativeDiscovery {
    fn fingerprints(&self, id: &DeviceId, pin: &str) -> Result<Vec<Fingerprint>> {
        #[cfg(target_os = "windows")]
        return windows::fingerprints(id, pin);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, pin);
            Err(CredentialError::BackendUnavailable(
                "native fingerprint management is not implemented for this platform".into(),
            ))
        }
    }

    fn enroll_fingerprint(
        &self,
        id: &DeviceId,
        pin: &str,
        on_progress: &mut dyn FnMut(FingerprintProgress),
    ) -> Result<Fingerprint> {
        #[cfg(target_os = "windows")]
        return windows::enroll_fingerprint(id, pin, on_progress);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, pin, on_progress);
            Err(CredentialError::BackendUnavailable(
                "native fingerprint management is not implemented for this platform".into(),
            ))
        }
    }

    fn remove_fingerprint(&self, id: &DeviceId, pin: &str, fingerprint_id: &str) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::remove_fingerprint(id, pin, fingerprint_id);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, pin, fingerprint_id);
            Err(CredentialError::BackendUnavailable(
                "native fingerprint management is not implemented for this platform".into(),
            ))
        }
    }

    fn fido_status(&self, id: &DeviceId) -> Result<FidoStatus> {
        #[cfg(target_os = "windows")]
        return windows::fido_status(id);

        #[cfg(not(target_os = "windows"))]
        {
            let _ = id;
            Err(CredentialError::BackendUnavailable(
                "native FIDO inspection is not implemented for this platform".into(),
            ))
        }
    }

    fn discoverable_credentials(
        &self,
        id: &DeviceId,
        pin: &str,
    ) -> Result<Vec<DiscoverableCredential>> {
        #[cfg(target_os = "windows")]
        return windows::discoverable_credentials(id, pin);

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, pin);
            Err(CredentialError::BackendUnavailable(
                "native FIDO inspection is not implemented for this platform".into(),
            ))
        }
    }
}

impl PivInspection for NativeDiscovery {
    fn piv_info(&self, id: &DeviceId) -> Result<PivInfo> {
        #[cfg(target_os = "windows")]
        return windows::piv::piv_info(id);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = id;
            Err(CredentialError::BackendUnavailable(
                "native PIV inspection is not implemented for this platform".into(),
            ))
        }
    }

    fn piv_slots(&self, id: &DeviceId) -> Result<Vec<PivSlotInfo>> {
        #[cfg(target_os = "windows")]
        return windows::piv::piv_slots(id);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = id;
            Err(CredentialError::BackendUnavailable(
                "native PIV inspection is not implemented for this platform".into(),
            ))
        }
    }

    fn piv_certificate(&self, id: &DeviceId, slot: PivSlot) -> Result<Option<PivCertificate>> {
        #[cfg(target_os = "windows")]
        return windows::piv::piv_certificate(id, slot);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, slot);
            Err(CredentialError::BackendUnavailable(
                "native PIV inspection is not implemented for this platform".into(),
            ))
        }
    }
}

impl PivManagement for NativeDiscovery {
    fn change_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_pin: &PivPin,
        new_pin: &PivPin,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::piv::change_pin(id, expected_serial, old_pin, new_pin);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, old_pin, new_pin);
            Err(CredentialError::UnsupportedOperation(
                "native PIV mutations are not implemented on this platform".into(),
            ))
        }
    }

    fn change_puk(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_puk: &PivPuk,
        new_puk: &PivPuk,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::piv::change_puk(id, expected_serial, old_puk, new_puk);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, old_puk, new_puk);
            Err(CredentialError::UnsupportedOperation(
                "native PIV mutations are not implemented on this platform".into(),
            ))
        }
    }

    fn unblock_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        puk: &PivPuk,
        new_pin: &PivPin,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::piv::unblock_pin(id, expected_serial, puk, new_pin);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, puk, new_pin);
            Err(CredentialError::UnsupportedOperation(
                "native PIV mutations are not implemented on this platform".into(),
            ))
        }
    }

    fn change_management_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        current: &ManagementKey,
        new: &ManagementKey,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::piv::change_management_key(id, expected_serial, current, new);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, current, new);
            Err(CredentialError::UnsupportedOperation(
                "native PIV mutations are not implemented on this platform".into(),
            ))
        }
    }

    fn managed_initialize(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        new_management_key: &ManagementKey,
        new_puk: &PivPuk,
    ) -> Result<ManagedPivInitializationOutcome> {
        #[cfg(target_os = "windows")]
        return windows::piv::managed_initialize(id, expected_serial, new_management_key, new_puk);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, new_management_key, new_puk);
            Err(CredentialError::UnsupportedOperation(
                "native PIV mutations are not implemented on this platform".into(),
            ))
        }
    }

    fn generate_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        configuration: PivKeyConfiguration,
    ) -> Result<Vec<u8>> {
        #[cfg(target_os = "windows")]
        return windows::piv::generate_key(id, expected_serial, management_key, configuration);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, management_key, configuration);
            Err(CredentialError::UnsupportedOperation(
                "native PIV mutations are not implemented on this platform".into(),
            ))
        }
    }

    fn attest(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        slot: PivSlot,
    ) -> Result<PivAttestation> {
        #[cfg(target_os = "windows")]
        return windows::piv::attest(id, expected_serial, slot);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, slot);
            Err(CredentialError::UnsupportedOperation(
                "native PIV attestation is not implemented on this platform".into(),
            ))
        }
    }

    fn sign_csr(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        pin: &PivPin,
        slot: PivSlot,
        subject_dn: &str,
        expected_public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        #[cfg(target_os = "windows")]
        return windows::piv::sign_csr(
            id,
            expected_serial,
            pin,
            slot,
            subject_dn,
            expected_public_key,
        );
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (
                id,
                expected_serial,
                pin,
                slot,
                subject_dn,
                expected_public_key,
            );
            Err(CredentialError::UnsupportedOperation(
                "native PIV CSR signing is not implemented on this platform".into(),
            ))
        }
    }

    fn import_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
        certificate_der: &[u8],
        expected_public_key: Option<&[u8]>,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::piv::import_certificate(
            id,
            expected_serial,
            management_key,
            slot,
            certificate_der,
            expected_public_key,
        );
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (
                id,
                expected_serial,
                management_key,
                slot,
                certificate_der,
                expected_public_key,
            );
            Err(CredentialError::UnsupportedOperation(
                "native PIV mutations are not implemented on this platform".into(),
            ))
        }
    }

    fn delete_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::piv::delete_certificate(id, expected_serial, management_key, slot);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, management_key, slot);
            Err(CredentialError::UnsupportedOperation(
                "native PIV mutations are not implemented on this platform".into(),
            ))
        }
    }

    fn delete_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::piv::delete_key(id, expected_serial, management_key, slot);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, management_key, slot);
            Err(CredentialError::UnsupportedOperation(
                "native PIV mutations are not implemented on this platform".into(),
            ))
        }
    }

    fn reset(&self, id: &DeviceId, expected_serial: &str) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::piv::reset(id, expected_serial);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial);
            Err(CredentialError::UnsupportedOperation(
                "native PIV reset is not implemented on this platform".into(),
            ))
        }
    }
}

impl DeviceManagement for NativeDiscovery {
    fn set_enabled_applications(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        usb: &[Application],
        nfc: Option<&[Application]>,
        lock_code: Option<&Secret>,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        return windows::piv::set_enabled_applications(id, expected_serial, usb, nfc, lock_code);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (id, expected_serial, usb, nfc, lock_code);
            Err(CredentialError::UnsupportedOperation(
                "native application configuration is not implemented on this platform".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::{Application, DeviceId, FirmwareVersion, MetadataAccess, Transport};

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
            fips: None,
            connection: Some(Transport::UsbSmartCard),
            transports: vec![Transport::UsbSmartCard],
            applications: vec![Application::Piv],
            supported_applications: vec![Application::Piv],
            usb_enabled: vec![Application::Piv],
            usb_supported: vec![Application::Piv],
            nfc_enabled: Vec::new(),
            nfc_supported: Vec::new(),
            config_locked: Some(false),
            fips_approved: None,
            pin_complexity: None,
            simulated: false,
            metadata_access: MetadataAccess::Unknown,
            piv_capabilities: Some(sigil_core::PivCapabilities {
                piv_writes: true,
                key_metadata: true,
                pin_touch_policy: true,
                set_management_key: true,
                attestation: true,
                delete_key: true,
                reset: true,
                factory_initialize: true,
                p384_generation: true,
                retired_slot_generation: true,
            }),
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
