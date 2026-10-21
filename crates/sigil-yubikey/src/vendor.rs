//! YubiKey PIV: the vendor hooks for behaviour SP 800-73 does not define. Everything else comes from `sigil_piv::ops`.

use sigil_core::{
    CredentialError, DeviceInfo, KeyStatus, ManagementKey, ManagementKeyAlgorithm, PinPolicy,
    PivAlgorithm, PivAttestation, PivInfo, PivPuk, PivSlot, Result,
};
use sigil_piv::{
    CardTransport,
    vendor::{PivCapabilities, PivVendor},
};

use crate::piv;

/// The YubiKey PIV applet. Serial, metadata, attestation, key delete, reset, the management-key set command, and
/// the FIPS rules are YubiKey extensions.
pub struct YubiKeyPiv;

impl PivVendor for YubiKeyPiv {
    fn name(&self) -> &'static str {
        "Yubico"
    }

    fn capabilities(&self) -> PivCapabilities {
        PivCapabilities {
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
        }
    }

    fn verify_serial(&self, transport: &mut dyn CardTransport, expected: &str) -> Result<String> {
        piv::read_expected_serial(transport, expected)
    }

    fn info(&self, transport: &mut dyn CardTransport) -> Result<PivInfo> {
        piv::read_info(transport)
    }

    fn listed_slots(&self) -> Vec<PivSlot> {
        let mut slots = PivSlot::STANDARD.to_vec();
        slots.extend(PivSlot::retired_slots());
        slots.push(PivSlot::ATTESTATION);
        slots
    }

    fn slot_key_status(
        &self,
        transport: &mut dyn CardTransport,
        slot: PivSlot,
    ) -> Result<KeyStatus> {
        piv::slot_key_status(transport, slot)
    }

    fn slot_public_key(
        &self,
        transport: &mut dyn CardTransport,
        slot: PivSlot,
    ) -> Result<Option<Vec<u8>>> {
        piv::slot_public_key_spki(transport, slot).map(Some)
    }

    fn set_management_key(
        &self,
        transport: &mut dyn CardTransport,
        new_key: &ManagementKey,
    ) -> Result<()> {
        piv::set_management_key_selected(transport, new_key)
    }

    fn attest(&self, transport: &mut dyn CardTransport, slot: PivSlot) -> Result<PivAttestation> {
        piv::attest(transport, slot)
    }

    fn delete_key(&self, transport: &mut dyn CardTransport, slot: PivSlot) -> Result<()> {
        piv::delete_key_selected(transport, slot)
    }

    fn reset(&self, transport: &mut dyn CardTransport) -> Result<()> {
        piv::reset_piv(transport)
    }

    fn factory_management_key(&self, info: &PivInfo) -> Result<ManagementKey> {
        let status = info
            .management_key
            .as_ref()
            .ok_or(CredentialError::PivNotFactoryDefault)?;
        factory_default_management_key(status.algorithm)
    }

    fn factory_puk(&self) -> Result<PivPuk> {
        PivPuk::new(b"12345678".to_vec())
    }

    fn is_factory_default(&self, info: &PivInfo) -> bool {
        info.puk
            .as_ref()
            .is_some_and(|status| status.default_value == Some(true))
            && info
                .management_key
                .as_ref()
                .is_some_and(|status| status.default_value == Some(true))
    }

    fn validate_new_code(&self, device: &DeviceInfo, code: &[u8]) -> Result<()> {
        if device.fips.unwrap_or(false) && code.len() < 8 {
            return Err(CredentialError::PivFipsNotApproved);
        }
        Ok(())
    }

    fn validate_pin_policy(&self, device: &DeviceInfo, policy: PinPolicy) -> Result<()> {
        if device.fips.unwrap_or(false) && policy == PinPolicy::Never {
            return Err(CredentialError::PivFipsNotApproved);
        }
        Ok(())
    }

    fn map_error(&self, device: &DeviceInfo, error: CredentialError) -> CredentialError {
        match error {
            CredentialError::CardStatus(0x6985) if device.fips.unwrap_or(false) => {
                CredentialError::PivFipsNotApproved
            }
            other => other,
        }
    }
}

fn factory_default_management_key(algorithm: PivAlgorithm) -> Result<ManagementKey> {
    let (algorithm, copies) = match algorithm {
        PivAlgorithm::Aes128 => (ManagementKeyAlgorithm::Aes128, 2),
        PivAlgorithm::Aes192 => (ManagementKeyAlgorithm::Aes192, 3),
        PivAlgorithm::Aes256 => (ManagementKeyAlgorithm::Aes256, 4),
        _ => return Err(CredentialError::PivNotFactoryDefault),
    };
    let key = [1, 2, 3, 4, 5, 6, 7, 8]
        .into_iter()
        .cycle()
        .take(copies * 8)
        .collect();
    ManagementKey::new(algorithm, key)
}

#[cfg(test)]
mod tests {
    use sigil_core::{DeviceId, MetadataAccess, PinPolicy, PivAlgorithm, PivPuk};

    use super::*;

    fn device(fips: Option<bool>) -> DeviceInfo {
        DeviceInfo {
            id: DeviceId("test".into()),
            vendor: "Yubico".into(),
            model: "YubiKey".into(),
            serial: None,
            firmware: None,
            form_factor: None,
            fips,
            usb_enabled: Vec::new(),
            usb_supported: Vec::new(),
            nfc_enabled: Vec::new(),
            nfc_supported: Vec::new(),
            config_locked: None,
            fips_approved: None,
            pin_complexity: None,
            connection: None,
            transports: Vec::new(),
            applications: Vec::new(),
            supported_applications: Vec::new(),
            simulated: false,
            metadata_access: MetadataAccess::Unknown,
            piv_capabilities: Some(YubiKeyPiv.capabilities()),
        }
    }

    #[test]
    fn yubikey_piv_declares_every_capability() {
        let capabilities = YubiKeyPiv.capabilities();
        assert_eq!(YubiKeyPiv.name(), "Yubico");
        assert!(
            capabilities.piv_writes
                && capabilities.key_metadata
                && capabilities.pin_touch_policy
                && capabilities.set_management_key
                && capabilities.attestation
                && capabilities.delete_key
                && capabilities.reset
                && capabilities.factory_initialize
                && capabilities.p384_generation
                && capabilities.retired_slot_generation
        );
    }

    #[test]
    fn fips_requires_eight_character_codes_and_a_pin_policy() {
        let fips = device(Some(true));
        assert_eq!(
            YubiKeyPiv.validate_new_code(&fips, b"1234567"),
            Err(CredentialError::PivFipsNotApproved)
        );
        assert_eq!(YubiKeyPiv.validate_new_code(&fips, b"12345678"), Ok(()));
        assert_eq!(
            YubiKeyPiv.validate_new_code(&device(Some(false)), b"123456"),
            Ok(())
        );
        assert_eq!(
            YubiKeyPiv.validate_pin_policy(&fips, PinPolicy::Never),
            Err(CredentialError::PivFipsNotApproved)
        );
        assert_eq!(
            YubiKeyPiv.validate_pin_policy(&fips, PinPolicy::Once),
            Ok(())
        );
        assert_eq!(
            YubiKeyPiv.validate_pin_policy(&device(Some(false)), PinPolicy::Never),
            Ok(())
        );
    }

    #[test]
    fn fips_maps_conditions_of_use_to_initialization_error_only_for_fips_devices() {
        assert_eq!(
            YubiKeyPiv.map_error(&device(Some(true)), CredentialError::CardStatus(0x6985)),
            CredentialError::PivFipsNotApproved
        );
        assert_eq!(
            YubiKeyPiv.map_error(&device(Some(false)), CredentialError::CardStatus(0x6985)),
            CredentialError::CardStatus(0x6985)
        );
    }

    #[test]
    fn factory_defaults_follow_the_management_key_algorithm() {
        let key = factory_default_management_key(PivAlgorithm::Aes256).unwrap();
        assert_eq!(key.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8].repeat(4)[..]);
        assert_eq!(
            YubiKeyPiv.factory_puk().unwrap(),
            PivPuk::new(b"12345678".to_vec()).unwrap()
        );
        assert!(factory_default_management_key(PivAlgorithm::EccP256).is_err());
    }
}
