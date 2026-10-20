use sigil_core::{Application, DeviceInfo, KeyStatus, PivSlot, PivSlotInfo};

use crate::state::{ManagedAction, Page};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PivActionKind {
    GenerateKey,
    ImportCertificate,
    ExportCertificate,
    CreateCsr,
    Attest,
    DeleteCertificate,
    DeleteKey,
}

pub(crate) fn nav_pages(device: Option<&DeviceInfo>) -> Vec<Page> {
    let Some(device) = device else {
        return vec![Page::Home, Page::Settings];
    };
    let mut pages = vec![Page::Home];
    if device.applications.contains(&Application::Oath) {
        pages.push(Page::Accounts);
    }
    if device.applications.contains(&Application::Fido2) {
        pages.push(Page::Passkeys);
    }
    if device.applications.contains(&Application::Piv) {
        pages.push(Page::Certificates);
    }
    if device.applications.contains(&Application::Otp) {
        pages.push(Page::Slots);
    }
    pages.push(Page::Settings);
    pages
}

pub(crate) fn page_after_device_change(page: Page, device: Option<&DeviceInfo>) -> Page {
    if nav_pages(device).contains(&page) {
        page
    } else {
        Page::Home
    }
}

pub(crate) fn managed_action_allowed(device: &DeviceInfo, action: ManagedAction) -> bool {
    let capabilities = device.piv_capabilities.unwrap_or_default();
    match action {
        ManagedAction::Initialize => capabilities.factory_initialize,
        ManagedAction::RotatePuk | ManagedAction::UnblockPin => capabilities.piv_writes,
        ManagedAction::RotateManagementKey => capabilities.set_management_key,
    }
}

pub(crate) fn slot_actions(
    device: &DeviceInfo,
    slot: &PivSlotInfo,
    generated_spki_known: bool,
) -> Vec<PivActionKind> {
    let capabilities = device.piv_capabilities.unwrap_or_default();
    let is_attestation_slot = slot.slot == PivSlot::ATTESTATION;
    let is_retired = (0x82..=0x95).contains(&slot.slot.byte());
    let has_certificate = slot.certificate.is_some();
    let has_reported_key = matches!(&slot.key, KeyStatus::Present(_));
    let has_unknown_key = matches!(&slot.key, KeyStatus::Unknown);
    let can_sign =
        has_reported_key || (has_unknown_key && (has_certificate || generated_spki_known));
    let mut actions = Vec::new();

    if has_certificate {
        actions.push(PivActionKind::ExportCertificate);
    }
    if capabilities.piv_writes && !is_attestation_slot {
        if !is_retired || capabilities.retired_slot_generation {
            actions.push(PivActionKind::GenerateKey);
        }
        actions.push(PivActionKind::ImportCertificate);
        if has_certificate {
            actions.push(PivActionKind::DeleteCertificate);
        }
        if can_sign {
            actions.push(PivActionKind::CreateCsr);
        }
    }
    if capabilities.attestation && has_reported_key && !is_attestation_slot {
        actions.push(PivActionKind::Attest);
    }
    if capabilities.delete_key && has_reported_key && !is_attestation_slot {
        actions.push(PivActionKind::DeleteKey);
    }
    actions
}

#[cfg(test)]
mod tests {
    use sigil_core::{
        Application, DeviceId, KeyStatus, MetadataAccess, PivCapabilities, PivSlot, PivSlotInfo,
    };

    use super::*;

    fn device(
        vendor: &str,
        applications: Vec<Application>,
        capabilities: Option<PivCapabilities>,
    ) -> DeviceInfo {
        DeviceInfo {
            id: DeviceId(format!("test-{vendor}")),
            vendor: vendor.into(),
            model: vendor.into(),
            serial: None,
            firmware: None,
            form_factor: None,
            fips: None,
            usb_enabled: Vec::new(),
            usb_supported: Vec::new(),
            nfc_enabled: Vec::new(),
            nfc_supported: Vec::new(),
            config_locked: None,
            fips_approved: None,
            pin_complexity: None,
            connection: None,
            transports: Vec::new(),
            supported_applications: applications.clone(),
            applications,
            simulated: true,
            metadata_access: MetadataAccess::Unknown,
            piv_capabilities: capabilities,
        }
    }

    fn slot(key: KeyStatus, certificate: bool) -> PivSlotInfo {
        PivSlotInfo {
            slot: PivSlot::AUTHENTICATION,
            certificate: certificate.then(|| sigil_core::CertificateSummary {
                subject: "CN=test".into(),
                issuer: "CN=test-ca".into(),
                serial: "01".into(),
                not_before: "2025-01-01 00:00Z".into(),
                not_after: "2030-01-01 00:00Z".into(),
                public_key_algorithm: Some(sigil_core::PivAlgorithm::EccP256),
                sha256_fingerprint: "00".repeat(32),
            }),
            key,
        }
    }

    #[test]
    fn navigation_pages_follow_the_enabled_applications() {
        let yubikey = device(
            "Yubico",
            vec![
                Application::Piv,
                Application::Fido2,
                Application::Otp,
                Application::Oath,
            ],
            Some(PivCapabilities::default()),
        );
        assert_eq!(
            nav_pages(Some(&yubikey)),
            vec![
                Page::Home,
                Page::Accounts,
                Page::Passkeys,
                Page::Certificates,
                Page::Slots,
                Page::Settings,
            ]
        );

        let thales = device(
            "Thales",
            vec![Application::Piv],
            Some(PivCapabilities {
                piv_writes: true,
                ..PivCapabilities::default()
            }),
        );
        assert_eq!(
            nav_pages(Some(&thales)),
            vec![Page::Home, Page::Certificates, Page::Settings]
        );
        assert_eq!(
            page_after_device_change(Page::Passkeys, Some(&thales)),
            Page::Home
        );
        assert_eq!(nav_pages(None), vec![Page::Home, Page::Settings]);
    }

    #[test]
    fn yubi_and_thales_slot_actions_follow_capabilities_and_key_knowledge() {
        let yubikey = device(
            "Yubico",
            vec![Application::Piv],
            Some(PivCapabilities {
                piv_writes: true,
                key_metadata: true,
                pin_touch_policy: true,
                attestation: true,
                delete_key: true,
                p384_generation: true,
                retired_slot_generation: true,
                ..PivCapabilities::default()
            }),
        );
        let present = slot(
            KeyStatus::Present(sigil_core::PivKeyMetadata {
                algorithm: sigil_core::PivAlgorithm::EccP256,
                pin_policy: sigil_core::PinPolicy::Once,
                touch_policy: sigil_core::TouchPolicy::Default,
                origin: None,
            }),
            true,
        );
        let yubikey_actions = slot_actions(&yubikey, &present, false);
        assert!(yubikey_actions.contains(&PivActionKind::GenerateKey));
        assert!(yubikey_actions.contains(&PivActionKind::ImportCertificate));
        assert!(yubikey_actions.contains(&PivActionKind::CreateCsr));
        assert!(yubikey_actions.contains(&PivActionKind::Attest));
        assert!(yubikey_actions.contains(&PivActionKind::DeleteKey));

        let thales = device(
            "Thales",
            vec![Application::Piv],
            Some(PivCapabilities {
                piv_writes: true,
                ..PivCapabilities::default()
            }),
        );
        let unknown_empty = slot(KeyStatus::Unknown, false);
        let actions = slot_actions(&thales, &unknown_empty, false);
        assert!(actions.contains(&PivActionKind::GenerateKey));
        assert!(actions.contains(&PivActionKind::ImportCertificate));
        assert!(!actions.contains(&PivActionKind::CreateCsr));
        assert!(!actions.contains(&PivActionKind::Attest));
        assert!(!actions.contains(&PivActionKind::DeleteKey));

        assert!(
            slot_actions(&thales, &slot(KeyStatus::Unknown, true), false)
                .contains(&PivActionKind::CreateCsr)
        );
        assert!(slot_actions(&thales, &unknown_empty, true).contains(&PivActionKind::CreateCsr));
        let retired = PivSlotInfo {
            slot: PivSlot::retired(1).unwrap(),
            ..slot(KeyStatus::Unknown, true)
        };
        assert!(!slot_actions(&thales, &retired, false).contains(&PivActionKind::GenerateKey));
        assert!(slot_actions(&yubikey, &retired, false).contains(&PivActionKind::GenerateKey));
    }

    #[test]
    fn absent_capabilities_mean_read_only() {
        let token = device("Unknown vendor", vec![Application::Piv], None);
        let slot = slot(KeyStatus::Unknown, true);
        assert_eq!(
            slot_actions(&token, &slot, false),
            vec![PivActionKind::ExportCertificate]
        );
    }

    #[test]
    fn managed_actions_follow_device_capabilities() {
        let thales = device(
            "Thales",
            vec![Application::Piv],
            Some(PivCapabilities {
                piv_writes: true,
                ..PivCapabilities::default()
            }),
        );
        assert!(!managed_action_allowed(&thales, ManagedAction::Initialize));
        assert!(managed_action_allowed(&thales, ManagedAction::RotatePuk));
        assert!(!managed_action_allowed(
            &thales,
            ManagedAction::RotateManagementKey
        ));
    }
}
