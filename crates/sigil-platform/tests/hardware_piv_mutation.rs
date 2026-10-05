#![cfg(target_os = "windows")]

use std::{str::FromStr, time::Duration};

use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use sigil_core::{
    CredentialError, DeviceDiscovery, KeyStatus, ManagementKey, ManagementKeyAlgorithm, PinPolicy,
    PivAlgorithm, PivInspection, PivKeyAlgorithm, PivKeyConfiguration, PivManagement, PivPin,
    PivPuk, PivSlot, TouchPolicy,
};
use sigil_platform::NativeDiscovery;
use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    certificate::TbsCertificate,
    der::{Decode, Encode},
    ext::Extension,
    name::Name,
    serial_number::SerialNumber,
    spki::{SubjectPublicKeyInfo, SubjectPublicKeyInfoRef},
    time::Validity,
};

struct ResetGuard {
    discovery: NativeDiscovery,
    id: sigil_core::DeviceId,
    serial: String,
    armed: bool,
}

impl ResetGuard {
    fn arm(discovery: NativeDiscovery, id: sigil_core::DeviceId, serial: String) -> Self {
        Self {
            discovery,
            id,
            serial,
            armed: true,
        }
    }

    fn restore_and_verify(&mut self) -> sigil_core::Result<()> {
        self.discovery.reset(&self.id, &self.serial)?;
        verify_factory_defaults(&self.discovery, &self.id, &self.serial)?;
        println!("reset_verified=true");
        self.armed = false;
        Ok(())
    }
}

impl Drop for ResetGuard {
    fn drop(&mut self) {
        if self.armed {
            let reset_verified = self
                .discovery
                .reset(&self.id, &self.serial)
                .and_then(|()| verify_factory_defaults(&self.discovery, &self.id, &self.serial))
                .is_ok();
            println!("reset_verified={reset_verified}");
        }
    }
}

#[test]
fn authorized_piv_mutation_restores_factory_defaults() {
    if std::env::var("SIGIL_HARDWARE_TESTS").as_deref() != Ok("1") {
        return;
    }
    let serial = std::env::var("SIGIL_HARDWARE_MUTATION_SERIAL")
        .expect("set SIGIL_HARDWARE_MUTATION_SERIAL to the authorized test serial");
    assert_eq!(
        serial, "39192733",
        "refusing to mutate an unapproved serial"
    );
    let discovery = NativeDiscovery;
    let matches = discovery
        .list()
        .expect("native device inventory")
        .into_iter()
        .filter(|device| {
            device.id.0.starts_with("windows-pcsc:")
                && device.serial.as_deref() == Some(serial.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "the authorized serial must identify one reader"
    );
    let device = matches
        .into_iter()
        .next()
        .expect("one serial-matched device");
    println!("serial={serial}");
    assert_factory_defaults(&discovery, &device.id, &serial);
    let preflight_slots = discovery
        .piv_slots(&device.id)
        .expect("PIV preflight slots");
    for slot in PivSlot::STANDARD {
        let info = preflight_slots
            .iter()
            .find(|info| info.slot == slot)
            .unwrap_or_else(|| panic!("PIV preflight omitted slot {slot}"));
        assert_eq!(info.key, KeyStatus::Absent);
        assert!(info.certificate.is_none());
    }
    assert!(
        discovery
            .piv_certificate(&device.id, PivSlot::ATTESTATION)
            .expect("read F9 certificate")
            .is_some(),
        "factory attestation certificate must be present"
    );

    let mut guard = ResetGuard::arm(discovery, device.id.clone(), serial.clone());

    let initial_pin = PivPin::new(b"123456".to_vec()).expect("factory PIN");
    let pin1 = PivPin::new(random_code()).expect("random P1");
    let pin2 = PivPin::new(random_code()).expect("random P2");
    let pin3 = PivPin::new(random_code()).expect("random P3");
    println!("operation=change_pin slot=none");
    guard
        .discovery
        .change_pin(&device.id, &serial, &initial_pin, &pin1)
        .expect("change PIN to P1");

    let wrong_pin = PivPin::new(random_code()).expect("random incorrect PIN");
    assert_eq!(
        guard
            .discovery
            .change_pin(&device.id, &serial, &wrong_pin, &pin2),
        Err(CredentialError::PinIncorrect { remaining: 2 })
    );
    println!("operation=wrong_pin remaining=2");

    println!("operation=change_pin slot=none");
    guard
        .discovery
        .change_pin(&device.id, &serial, &pin1, &pin2)
        .expect("change PIN P1 to P2");

    let default_puk = PivPuk::new(b"12345678".to_vec()).expect("factory PUK");
    let puk1 = PivPuk::new(random_code()).expect("random K1");
    println!("operation=change_puk slot=none");
    guard
        .discovery
        .change_puk(&device.id, &serial, &default_puk, &puk1)
        .expect("change PUK to K1");
    println!("operation=unblock_pin slot=none");
    guard
        .discovery
        .unblock_pin(&device.id, &serial, &puk1, &pin3)
        .expect("unblock PIN with K1 and set P3");

    let default_key = ManagementKey::new(
        ManagementKeyAlgorithm::Aes192,
        [
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        ]
        .to_vec(),
    )
    .expect("factory management key");
    let mut random_key = vec![0; ManagementKeyAlgorithm::Aes256.key_len()];
    getrandom::fill(&mut random_key).expect("OS random source");
    let key1 = ManagementKey::new(ManagementKeyAlgorithm::Aes256, random_key)
        .expect("random AES-256 management key");
    println!("operation=change_management_key slot=none");
    guard
        .discovery
        .change_management_key(&device.id, &serial, &default_key, &key1)
        .expect("change management key");
    assert_eq!(
        guard
            .discovery
            .change_management_key(&device.id, &serial, &default_key, &default_key),
        Err(CredentialError::ManagementKeyIncorrect)
    );

    println!("operation=generate_key slot=9a");
    let public_spki = guard
        .discovery
        .generate_key(
            &device.id,
            &serial,
            &key1,
            PivKeyConfiguration {
                slot: PivSlot::AUTHENTICATION,
                algorithm: PivKeyAlgorithm::EccP256,
                pin_policy: PinPolicy::Once,
                touch_policy: TouchPolicy::Never,
            },
        )
        .expect("generate P-256 key");
    println!("operation=attest slot=9a");
    let attestation = guard
        .discovery
        .attest(&device.id, &serial, PivSlot::AUTHENTICATION)
        .expect("attest generated key");
    sigil_yubikey::piv::verify_attestation(
        &attestation.attestation_der,
        &attestation.intermediate_der,
        &public_spki,
        &serial,
        PivSlot::AUTHENTICATION,
        PinPolicy::Once,
        TouchPolicy::Never,
    )
    .expect("verify YubiKey attestation");

    println!("operation=sign_csr slot=9a");
    let csr = guard
        .discovery
        .sign_csr(
            &device.id,
            &serial,
            &pin3,
            PivSlot::AUTHENTICATION,
            "CN=Sigil hardware mutation test",
        )
        .expect("sign CSR with card");
    sigil_piv::management::verify_csr(&csr).expect("verify card-signed CSR");

    let certificate = issue_certificate(&public_spki, 42);
    println!("operation=import_certificate slot=9a");
    guard
        .discovery
        .import_certificate(
            &device.id,
            &serial,
            &key1,
            PivSlot::AUTHENTICATION,
            &certificate,
        )
        .expect("import certificate matching slot key");
    assert_eq!(
        guard
            .discovery
            .piv_certificate(&device.id, PivSlot::AUTHENTICATION)
            .expect("read imported certificate")
            .expect("certificate present")
            .der,
        certificate
    );
    let alternate_spki = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into())
        .expect("alternate test key")
        .verifying_key()
        .to_public_key_der()
        .expect("alternate SPKI");
    let wrong_certificate = issue_certificate(alternate_spki.as_bytes(), 43);
    assert_eq!(
        guard.discovery.import_certificate(
            &device.id,
            &serial,
            &key1,
            PivSlot::AUTHENTICATION,
            &wrong_certificate,
        ),
        Err(CredentialError::DeviceMismatch)
    );
    println!("operation=delete_certificate slot=9a");
    guard
        .discovery
        .delete_certificate(&device.id, &serial, &key1, PivSlot::AUTHENTICATION)
        .expect("delete certificate");
    assert!(
        guard
            .discovery
            .piv_certificate(&device.id, PivSlot::AUTHENTICATION)
            .expect("read deleted certificate")
            .is_none()
    );
    println!("operation=delete_key slot=9a");
    guard
        .discovery
        .delete_key(&device.id, &serial, &key1, PivSlot::AUTHENTICATION)
        .expect("delete generated key");
    assert!(matches!(
        guard
            .discovery
            .piv_slots(&device.id)
            .expect("read deleted key slot")
            .into_iter()
            .find(|entry| entry.slot == PivSlot::AUTHENTICATION)
            .map(|entry| entry.key),
        Some(KeyStatus::Absent)
    ));

    println!("operation=reset slot=none");
    guard
        .restore_and_verify()
        .expect("reset and verify factory defaults");
}

fn assert_factory_defaults(discovery: &NativeDiscovery, id: &sigil_core::DeviceId, serial: &str) {
    verify_factory_defaults(discovery, id, serial).expect("PIV factory defaults");
}

fn verify_factory_defaults(
    discovery: &NativeDiscovery,
    id: &sigil_core::DeviceId,
    serial: &str,
) -> sigil_core::Result<()> {
    let device = discovery
        .list()?
        .into_iter()
        .find(|device| device.id == *id)
        .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))?;
    if device.serial.as_deref() != Some(serial) {
        return Err(CredentialError::DeviceMismatch);
    }
    if device.fips != Some(true) {
        return Err(CredentialError::SmartCardOperation(
            "authorized device is not reported as FIPS-capable".into(),
        ));
    }
    let info = discovery.piv_info(id)?;
    verify_retry_default(info.pin.as_ref(), 3)?;
    verify_retry_default(info.puk.as_ref(), 3)?;
    let management_key = info.management_key.ok_or_else(|| {
        CredentialError::SmartCardOperation("PIV management-key metadata is unavailable".into())
    })?;
    if management_key.algorithm != PivAlgorithm::Aes192
        || management_key.default_value != Some(true)
    {
        return Err(CredentialError::SmartCardOperation(
            "PIV factory management-key defaults were not restored".into(),
        ));
    }
    let slots = discovery.piv_slots(id)?;
    for slot in PivSlot::STANDARD {
        let info = slots.iter().find(|info| info.slot == slot).ok_or_else(|| {
            CredentialError::SmartCardOperation(format!("PIV slot {slot} is unavailable"))
        })?;
        if info.key != KeyStatus::Absent || info.certificate.is_some() {
            return Err(CredentialError::SmartCardOperation(
                "PIV factory slots were not restored".into(),
            ));
        }
    }
    if !slots
        .iter()
        .any(|info| info.slot == PivSlot::ATTESTATION && info.certificate.is_some())
    {
        return Err(CredentialError::SmartCardOperation(
            "factory F9 certificate is missing".into(),
        ));
    }
    Ok(())
}

fn verify_retry_default(
    status: Option<&sigil_core::RetryStatus>,
    expected: u8,
) -> sigil_core::Result<()> {
    let status = status.ok_or_else(|| {
        CredentialError::SmartCardOperation("PIV retry metadata is unavailable".into())
    })?;
    if status.remaining != expected || status.total != Some(3) || status.default_value != Some(true)
    {
        return Err(CredentialError::SmartCardOperation(
            "PIV factory retry defaults were not restored".into(),
        ));
    }
    Ok(())
}

fn random_code() -> Vec<u8> {
    const CHARACTERS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut result = Vec::with_capacity(8);
    while result.len() < 8 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).expect("OS random source");
        for byte in random {
            if byte < 248 {
                result.push(CHARACTERS[usize::from(byte % 62)]);
                if result.len() == 8 {
                    break;
                }
            }
        }
    }
    result
}

#[derive(Clone)]
struct TestProfile {
    subject: Name,
    issuer: Name,
}

impl BuilderProfile for TestProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

fn issue_certificate(spki_der: &[u8], serial: u32) -> Vec<u8> {
    let issuer = Name::from_str("CN=Sigil mutation test CA").expect("test CA name");
    let subject = Name::from_str("CN=Sigil PIV hardware test").expect("test leaf name");
    let ca_key = SigningKey::from_bytes((&[11u8; 32]).into()).expect("test CA key");
    let builder = CertificateBuilder::new(
        TestProfile { subject, issuer },
        SerialNumber::from(serial),
        Validity::from_now(Duration::from_secs(3600)).expect("test certificate validity"),
        SubjectPublicKeyInfo::from_der(spki_der).expect("slot public key"),
    )
    .expect("test certificate builder");
    builder
        .build::<_, p256::ecdsa::DerSignature>(&ca_key)
        .expect("test CA issues certificate")
        .to_der()
        .expect("certificate DER")
}
