//! Hardware-free fixture backend. Never use this for enrollment or issuance.

use std::{
    collections::HashMap,
    sync::{
        Mutex,
        mpsc::{self, Receiver, Sender},
    },
};

use sigil_core::{
    Application, CredentialError, DeviceDiscovery, DeviceEvent, DeviceId, DeviceInfo,
    DeviceManagement, DiscoverableCredential, FidoInspection, FidoStatus, Fingerprint,
    FingerprintProgress, FirmwareVersion, KeyOrigin, KeyStatus, ManagedPivInitializationOutcome,
    ManagementKey, ManagementKeyAlgorithm, ManagementKeyStatus, MetadataAccess, PinPolicy,
    PivAlgorithm, PivAttestation, PivCertificate, PivInfo, PivInspection, PivKeyAlgorithm,
    PivKeyMetadata, PivManagement, PivPin, PivPuk, PivSlot, PivSlotInfo, Result, RetryStatus,
    Secret, TouchPolicy, Transport,
};

struct MockPivSlot {
    algorithm: PivAlgorithm,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    public_key_spki: Vec<u8>,
    certificate_der: Option<Vec<u8>>,
    signing_key: Option<MockSigningKey>,
}

enum MockSigningKey {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

impl MockSigningKey {
    fn public_key_spki(&self) -> Result<Vec<u8>> {
        use p256::pkcs8::EncodePublicKey;

        match self {
            Self::P256(key) => key
                .verifying_key()
                .to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|error| CredentialError::CertificateParse(error.to_string())),
            Self::P384(key) => key
                .verifying_key()
                .to_public_key_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|error| CredentialError::CertificateParse(error.to_string())),
        }
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;

        match self {
            Self::P256(key) => key
                .sign_prehash(digest)
                .map(|signature: p256::ecdsa::Signature| signature.to_der().as_bytes().to_vec())
                .map_err(|_| CredentialError::SmartCardOperation("mock CSR signing failed".into())),
            Self::P384(key) => key
                .sign_prehash(digest)
                .map(|signature: p384::ecdsa::Signature| signature.to_der().as_bytes().to_vec())
                .map_err(|_| CredentialError::SmartCardOperation("mock CSR signing failed".into())),
        }
    }
}

struct MockPivState {
    pin: PivPin,
    puk: PivPuk,
    pin_retries: u8,
    puk_retries: u8,
    management_key: ManagementKey,
    slots: HashMap<PivSlot, MockPivSlot>,
}

impl MockPivState {
    fn with_fixtures() -> Self {
        let mut slots = HashMap::new();
        slots.insert(
            PivSlot::AUTHENTICATION,
            fixture_slot(PivAlgorithm::EccP256, PinPolicy::Once, P256_CERT),
        );
        slots.insert(
            PivSlot::KEY_MANAGEMENT,
            fixture_slot(PivAlgorithm::Rsa2048, PinPolicy::Once, RSA_CERT),
        );
        slots.insert(
            PivSlot::CARD_AUTHENTICATION,
            fixture_slot(PivAlgorithm::EccP256, PinPolicy::Never, CARD_AUTH_CERT),
        );
        Self::factory_default(slots)
    }

    fn factory_default(slots: HashMap<PivSlot, MockPivSlot>) -> Self {
        Self {
            pin: PivPin::new(b"123456".to_vec()).expect("factory default PIV PIN"),
            puk: PivPuk::new(b"12345678".to_vec()).expect("factory default PIV PUK"),
            pin_retries: 3,
            puk_retries: 3,
            management_key: ManagementKey::new(
                ManagementKeyAlgorithm::Aes192,
                [
                    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
                ]
                .to_vec(),
            )
            .expect("factory default management key"),
            slots,
        }
    }

    fn empty_defaults() -> Self {
        Self::factory_default(HashMap::new())
    }

    fn info(&self) -> PivInfo {
        PivInfo {
            version: Some(FirmwareVersion {
                major: 5,
                minor: 7,
                patch: 1,
            }),
            pin: Some(RetryStatus {
                remaining: self.pin_retries,
                total: Some(3),
                default_value: Some(self.pin.as_bytes() == b"123456"),
            }),
            puk: Some(RetryStatus {
                remaining: self.puk_retries,
                total: Some(3),
                default_value: Some(self.puk.as_bytes() == b"12345678"),
            }),
            management_key: Some(ManagementKeyStatus {
                algorithm: self.management_key.algorithm().piv_algorithm(),
                default_value: Some(
                    self.management_key.algorithm() == ManagementKeyAlgorithm::Aes192
                        && self.management_key.as_bytes()
                            == [
                                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
                                7, 8,
                            ],
                ),
                touch_policy: Some(TouchPolicy::Never),
            }),
        }
    }

    fn slot_info(&self, slot: PivSlot) -> Result<PivSlotInfo> {
        match self.slots.get(&slot) {
            Some(state) => Ok(PivSlotInfo {
                slot,
                certificate: state
                    .certificate_der
                    .as_deref()
                    .map(sigil_piv::summarize_certificate)
                    .transpose()?,
                key: KeyStatus::Present(PivKeyMetadata {
                    algorithm: state.algorithm,
                    pin_policy: state.pin_policy,
                    touch_policy: state.touch_policy,
                    origin: Some(KeyOrigin::Generated),
                }),
            }),
            None => Ok(PivSlotInfo {
                slot,
                certificate: None,
                key: KeyStatus::Absent,
            }),
        }
    }
}

fn fixture_slot(algorithm: PivAlgorithm, pin_policy: PinPolicy, der: &[u8]) -> MockPivSlot {
    MockPivSlot {
        algorithm,
        pin_policy,
        touch_policy: TouchPolicy::Never,
        public_key_spki: sigil_piv::management::certificate_spki(der)
            .expect("fixture certificate public key"),
        certificate_der: Some(der.to_vec()),
        signing_key: None,
    }
}

#[derive(Default)]
pub struct MockDiscovery {
    devices: Mutex<Vec<DeviceInfo>>,
    listeners: Mutex<Vec<Sender<DeviceEvent>>>,
    piv_states: Mutex<HashMap<DeviceId, MockPivState>>,
    managed_initialization_fault: Mutex<ManagedInitializationFault>,
}

#[derive(Default)]
struct ManagedInitializationFault {
    fail_puk_change: bool,
    fail_rollback: bool,
}

impl MockDiscovery {
    pub fn with_example() -> Self {
        Self::with_devices(vec![DeviceInfo {
            id: DeviceId("mock-yubikey-12345678".into()),
            vendor: "Yubico (simulated)".into(),
            model: "YubiKey 5 NFC".into(),
            serial: Some("12345678".into()),
            firmware: Some(FirmwareVersion {
                major: 5,
                minor: 7,
                patch: 1,
            }),
            form_factor: Some("Keychain (USB-A)".into()),
            fips: None,
            connection: Some(Transport::UsbSmartCard),
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
                Application::YubiHsmAuth,
            ],
            supported_applications: vec![
                Application::Piv,
                Application::Fido2,
                Application::U2f,
                Application::Otp,
                Application::OpenPgp,
                Application::Oath,
                Application::YubiHsmAuth,
            ],
            simulated: true,
            metadata_access: MetadataAccess::Available,
            usb_enabled: vec![
                Application::Piv,
                Application::Fido2,
                Application::U2f,
                Application::Otp,
                Application::OpenPgp,
                Application::Oath,
                Application::YubiHsmAuth,
            ],
            usb_supported: vec![
                Application::Piv,
                Application::Fido2,
                Application::U2f,
                Application::Otp,
                Application::OpenPgp,
                Application::Oath,
                Application::YubiHsmAuth,
            ],
            nfc_enabled: vec![
                Application::Piv,
                Application::Fido2,
                Application::U2f,
                Application::Otp,
                Application::OpenPgp,
                Application::Oath,
                Application::YubiHsmAuth,
            ],
            nfc_supported: vec![
                Application::Piv,
                Application::Fido2,
                Application::U2f,
                Application::Otp,
                Application::OpenPgp,
                Application::Oath,
                Application::YubiHsmAuth,
            ],
            config_locked: Some(false),
            fips_approved: Some(Vec::new()),
            pin_complexity: Some(true),
        }])
    }

    pub fn with_example_fips() -> Self {
        let mut mock = Self::with_example();
        mock.devices
            .get_mut()
            .expect("mock device list lock")
            .first_mut()
            .expect("mock example device")
            .fips = Some(true);
        mock
    }

    pub fn with_devices(devices: Vec<DeviceInfo>) -> Self {
        let piv_states = devices
            .iter()
            .map(|device| (device.id.clone(), MockPivState::with_fixtures()))
            .collect();
        Self {
            devices: Mutex::new(devices),
            listeners: Mutex::new(Vec::new()),
            piv_states: Mutex::new(piv_states),
            managed_initialization_fault: Mutex::new(ManagedInitializationFault::default()),
        }
    }

    pub fn inject_managed_initialize_puk_failure(&self, rollback_fails: bool) {
        if let Ok(mut fault) = self.managed_initialization_fault.lock() {
            fault.fail_puk_change = true;
            fault.fail_rollback = rollback_fails;
        }
    }

    #[doc(hidden)]
    pub fn has_key_in_slot(&self, id: &DeviceId, slot: PivSlot) -> Result<bool> {
        self.with_piv_state(id, |state| Ok(state.slots.contains_key(&slot)))
    }

    pub fn connect(&self, mut device: DeviceInfo) -> Result<()> {
        device.simulated = true;
        let id = device.id.clone();
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
        self.piv_states
            .lock()
            .map_err(|_| CredentialError::InventoryUnavailable)?
            .entry(id)
            .or_insert_with(MockPivState::with_fixtures);
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
            self.piv_states
                .lock()
                .map_err(|_| CredentialError::InventoryUnavailable)?
                .remove(id);
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

impl FidoInspection for MockDiscovery {
    fn fido_status(&self, id: &DeviceId) -> Result<FidoStatus> {
        if !self.list()?.iter().any(|device| &device.id == id) {
            return Err(CredentialError::DeviceNotFound(id.0.clone()));
        }
        Ok(FidoStatus {
            versions: vec!["FIDO_2_1".into(), "U2F_V2".into()],
            pin_set: Some(true),
            pin_retries: Some(8),
            credential_management: true,
            fingerprint_enrollment: true,
        })
    }

    fn discoverable_credentials(
        &self,
        id: &DeviceId,
        _pin: &str,
    ) -> Result<Vec<DiscoverableCredential>> {
        if !self.list()?.iter().any(|device| &device.id == id) {
            return Err(CredentialError::DeviceNotFound(id.0.clone()));
        }
        Ok(Vec::new())
    }

    fn fingerprints(&self, id: &DeviceId, _pin: &str) -> Result<Vec<Fingerprint>> {
        self.fido_status(id)?;
        Ok(vec![Fingerprint {
            id: "0102".into(),
            name: Some("Index finger (simulated)".into()),
        }])
    }

    fn enroll_fingerprint(
        &self,
        _id: &DeviceId,
        _pin: &str,
        _on_progress: &mut dyn FnMut(FingerprintProgress),
    ) -> Result<Fingerprint> {
        Err(CredentialError::UnsupportedOperation(
            "fingerprint enrollment on simulated hardware".into(),
        ))
    }

    fn remove_fingerprint(&self, _id: &DeviceId, _pin: &str, _fingerprint_id: &str) -> Result<()> {
        Err(CredentialError::UnsupportedOperation(
            "fingerprint deletion on simulated hardware".into(),
        ))
    }
}

impl PivInspection for MockDiscovery {
    fn piv_info(&self, id: &DeviceId) -> Result<PivInfo> {
        self.with_piv_state(id, |state| Ok(state.info()))
    }

    fn piv_slots(&self, id: &DeviceId) -> Result<Vec<PivSlotInfo>> {
        self.with_piv_state(id, |state| {
            PivSlot::STANDARD
                .into_iter()
                .map(|slot| state.slot_info(slot))
                .collect()
        })
    }

    fn piv_certificate(&self, id: &DeviceId, slot: PivSlot) -> Result<Option<PivCertificate>> {
        self.with_piv_state(id, |state| {
            state
                .slots
                .get(&slot)
                .and_then(|slot| slot.certificate_der.as_ref())
                .map(|der| {
                    Ok(PivCertificate {
                        slot,
                        summary: sigil_piv::summarize_certificate(der)?,
                        der: der.clone(),
                    })
                })
                .transpose()
        })
    }
}

impl PivManagement for MockDiscovery {
    fn change_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_pin: &PivPin,
        new_pin: &PivPin,
    ) -> Result<()> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            verify_mock_pin(state, old_pin)?;
            state.pin = PivPin::new(new_pin.as_bytes().to_vec())?;
            state.pin_retries = 3;
            Ok(())
        })
    }

    fn change_puk(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_puk: &PivPuk,
        new_puk: &PivPuk,
    ) -> Result<()> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            verify_mock_puk(state, old_puk)?;
            state.puk = PivPuk::new(new_puk.as_bytes().to_vec())?;
            state.puk_retries = 3;
            Ok(())
        })
    }

    fn unblock_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        puk: &PivPuk,
        new_pin: &PivPin,
    ) -> Result<()> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            verify_mock_puk(state, puk)?;
            state.pin = PivPin::new(new_pin.as_bytes().to_vec())?;
            state.pin_retries = 3;
            state.puk_retries = 3;
            Ok(())
        })
    }

    fn change_management_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        current: &ManagementKey,
        new: &ManagementKey,
    ) -> Result<()> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            verify_mock_management_key(state, current)?;
            state.management_key = ManagementKey::new(new.algorithm(), new.as_bytes().to_vec())?;
            Ok(())
        })
    }

    fn managed_initialize(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        new_management_key: &ManagementKey,
        new_puk: &PivPuk,
    ) -> Result<ManagedPivInitializationOutcome> {
        self.verify_expected_serial(id, expected_serial)?;
        let fault = {
            let mut fault = self
                .managed_initialization_fault
                .lock()
                .map_err(|_| CredentialError::InventoryUnavailable)?;
            std::mem::take(&mut *fault)
        };
        self.with_piv_state(id, |state| {
            let info = state.info();
            if !info
                .puk
                .as_ref()
                .is_some_and(|status| status.default_value == Some(true))
                || !info
                    .management_key
                    .as_ref()
                    .is_some_and(|status| status.default_value == Some(true))
            {
                return Err(CredentialError::PivNotFactoryDefault);
            }
            if new_management_key.algorithm() != ManagementKeyAlgorithm::Aes256 {
                return Err(CredentialError::UnsupportedOperation(
                    "managed initialization requires a new AES-256 management key".into(),
                ));
            }
            let previous_key = ManagementKey::new(
                state.management_key.algorithm(),
                state.management_key.as_bytes().to_vec(),
            )?;
            state.management_key = ManagementKey::new(
                new_management_key.algorithm(),
                new_management_key.as_bytes().to_vec(),
            )?;
            if fault.fail_puk_change {
                if fault.fail_rollback {
                    return Ok(ManagedPivInitializationOutcome::Partial);
                }
                state.management_key = previous_key;
                return Ok(ManagedPivInitializationOutcome::NotApplied);
            }
            state.puk = PivPuk::new(new_puk.as_bytes().to_vec())?;
            state.puk_retries = 3;
            Ok(ManagedPivInitializationOutcome::Applied)
        })
    }

    fn generate_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        configuration: sigil_core::PivKeyConfiguration,
    ) -> Result<Vec<u8>> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            verify_mock_management_key(state, management_key)?;
            if configuration.slot == PivSlot::ATTESTATION {
                return Err(CredentialError::UnsupportedOperation(
                    "slot F9 is reserved for the YubiKey attestation key".into(),
                ));
            }
            let signing_key = match configuration.algorithm {
                PivKeyAlgorithm::EccP256 => MockSigningKey::P256(
                    p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).map_err(|_| {
                        CredentialError::SmartCardOperation("mock key generation failed".into())
                    })?,
                ),
                PivKeyAlgorithm::EccP384 => MockSigningKey::P384(
                    p384::ecdsa::SigningKey::from_bytes((&[7u8; 48]).into()).map_err(|_| {
                        CredentialError::SmartCardOperation("mock key generation failed".into())
                    })?,
                ),
            };
            let public_key_spki = signing_key.public_key_spki()?;
            state.slots.insert(
                configuration.slot,
                MockPivSlot {
                    algorithm: configuration.algorithm.piv_algorithm(),
                    pin_policy: configuration.pin_policy,
                    touch_policy: configuration.touch_policy,
                    public_key_spki: public_key_spki.clone(),
                    certificate_der: None,
                    signing_key: Some(signing_key),
                },
            );
            Ok(public_key_spki)
        })
    }

    fn attest(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        slot: PivSlot,
    ) -> Result<PivAttestation> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            if !state.slots.contains_key(&slot) || slot == PivSlot::ATTESTATION {
                return Err(CredentialError::CertificateNotFound(slot.to_string()));
            }
            Ok(PivAttestation {
                attestation_der: P256_CERT.to_vec(),
                intermediate_der: P256_CERT.to_vec(),
            })
        })
    }

    fn sign_csr(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        pin: &PivPin,
        slot: PivSlot,
        subject_dn: &str,
    ) -> Result<Vec<u8>> {
        use sha2::Digest;

        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            verify_mock_pin(state, pin)?;
            let slot = state
                .slots
                .get(&slot)
                .ok_or(CredentialError::DeviceMismatch)?;
            let signing_key = slot.signing_key.as_ref().ok_or_else(|| {
                CredentialError::UnsupportedOperation("mock slot has no signing key".into())
            })?;
            let (info, algorithm) =
                sigil_piv::management::build_csr_info(subject_dn, &slot.public_key_spki)?;
            let digest = match algorithm {
                PivKeyAlgorithm::EccP256 => sha2::Sha256::digest(&info).to_vec(),
                PivKeyAlgorithm::EccP384 => sha2::Sha384::digest(&info).to_vec(),
            };
            let signature = signing_key.sign_digest(&digest)?;
            let csr = sigil_piv::management::assemble_csr(&info, &signature, algorithm)?;
            sigil_piv::management::verify_csr(&csr)?;
            Ok(csr)
        })
    }

    fn import_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
        certificate_der: &[u8],
    ) -> Result<()> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            verify_mock_management_key(state, management_key)?;
            if slot == PivSlot::ATTESTATION {
                return Err(CredentialError::UnsupportedOperation(
                    "slot F9 is reserved for the YubiKey attestation key".into(),
                ));
            }
            let slot_state = state
                .slots
                .get_mut(&slot)
                .ok_or(CredentialError::DeviceMismatch)?;
            let certificate_spki = sigil_piv::management::certificate_spki(certificate_der)?;
            if certificate_spki != slot_state.public_key_spki {
                return Err(CredentialError::DeviceMismatch);
            }
            sigil_piv::summarize_certificate(certificate_der)?;
            slot_state.certificate_der = Some(certificate_der.to_vec());
            Ok(())
        })
    }

    fn delete_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            verify_mock_management_key(state, management_key)?;
            if slot == PivSlot::ATTESTATION {
                return Err(CredentialError::UnsupportedOperation(
                    "slot F9 is reserved for the YubiKey attestation certificate".into(),
                ));
            }
            if let Some(slot) = state.slots.get_mut(&slot) {
                slot.certificate_der = None;
            }
            Ok(())
        })
    }

    fn delete_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            verify_mock_management_key(state, management_key)?;
            if slot == PivSlot::ATTESTATION {
                return Err(CredentialError::UnsupportedOperation(
                    "slot F9 is reserved for the YubiKey attestation key".into(),
                ));
            }
            state.slots.remove(&slot);
            Ok(())
        })
    }

    fn reset(&self, id: &DeviceId, expected_serial: &str) -> Result<()> {
        self.verify_expected_serial(id, expected_serial)?;
        self.with_piv_state(id, |state| {
            *state = MockPivState::empty_defaults();
            Ok(())
        })
    }
}

impl MockDiscovery {
    fn with_piv_state<T>(
        &self,
        id: &DeviceId,
        operation: impl FnOnce(&mut MockPivState) -> Result<T>,
    ) -> Result<T> {
        self.require_known_device(id)?;
        let mut states = self
            .piv_states
            .lock()
            .map_err(|_| CredentialError::InventoryUnavailable)?;
        let state = states
            .get_mut(id)
            .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))?;
        operation(state)
    }

    fn require_known_device(&self, id: &DeviceId) -> Result<()> {
        if self.list()?.iter().any(|device| &device.id == id) {
            Ok(())
        } else {
            Err(CredentialError::DeviceNotFound(id.0.clone()))
        }
    }

    fn verify_expected_serial(&self, id: &DeviceId, expected_serial: &str) -> Result<()> {
        let actual = self
            .device(id)?
            .serial
            .ok_or(CredentialError::DeviceMismatch)?;
        if expected_serial.is_empty() || actual != expected_serial {
            return Err(CredentialError::DeviceMismatch);
        }
        Ok(())
    }

    fn device(&self, id: &DeviceId) -> Result<DeviceInfo> {
        self.list()?
            .into_iter()
            .find(|device| device.id == *id)
            .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))
    }
}

fn verify_mock_pin(state: &mut MockPivState, pin: &PivPin) -> Result<()> {
    if state.pin_retries == 0 {
        return Err(CredentialError::PinBlocked);
    }
    if state.pin.as_bytes() == pin.as_bytes() {
        state.pin_retries = 3;
        Ok(())
    } else {
        state.pin_retries -= 1;
        Err(CredentialError::PinIncorrect {
            remaining: state.pin_retries,
        })
    }
}

fn verify_mock_puk(state: &mut MockPivState, puk: &PivPuk) -> Result<()> {
    if state.puk_retries == 0 {
        return Err(CredentialError::PukBlocked);
    }
    if state.puk.as_bytes() == puk.as_bytes() {
        state.puk_retries = 3;
        Ok(())
    } else {
        state.puk_retries -= 1;
        Err(CredentialError::PukIncorrect {
            remaining: state.puk_retries,
        })
    }
}

fn verify_mock_management_key(state: &MockPivState, key: &ManagementKey) -> Result<()> {
    if state.management_key.algorithm() == key.algorithm()
        && state.management_key.as_bytes() == key.as_bytes()
    {
        Ok(())
    } else {
        Err(CredentialError::ManagementKeyIncorrect)
    }
}

const P256_CERT: &[u8] = include_bytes!("../fixtures/piv-9a-p256.der");
const RSA_CERT: &[u8] = include_bytes!("../fixtures/piv-9d-rsa2048.der");
const CARD_AUTH_CERT: &[u8] = include_bytes!("../fixtures/piv-9e-p256.der");

impl DeviceManagement for MockDiscovery {
    fn set_enabled_applications(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        usb: &[Application],
        nfc: Option<&[Application]>,
        lock_code: Option<&Secret>,
    ) -> Result<()> {
        self.verify_expected_serial(id, expected_serial)?;
        if lock_code.is_some_and(|code| code.expose().len() != 16) {
            return Err(CredentialError::SmartCardOperation(
                "configuration lock code must be 16 bytes".into(),
            ));
        }
        let updated = {
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| CredentialError::InventoryUnavailable)?;
            let device = devices
                .iter_mut()
                .find(|device| device.id == *id)
                .ok_or_else(|| CredentialError::DeviceNotFound(id.0.clone()))?;
            if device.config_locked == Some(true) && lock_code.is_none() {
                return Err(CredentialError::SmartCardOperation(
                    "the YubiKey configuration lock code is required".into(),
                ));
            }
            device.usb_enabled = usb.to_vec();
            if let Some(nfc) = nfc {
                device.nfc_enabled = nfc.to_vec();
            }
            device.applications = if device.connection == Some(Transport::Nfc) {
                device.nfc_enabled.clone()
            } else {
                device.usb_enabled.clone()
            };
            device.clone()
        };
        self.publish(DeviceEvent::Updated(updated))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piv_mock_tracks_secrets_slots_and_reset_state() {
        let mock = MockDiscovery::with_example();
        let id = DeviceId("mock-yubikey-12345678".into());
        let serial = "12345678";
        let pin0 = PivPin::new(b"123456".to_vec()).unwrap();
        let pin1 = PivPin::new(b"654321".to_vec()).unwrap();
        let pin2 = PivPin::new(b"765432".to_vec()).unwrap();
        let puk0 = PivPuk::new(b"12345678".to_vec()).unwrap();
        let puk1 = PivPuk::new(b"87654321".to_vec()).unwrap();
        mock.change_pin(&id, serial, &pin0, &pin1).unwrap();
        assert_eq!(
            mock.change_pin(
                &id,
                serial,
                &PivPin::new(b"111111".to_vec()).unwrap(),
                &pin2,
            ),
            Err(CredentialError::PinIncorrect { remaining: 2 })
        );
        mock.change_puk(&id, serial, &puk0, &puk1).unwrap();
        mock.unblock_pin(&id, serial, &puk1, &pin2).unwrap();

        let default_management = ManagementKey::new(
            ManagementKeyAlgorithm::Aes192,
            [
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
            ]
            .to_vec(),
        )
        .unwrap();
        let management_key =
            ManagementKey::new(ManagementKeyAlgorithm::Aes128, vec![0x44; 16]).unwrap();
        mock.change_management_key(&id, serial, &default_management, &management_key)
            .unwrap();
        let spki = mock
            .generate_key(
                &id,
                serial,
                &management_key,
                sigil_core::PivKeyConfiguration {
                    slot: PivSlot::SIGNATURE,
                    algorithm: PivKeyAlgorithm::EccP256,
                    pin_policy: PinPolicy::Once,
                    touch_policy: TouchPolicy::Never,
                },
            )
            .unwrap();
        let csr = mock
            .sign_csr(&id, serial, &pin2, PivSlot::SIGNATURE, "CN=Mock signer")
            .unwrap();
        sigil_piv::management::verify_csr(&csr).unwrap();
        assert!(!spki.is_empty());
        assert!(
            !mock
                .attest(&id, serial, PivSlot::SIGNATURE)
                .unwrap()
                .attestation_der
                .is_empty()
        );

        mock.import_certificate(
            &id,
            serial,
            &management_key,
            PivSlot::AUTHENTICATION,
            P256_CERT,
        )
        .unwrap();
        assert_eq!(
            mock.import_certificate(
                &id,
                serial,
                &management_key,
                PivSlot::AUTHENTICATION,
                RSA_CERT,
            ),
            Err(CredentialError::DeviceMismatch)
        );
        mock.delete_certificate(&id, serial, &management_key, PivSlot::AUTHENTICATION)
            .unwrap();
        assert!(
            mock.piv_certificate(&id, PivSlot::AUTHENTICATION)
                .unwrap()
                .is_none()
        );
        mock.delete_key(&id, serial, &management_key, PivSlot::SIGNATURE)
            .unwrap();
        mock.reset(&id, serial).unwrap();
        let info = mock.piv_info(&id).unwrap();
        assert_eq!(
            info.pin.as_ref().and_then(|value| value.default_value),
            Some(true)
        );
        assert_eq!(
            info.puk.as_ref().and_then(|value| value.default_value),
            Some(true)
        );
        assert_eq!(
            info.management_key
                .as_ref()
                .and_then(|value| value.default_value),
            Some(true)
        );
        assert_eq!(
            mock.piv_slots(&id)
                .unwrap()
                .iter()
                .find(|slot| slot.slot == PivSlot::SIGNATURE)
                .map(|slot| slot.key.clone()),
            Some(KeyStatus::Absent)
        );
    }
}
