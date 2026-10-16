//! SP 800-73 PIV operations, written once. Vendor behaviour comes from a `PivVendor`. A capability-gated operation
//! checks the capability before it sends any APDU, so an unsupported token is refused without touching the card.

use std::time::{SystemTime, UNIX_EPOCH};

use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384};
use sigil_core::{
    CredentialError, DeviceInfo, KeyStatus, ManagedPivInitializationOutcome, ManagementKey,
    ManagementKeyAlgorithm, PinPolicy, PivAttestation, PivCertificate, PivInfo, PivKeyAlgorithm,
    PivKeyConfiguration, PivPin, PivPuk, PivSlot, PivSlotInfo, Result, TouchPolicy,
};
use x509_cert::Certificate;

use crate::{
    CardTransport, management, read_certificate as read_certificate_object, select,
    summarize_certificate, tlv,
    vendor::{PivVendor, unsupported},
};

fn require(vendor: &dyn PivVendor, enabled: bool, operation: &str) -> Result<()> {
    if enabled {
        Ok(())
    } else {
        Err(unsupported(vendor.name(), operation))
    }
}

fn reject_attestation_slot(slot: PivSlot) -> Result<()> {
    if slot == PivSlot::ATTESTATION {
        Err(CredentialError::UnsupportedOperation(
            "slot F9 is reserved for the attestation key".into(),
        ))
    } else {
        Ok(())
    }
}

fn unsupported_public_key() -> CredentialError {
    CredentialError::UnsupportedOperation("this token cannot report the slot's public key".into())
}

pub fn read_info(transport: &mut dyn CardTransport, vendor: &dyn PivVendor) -> Result<PivInfo> {
    vendor.info(transport)
}

pub fn read_slots(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
) -> Result<Vec<PivSlotInfo>> {
    select(transport)?;
    let mut entries = Vec::new();
    for slot in vendor.listed_slots() {
        let (certificate_present, certificate) = match read_certificate_object(transport, slot) {
            Ok(Some(bytes)) => match summarize_certificate(&bytes) {
                Ok(summary) => (true, Some(summary)),
                Err(error @ CredentialError::CertificateParse(_)) => {
                    tracing::warn!(slot = %slot, %error, "could not parse PIV slot certificate");
                    (true, None)
                }
                Err(error) => return Err(error),
            },
            Ok(None) => (false, None),
            Err(error @ CredentialError::CertificateParse(_)) => {
                tracing::warn!(slot = %slot, %error, "could not parse PIV slot certificate");
                (true, None)
            }
            Err(error) => return Err(error),
        };
        let key: KeyStatus = vendor.slot_key_status(transport, slot)?;
        let is_standard = PivSlot::STANDARD.contains(&slot);
        if !is_standard && !certificate_present && !matches!(key, KeyStatus::Present(_)) {
            continue;
        }
        entries.push(PivSlotInfo {
            slot,
            certificate,
            key,
        });
    }
    Ok(entries)
}

pub fn read_certificate(
    transport: &mut dyn CardTransport,
    slot: PivSlot,
) -> Result<Option<PivCertificate>> {
    select(transport)?;
    let Some(der) = read_certificate_object(transport, slot)? else {
        return Ok(None);
    };
    let summary = summarize_certificate(&der)?;
    Ok(Some(PivCertificate { slot, summary, der }))
}

pub fn change_pin(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    device: &DeviceInfo,
    old_pin: &PivPin,
    new_pin: &PivPin,
) -> Result<()> {
    require(vendor, vendor.capabilities().piv_writes, "PIN change")?;
    vendor.validate_new_code(device, new_pin.as_bytes())?;
    management::change_pin(transport, old_pin, new_pin)
}

pub fn change_puk(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    device: &DeviceInfo,
    old_puk: &PivPuk,
    new_puk: &PivPuk,
) -> Result<()> {
    require(vendor, vendor.capabilities().piv_writes, "PUK change")?;
    vendor.validate_new_code(device, new_puk.as_bytes())?;
    management::change_puk(transport, old_puk, new_puk)
}

pub fn unblock_pin(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    device: &DeviceInfo,
    puk: &PivPuk,
    new_pin: &PivPin,
) -> Result<()> {
    require(vendor, vendor.capabilities().piv_writes, "PIN unblock")?;
    vendor.validate_new_code(device, puk.as_bytes())?;
    vendor.validate_new_code(device, new_pin.as_bytes())?;
    management::unblock_pin(transport, puk, new_pin)
}

pub fn change_management_key(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    current: &ManagementKey,
    new_key: &ManagementKey,
) -> Result<()> {
    require(
        vendor,
        vendor.capabilities().set_management_key,
        "management key change",
    )?;
    select(transport)?;
    management::authenticate_management_key_selected(transport, current)?;
    vendor.set_management_key(transport, new_key)?;
    management::authenticate_management_key_selected(transport, new_key)
}

pub fn managed_initialize(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    device: &DeviceInfo,
    new_management_key: &ManagementKey,
    new_puk: &PivPuk,
) -> Result<ManagedPivInitializationOutcome> {
    let capabilities = vendor.capabilities();
    require(
        vendor,
        capabilities.piv_writes
            && capabilities.set_management_key
            && capabilities.factory_initialize,
        "managed initialization",
    )?;
    if new_management_key.algorithm() != ManagementKeyAlgorithm::Aes256 {
        return Err(CredentialError::UnsupportedOperation(
            "managed initialization requires a new AES-256 management key".into(),
        ));
    }
    vendor.validate_new_code(device, new_puk.as_bytes())?;
    let info = vendor
        .info(transport)
        .map_err(|_| CredentialError::PivNotFactoryDefault)?;
    if !vendor.is_factory_default(&info) {
        return Err(CredentialError::PivNotFactoryDefault);
    }
    let factory_management_key = vendor.factory_management_key(&info)?;
    let factory_puk = vendor.factory_puk()?;

    change_management_key(
        transport,
        vendor,
        &factory_management_key,
        new_management_key,
    )?;
    if let Err(puk_error) = management::change_puk(transport, &factory_puk, new_puk) {
        if !matches!(
            puk_error,
            CredentialError::PukIncorrect { .. }
                | CredentialError::CardStatus(_)
                | CredentialError::PivFipsNotApproved
                | CredentialError::PukComplexity
        ) {
            return Err(puk_error);
        }
        return if change_management_key(
            transport,
            vendor,
            new_management_key,
            &factory_management_key,
        )
        .is_ok()
        {
            Ok(ManagedPivInitializationOutcome::NotApplied)
        } else {
            Ok(ManagedPivInitializationOutcome::Partial)
        };
    }
    Ok(ManagedPivInitializationOutcome::Applied)
}

pub fn generate_key(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    device: &DeviceInfo,
    management_key: &ManagementKey,
    configuration: PivKeyConfiguration,
) -> Result<Vec<u8>> {
    let capabilities = vendor.capabilities();
    require(vendor, capabilities.piv_writes, "key generation")?;
    vendor.validate_pin_policy(device, configuration.pin_policy)?;
    let policies = if capabilities.pin_touch_policy {
        Some((configuration.pin_policy, configuration.touch_policy))
    } else if configuration.pin_policy == PinPolicy::Default
        && configuration.touch_policy == TouchPolicy::Default
    {
        None
    } else {
        return Err(unsupported(vendor.name(), "PIN and touch policies"));
    };
    management::generate_key_pair_with_policies(
        transport,
        management_key,
        configuration.slot,
        configuration.algorithm,
        policies,
    )
    .map_err(|error| vendor.map_error(device, error))
}

pub fn attest(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    slot: PivSlot,
) -> Result<PivAttestation> {
    require(vendor, vendor.capabilities().attestation, "attestation")?;
    vendor.attest(transport, slot)
}

pub fn sign_csr(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    device: &DeviceInfo,
    pin: &PivPin,
    slot: PivSlot,
    subject_dn: &str,
    expected_public_key: Option<&[u8]>,
) -> Result<Vec<u8>> {
    require(vendor, vendor.capabilities().piv_writes, "CSR signing")?;
    if slot == PivSlot::ATTESTATION {
        return Err(CredentialError::UnsupportedOperation(
            "slot F9 cannot sign arbitrary CSR data".into(),
        ));
    }
    vendor.validate_new_code(device, pin.as_bytes())?;
    select(transport)?;
    management::verify_pin_selected(transport, pin)?;
    let vendor_key = vendor.slot_public_key(transport, slot)?;
    let spki = match bound_public_key(vendor_key, expected_public_key)? {
        Some(key) => key,
        None => slot_certificate_spki(transport, slot)?.ok_or_else(unsupported_public_key)?,
    };
    let (info_der, algorithm) = management::build_csr_info(subject_dn, &spki)?;
    let digest = match algorithm {
        PivKeyAlgorithm::EccP256 => Sha256::digest(&info_der).to_vec(),
        PivKeyAlgorithm::EccP384 => Sha384::digest(&info_der).to_vec(),
    };
    let signature = management::sign_digest_selected(transport, slot, algorithm, &digest)?;
    let csr = management::assemble_csr(&info_der, &signature, algorithm)?;
    management::verify_csr(&csr)?;
    Ok(csr)
}

pub fn import_certificate(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    device: &DeviceInfo,
    management_key: &ManagementKey,
    slot: PivSlot,
    certificate_der: &[u8],
    expected_public_key: Option<&[u8]>,
) -> Result<()> {
    require(
        vendor,
        vendor.capabilities().piv_writes,
        "certificate import",
    )?;
    reject_attestation_slot(slot)?;
    select(transport)?;
    management::authenticate_management_key_selected(transport, management_key)?;
    let vendor_key = vendor.slot_public_key(transport, slot)?;
    let slot_spki =
        bound_public_key(vendor_key, expected_public_key)?.ok_or_else(unsupported_import_key)?;
    verify_certificate_matches_key(certificate_der, &slot_spki)?;
    if vendor.ensure_chuid_on_import() {
        ensure_chuid(transport, random_guid()?, &chuid_expiry(unix_now()))?;
    }
    management::put_certificate_selected(transport, slot, certificate_der)
        .map_err(|error| vendor.map_error(device, error))
}

pub fn delete_certificate(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    device: &DeviceInfo,
    management_key: &ManagementKey,
    slot: PivSlot,
) -> Result<()> {
    require(
        vendor,
        vendor.capabilities().piv_writes,
        "certificate delete",
    )?;
    reject_attestation_slot(slot)?;
    select(transport)?;
    management::authenticate_management_key_selected(transport, management_key)?;
    management::delete_certificate_selected(transport, slot)
        .map_err(|error| vendor.map_error(device, error))
}

pub fn delete_key(
    transport: &mut dyn CardTransport,
    vendor: &dyn PivVendor,
    management_key: &ManagementKey,
    slot: PivSlot,
) -> Result<()> {
    require(vendor, vendor.capabilities().delete_key, "key delete")?;
    reject_attestation_slot(slot)?;
    select(transport)?;
    management::authenticate_management_key_selected(transport, management_key)?;
    vendor.delete_key(transport, slot)
}

pub fn reset(transport: &mut dyn CardTransport, vendor: &dyn PivVendor) -> Result<()> {
    require(vendor, vendor.capabilities().reset, "reset")?;
    vendor.reset(transport)
}

/// The key a CSR or import is bound to. A key the token reports must agree with a caller-supplied key.
fn bound_public_key(
    vendor_key: Option<Vec<u8>>,
    caller_key: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    match (vendor_key, caller_key) {
        (Some(vendor), Some(caller)) if vendor != caller => Err(CredentialError::DeviceMismatch),
        (Some(vendor), _) => Ok(Some(vendor)),
        (None, Some(caller)) => Ok(Some(caller.to_vec())),
        (None, None) => Ok(None),
    }
}

fn unsupported_import_key() -> CredentialError {
    CredentialError::UnsupportedOperation(
        "this token cannot report the slot's public key; supply the key from generation".into(),
    )
}

/// The SubjectPublicKeyInfo of the certificate currently in the slot, when there is one.
fn slot_certificate_spki(
    transport: &mut dyn CardTransport,
    slot: PivSlot,
) -> Result<Option<Vec<u8>>> {
    let Some(der) = read_certificate_object(transport, slot)? else {
        return Ok(None);
    };
    management::certificate_spki(&der).map(Some)
}

const CHUID_TAG: [u8; 3] = [0x5f, 0xc1, 0x02];

/// Writes a CHUID when the token has none. A present CHUID is left unchanged.
pub fn ensure_chuid(transport: &mut dyn CardTransport, guid: [u8; 16], expiry: &str) -> Result<()> {
    if management::read_data_object_selected(transport, &CHUID_TAG)?.is_some() {
        return Ok(());
    }
    management::put_data_object_selected(transport, &CHUID_TAG, &chuid(&guid, expiry)?)
}

/// The CHUID contents: FASC-N, GUID, expiry as YYYYMMDD, an empty issuer signature, and an empty error-detection code.
/// The CHUID object wraps these in tag 53 when it is stored (SP 800-73-4 Part 1).
pub fn chuid(guid: &[u8; 16], expiry: &str) -> Result<Vec<u8>> {
    let mut contents = tlv::encode(0x30, &NON_FEDERAL_FASCN)?;
    contents.extend_from_slice(&tlv::encode(0x34, guid)?);
    contents.extend_from_slice(&tlv::encode(0x35, expiry.as_bytes())?);
    contents.extend_from_slice(&tlv::encode(0x3e, &[])?);
    contents.extend_from_slice(&tlv::encode(0xfe, &[])?);
    Ok(contents)
}

/// The non-federal FASC-N (agency 9999, system 9999, credential 999999) that ykman writes in its CHUIDs: `generate_chuid`
/// in ykman/piv.py, yubikey-manager (https://github.com/Yubico/yubikey-manager), built from
/// `FascN(9999, 9999, 999999, 0, 1, 0000000000, 3, 0000, 1)`. The 40-character FASC-N is 5-bit BCD with sentinels and an
/// LRC (TIG SCEPACS). Every card carries this value, so the GUID alone identifies the credential.
const NON_FEDERAL_FASCN: [u8; 25] = [
    0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58, 0x21, 0x08,
    0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb,
];

/// The CHUID expiry for a credential issued now: the same calendar date ten years later, as YYYYMMDD.
pub fn chuid_expiry(unix_now: i64) -> String {
    let (year, month, day) = civil_from_days(unix_now.div_euclid(86_400));
    let year = year + 10;
    let day = if month == 2 && day == 29 && !is_leap(year) {
        28
    } else {
        day
    };
    format!("{year:04}{month:02}{day:02}")
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Converts days since 1970-01-01 to a proleptic Gregorian (year, month, day).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn random_guid() -> Result<[u8; 16]> {
    let mut guid = [0u8; 16];
    getrandom::fill(&mut guid)
        .map_err(|_| CredentialError::BackendUnavailable("OS random source unavailable".into()))?;
    Ok(guid)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

/// Checks that a certificate carries the given SubjectPublicKeyInfo.
pub fn verify_certificate_matches_key(certificate_der: &[u8], expected_spki: &[u8]) -> Result<()> {
    let certificate = Certificate::from_der(certificate_der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let spki = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    if spki != expected_spki {
        return Err(CredentialError::DeviceMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sigil_core::{
        DeviceId, KeyStatus, MetadataAccess, PinPolicy, PivKeyAlgorithm, PivPin, PivPuk, PivSlot,
        TouchPolicy,
    };

    use super::*;
    use crate::vendor::PivCapabilities;

    const P256_CERT: &[u8] = include_bytes!("../../sigil-mock/fixtures/piv-9a-p256.der");

    /// A card that answers SELECT, VERIFY, and GET DATA for the objects it holds. Every command is recorded, and an
    /// unexpected command fails the transmit rather than panicking.
    struct FakeCard {
        objects: Vec<([u8; 3], Vec<u8>)>,
        pin_status: u16,
        sent: Vec<Vec<u8>>,
    }

    impl FakeCard {
        fn empty() -> Self {
            Self {
                objects: Vec::new(),
                pin_status: 0x9000,
                sent: Vec::new(),
            }
        }
    }

    impl CardTransport for FakeCard {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            self.sent.push(command.to_vec());
            let ok = |data: &[u8]| [data, &[0x90, 0x00]].concat();
            match command[1] {
                0xa4 => Ok(ok(&[])),
                0x20 => {
                    let status = if command.len() == 4 {
                        0x63c5
                    } else {
                        self.pin_status
                    };
                    Ok(status.to_be_bytes().to_vec())
                }
                0xcb => {
                    let tag = [command[7], command[8], command[9]];
                    match self.objects.iter().find(|(object, _)| *object == tag) {
                        Some((_, data)) => Ok(ok(data)),
                        None => Ok(vec![0x6a, 0x80]),
                    }
                }
                0xdb => Ok(ok(&[])),
                _ => Err(CredentialError::SmartCardOperation(
                    "unexpected APDU".into(),
                )),
            }
        }
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    fn certificate_object(certificate: &[u8]) -> Vec<u8> {
        let mut field = vec![
            0x70,
            0x82,
            (certificate.len() >> 8) as u8,
            certificate.len() as u8,
        ];
        field.extend_from_slice(certificate);
        let mut object = vec![0x53, 0x82, ((field.len()) >> 8) as u8, field.len() as u8];
        object.extend_from_slice(&field);
        object
    }

    /// A vendor with only the capabilities a test sets and the SP 800-73 defaults for everything else.
    struct TestVendor(PivCapabilities);

    impl PivVendor for TestVendor {
        fn name(&self) -> &'static str {
            "Test"
        }
        fn capabilities(&self) -> PivCapabilities {
            self.0
        }
        fn verify_serial(
            &self,
            _transport: &mut dyn CardTransport,
            _expected: &str,
        ) -> Result<String> {
            Err(CredentialError::DeviceMismatch)
        }
    }

    fn device() -> DeviceInfo {
        DeviceInfo {
            id: DeviceId("test".into()),
            vendor: "Test".into(),
            model: "Test".into(),
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
            applications: Vec::new(),
            supported_applications: Vec::new(),
            simulated: false,
            metadata_access: MetadataAccess::Unknown,
        }
    }

    fn management_key() -> ManagementKey {
        ManagementKey::new(ManagementKeyAlgorithm::Aes256, vec![0x11; 32]).unwrap()
    }

    fn configuration(pin_policy: PinPolicy, touch_policy: TouchPolicy) -> PivKeyConfiguration {
        PivKeyConfiguration {
            slot: PivSlot::AUTHENTICATION,
            algorithm: PivKeyAlgorithm::EccP256,
            pin_policy,
            touch_policy,
        }
    }

    #[test]
    fn gated_operations_fail_before_any_apdu_without_their_capability() {
        let vendor = TestVendor(PivCapabilities::default());
        let device = device();
        let mut card = FakeCard::empty();
        let pin = PivPin::new(b"123456".to_vec()).unwrap();
        let puk = PivPuk::new(b"12345678".to_vec()).unwrap();
        let key = management_key();
        let results = [
            change_pin(&mut card, &vendor, &device, &pin, &pin),
            change_puk(&mut card, &vendor, &device, &puk, &puk),
            unblock_pin(&mut card, &vendor, &device, &puk, &pin),
            change_management_key(&mut card, &vendor, &key, &key),
            managed_initialize(&mut card, &vendor, &device, &key, &puk).map(|_| ()),
            generate_key(
                &mut card,
                &vendor,
                &device,
                &key,
                configuration(PinPolicy::Default, TouchPolicy::Default),
            )
            .map(|_| ()),
            sign_csr(
                &mut card,
                &vendor,
                &device,
                &pin,
                PivSlot::AUTHENTICATION,
                "CN=test",
                None,
            )
            .map(|_| ()),
            import_certificate(
                &mut card,
                &vendor,
                &device,
                &key,
                PivSlot::AUTHENTICATION,
                P256_CERT,
                None,
            ),
            delete_certificate(&mut card, &vendor, &device, &key, PivSlot::AUTHENTICATION),
            delete_key(&mut card, &vendor, &key, PivSlot::AUTHENTICATION),
            reset(&mut card, &vendor).map(|_| ()),
            attest(&mut card, &vendor, PivSlot::AUTHENTICATION).map(|_| ()),
        ];
        for result in results {
            assert!(
                matches!(result, Err(CredentialError::UnsupportedOperation(_))),
                "expected UnsupportedOperation, got {result:?}"
            );
        }
        assert!(card.sent.is_empty(), "no APDU may be sent: {:?}", card.sent);
    }

    #[test]
    fn non_default_policies_are_refused_before_apdu_when_the_token_cannot_set_them() {
        let vendor = TestVendor(PivCapabilities {
            piv_writes: true,
            ..PivCapabilities::default()
        });
        let mut card = FakeCard::empty();
        let result = generate_key(
            &mut card,
            &vendor,
            &device(),
            &management_key(),
            configuration(PinPolicy::Once, TouchPolicy::Default),
        );
        assert!(matches!(
            result,
            Err(CredentialError::UnsupportedOperation(_))
        ));
        assert!(card.sent.is_empty());
    }

    #[test]
    fn sign_csr_stops_before_the_signing_command_when_the_slot_key_is_unreadable() {
        let vendor = TestVendor(PivCapabilities {
            piv_writes: true,
            ..PivCapabilities::default()
        });
        let mut card = FakeCard::empty();
        let pin = PivPin::new(b"123456".to_vec()).unwrap();
        let result = sign_csr(
            &mut card,
            &vendor,
            &device(),
            &pin,
            PivSlot::AUTHENTICATION,
            "CN=test",
            None,
        );
        assert!(matches!(
            result,
            Err(CredentialError::UnsupportedOperation(message)) if message.contains("public key")
        ));
        assert!(
            card.sent.iter().all(|command| command[1] != 0x87),
            "no GENERAL AUTHENTICATE may be sent: {:?}",
            card.sent
        );
    }

    #[test]
    fn chuid_carries_fascn_guid_expiry_and_empty_signature_and_lrc() {
        let guid = [0x11u8; 16];
        let contents = chuid(&guid, "20300228").unwrap();
        let fields = crate::tlv::parse(&contents).unwrap();
        let tags: Vec<u16> = fields.iter().map(|(tag, _)| *tag).collect();
        assert_eq!(tags, vec![0x30, 0x34, 0x35, 0x3e, 0xfe]);
        assert_eq!(
            fields[0].1,
            hex_bytes("d4e739da739ced39ce739d836858210842108421c84210c3eb")
        );
        assert_eq!(fields[1].1, guid);
        assert_eq!(fields[2].1, b"20300228");
        assert!(fields[3].1.is_empty() && fields[4].1.is_empty());
    }

    #[test]
    fn ensure_chuid_writes_only_when_the_token_has_none() {
        let mut absent = FakeCard::empty();
        ensure_chuid(&mut absent, [0x22; 16], "20300228").unwrap();
        let write = absent.sent.last().unwrap();
        assert_eq!(&write[..4], &[0x00, 0xdb, 0x3f, 0xff]);
        assert_eq!(&write[5..10], &[0x5c, 0x03, 0x5f, 0xc1, 0x02]);
        assert_eq!(write[10], 0x53);

        let mut present = FakeCard::empty();
        present
            .objects
            .push((CHUID_TAG, vec![0x53, 0x02, 0x30, 0x00]));
        ensure_chuid(&mut present, [0x22; 16], "20300228").unwrap();
        assert!(!present.sent.iter().any(|command| command[1] == 0xdb));
    }

    #[test]
    fn chuid_expiry_is_ten_years_later_with_leap_day_handled() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(18_321), (2020, 2, 29));
        assert_eq!(chuid_expiry(1_582_934_400), "20300228");
        assert_eq!(chuid_expiry(0), "19800101");
    }

    #[test]
    fn bound_key_must_agree_with_the_token_when_both_are_known() {
        assert_eq!(
            bound_public_key(Some(vec![1]), Some(&[1])).unwrap(),
            Some(vec![1])
        );
        assert_eq!(
            bound_public_key(Some(vec![1]), Some(&[2])),
            Err(CredentialError::DeviceMismatch)
        );
        assert_eq!(bound_public_key(None, Some(&[3])).unwrap(), Some(vec![3]));
        assert_eq!(
            bound_public_key(Some(vec![4]), None).unwrap(),
            Some(vec![4])
        );
        assert_eq!(bound_public_key(None, None).unwrap(), None);
    }

    #[test]
    fn read_info_reports_only_the_pin_retry_counter() {
        let mut card = FakeCard::empty();
        card.pin_status = 0x63c5;
        let info = read_info(&mut card, &TestVendor(PivCapabilities::default())).unwrap();
        assert_eq!(
            info.pin,
            Some(sigil_core::RetryStatus {
                remaining: 5,
                total: None,
                default_value: None
            })
        );
        assert_eq!(
            (info.version, info.puk, info.management_key),
            (None, None, None)
        );
    }

    #[test]
    fn absent_objects_are_missing_whether_they_report_6a80_or_6a82() {
        let mut card = FakeCard::empty();
        let slots = read_slots(&mut card, &TestVendor(PivCapabilities::default())).unwrap();
        assert_eq!(slots.len(), 4, "only standard slots are listed when empty");
        assert!(slots.iter().all(|slot| slot.certificate.is_none()));
        assert!(slots.iter().all(|slot| slot.key == KeyStatus::Unknown));
    }

    #[test]
    fn a_present_certificate_is_summarized_and_its_key_status_stays_unknown() {
        let mut card = FakeCard::empty();
        card.objects
            .push(([0x5f, 0xc1, 0x05], certificate_object(P256_CERT)));
        let slots = read_slots(&mut card, &TestVendor(PivCapabilities::default())).unwrap();
        let authentication = slots
            .iter()
            .find(|slot| slot.slot == PivSlot::AUTHENTICATION)
            .unwrap();
        let summary = authentication
            .certificate
            .as_ref()
            .expect("certificate summary");
        assert!(summary.subject.contains("Simulated PIV Authentication"));
        assert_eq!(authentication.key, KeyStatus::Unknown);
        assert_eq!(
            slots
                .iter()
                .filter(|slot| slot.certificate.is_some())
                .count(),
            1
        );
    }

    #[test]
    fn read_certificate_returns_none_for_an_absent_object() {
        let mut card = FakeCard::empty();
        assert_eq!(
            read_certificate(&mut card, PivSlot::SIGNATURE).unwrap(),
            None
        );
        card.objects
            .push(([0x5f, 0xc1, 0x0a], certificate_object(P256_CERT)));
        let found = read_certificate(&mut card, PivSlot::SIGNATURE)
            .unwrap()
            .unwrap();
        assert_eq!(found.der, P256_CERT);
    }
}
