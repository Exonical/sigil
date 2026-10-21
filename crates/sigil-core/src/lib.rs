//! Vendor-neutral credential domain. No transport handles or UI types belong here.

use std::sync::mpsc::Receiver;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod piv;
pub mod secrets;
pub mod time;
pub use piv::{
    AttestationInspection, CertificateFormat, CertificateSummary, KeyOrigin, KeyStatus,
    ManagementKeyStatus, PinPolicy, PivAlgorithm, PivAttestation, PivCertificate, PivInfo,
    PivKeyAlgorithm, PivKeyConfiguration, PivKeyMetadata, PivSlot, PivSlotInfo, RetryStatus,
    TouchPolicy,
};
pub use secrets::{ManagementKey, ManagementKeyAlgorithm, PivPin, PivPuk, Secret};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    UsbSmartCard,
    UsbHid,
    UsbOtp,
    Nfc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Application {
    Piv,
    Fido2,
    U2f,
    Otp,
    OpenPgp,
    Oath,
    YubiHsmAuth,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PivCapabilities {
    pub piv_writes: bool,
    pub key_metadata: bool,
    pub pin_touch_policy: bool,
    pub set_management_key: bool,
    pub attestation: bool,
    pub delete_key: bool,
    pub reset: bool,
    pub factory_initialize: bool,
    pub p384_generation: bool,
    pub retired_slot_generation: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Opaque identifier scoped to the discovery backend. Never infer a serial from this.
    pub id: DeviceId,
    pub vendor: String,
    pub model: String,
    pub serial: Option<String>,
    pub firmware: Option<FirmwareVersion>,
    /// Device form factor, when reported by the provider.
    pub form_factor: Option<String>,
    /// Whether the device reports FIPS-capable PIV firmware.
    #[serde(default)]
    pub fips: Option<bool>,
    #[serde(default)]
    pub usb_enabled: Vec<Application>,
    #[serde(default)]
    pub usb_supported: Vec<Application>,
    #[serde(default)]
    pub nfc_enabled: Vec<Application>,
    #[serde(default)]
    pub nfc_supported: Vec<Application>,
    #[serde(default)]
    pub config_locked: Option<bool>,
    #[serde(default)]
    pub fips_approved: Option<Vec<Application>>,
    #[serde(default)]
    pub pin_complexity: Option<bool>,
    /// How this discovery entry is currently reached (USB CCID, USB HID, or NFC). `transports` lists interfaces the device supports/enables.
    #[serde(default)]
    pub connection: Option<Transport>,
    /// Interfaces the device supports or enables.
    pub transports: Vec<Transport>,
    /// Applications verified as enabled on the current USB configuration.
    pub applications: Vec<Application>,
    /// Applications the device reports it can support, including disabled ones.
    pub supported_applications: Vec<Application>,
    /// True for fixtures. Consumers must clearly distinguish simulated hardware.
    pub simulated: bool,
    /// Whether the current process could read device management metadata.
    #[serde(default)]
    pub metadata_access: MetadataAccess,
    /// PIV operations supported by the vendor implementation. `None` means read-only.
    #[serde(default)]
    pub piv_capabilities: Option<PivCapabilities>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataAccess {
    #[default]
    Unknown,
    Available,
    Restricted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FidoStatus {
    pub versions: Vec<String>,
    pub pin_set: Option<bool>,
    pub pin_retries: Option<i32>,
    pub credential_management: bool,
    #[serde(default)]
    pub fingerprint_enrollment: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Opaque template identifier, hex encoded for CLI and GUI selection.
    pub id: String,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintProgress {
    pub message: String,
    pub remaining_samples: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverableCredential {
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    /// Hex encoded opaque credential identifier; do not infer account identity from it.
    pub credential_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    Connected(DeviceInfo),
    Disconnected(DeviceId),
    Updated(DeviceInfo),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialError {
    #[error("device {0} was not found")]
    DeviceNotFound(String),
    #[error("device was removed during the operation")]
    DeviceRemoved,
    #[error("operation is not supported: {0}")]
    UnsupportedOperation(String),
    #[error("platform backend is unavailable: {0}")]
    BackendUnavailable(String),
    #[error("Windows smart-card service is unavailable: {0}")]
    PcscUnavailable(String),
    #[error("device inventory is unavailable")]
    InventoryUnavailable,
    #[error("FIDO access is restricted; on Windows, run Sigil as administrator")]
    FidoAccessRestricted,
    #[error(
        "This security key has no FIDO PIN yet. Set a FIDO PIN before managing passkeys or fingerprints."
    )]
    FidoPinNotSet,
    #[error("FIDO operation failed: {0}")]
    FidoOperation(String),
    #[error("invalid PIV slot: {0}")]
    InvalidSlot(String),
    #[error("PIV application is not available on this device")]
    PivUnavailable,
    #[error("smart-card operation failed: {0}")]
    SmartCardOperation(String),
    #[error("card returned status {0:04X}")]
    CardStatus(u16),
    #[error("incorrect PIV PIN; {remaining} retries remain")]
    PinIncorrect { remaining: u8 },
    #[error("incorrect PIV PUK; {remaining} retries remain")]
    PukIncorrect { remaining: u8 },
    #[error("PIV PIN is blocked")]
    PinBlocked,
    #[error("PIV PUK is blocked")]
    PukBlocked,
    #[error(
        "The key rejected this PIN as too easy to guess (PIN complexity is enforced). Choose a less common PIN."
    )]
    PinComplexity,
    #[error(
        "The key rejected this PUK as too easy to guess (PIN complexity is enforced). Choose a less common PUK."
    )]
    PukComplexity,
    #[error("managed setup requires the factory-default PUK and management key; reset PIV first")]
    PivNotFactoryDefault,
    #[error("PIV management key is incorrect")]
    ManagementKeyIncorrect,
    #[error("managed PIV rotation {0} is incomplete and requires administrator recovery")]
    ManagedRotationIncomplete(String),
    #[error("device identity does not match")]
    DeviceMismatch,
    #[error(
        "This FIPS YubiKey must be initialized first: change the PIN and PUK to 8-character values and the management key to a new AES key."
    )]
    PivFipsNotApproved,
    #[error("certificate could not be parsed: {0}")]
    CertificateParse(String),
    #[error("slot {0} has no certificate")]
    CertificateNotFound(String),
    #[error("operation unauthorized: {0}")]
    OperationUnauthorized(String),
    #[error("backend rejected the operation: {0}")]
    BackendRejected(String),
    #[error("caller rejected: {0}")]
    CallerRejected(String),
    #[error("Sigil agent is unavailable: {0}")]
    AgentUnavailable(String),
    #[error("the process serving {0} is not the Sigil agent")]
    AgentUntrusted(String),
    #[error("agent protocol {agent} does not match client protocol {client}")]
    ProtocolMismatch { agent: u32, client: u32 },
}

pub type Result<T> = std::result::Result<T, CredentialError>;

/// A snapshot followed by a subscription can have a race; callers should subscribe
/// before fetching a snapshot and reconcile subsequent events by device ID.
pub trait DeviceDiscovery: FidoInspection + PivInspection + Send + Sync {
    fn list(&self) -> Result<Vec<DeviceInfo>>;
    fn subscribe(&self) -> Result<Receiver<DeviceEvent>>;
}

pub trait CredentialDevice: Send + Sync {
    fn info(&self) -> Result<DeviceInfo>;
}

/// A PIV capability is separate from generic credential devices.
pub trait PivDevice: CredentialDevice {
    fn piv_available(&self) -> Result<bool>;
}

pub trait FidoDevice: CredentialDevice {
    fn fido2_available(&self) -> Result<bool>;
}

/// Typed CTAP operations. PINs are supplied in memory and are not persisted.
pub trait FidoInspection: Send + Sync {
    fn fido_status(&self, id: &DeviceId) -> Result<FidoStatus>;
    fn discoverable_credentials(
        &self,
        id: &DeviceId,
        pin: &str,
    ) -> Result<Vec<DiscoverableCredential>>;
    fn fingerprints(&self, id: &DeviceId, pin: &str) -> Result<Vec<Fingerprint>>;
    fn enroll_fingerprint(
        &self,
        id: &DeviceId,
        pin: &str,
        on_progress: &mut dyn FnMut(FingerprintProgress),
    ) -> Result<Fingerprint>;
    fn remove_fingerprint(&self, id: &DeviceId, pin: &str, fingerprint_id: &str) -> Result<()>;
}

pub trait PivInspection: Send + Sync {
    fn piv_info(&self, id: &DeviceId) -> Result<PivInfo>;
    fn piv_slots(&self, id: &DeviceId) -> Result<Vec<PivSlotInfo>>;
    fn piv_certificate(&self, id: &DeviceId, slot: PivSlot) -> Result<Option<PivCertificate>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedPivInitializationOutcome {
    Applied,
    NotApplied,
    Partial,
}

pub trait PivManagement: Send + Sync {
    fn change_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_pin: &PivPin,
        new_pin: &PivPin,
    ) -> Result<()>;

    fn change_puk(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        old_puk: &PivPuk,
        new_puk: &PivPuk,
    ) -> Result<()>;

    fn unblock_pin(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        puk: &PivPuk,
        new_pin: &PivPin,
    ) -> Result<()>;

    fn change_management_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        current: &ManagementKey,
        new: &ManagementKey,
    ) -> Result<()>;

    fn managed_initialize(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        new_management_key: &ManagementKey,
        new_puk: &PivPuk,
    ) -> Result<ManagedPivInitializationOutcome> {
        let _ = (id, expected_serial, new_management_key, new_puk);
        Err(CredentialError::UnsupportedOperation(
            "managed PIV initialization is not implemented".into(),
        ))
    }

    fn generate_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        configuration: PivKeyConfiguration,
    ) -> Result<Vec<u8>>;

    fn attest(&self, id: &DeviceId, expected_serial: &str, slot: PivSlot)
    -> Result<PivAttestation>;

    fn sign_csr(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        pin: &PivPin,
        slot: PivSlot,
        subject_dn: &str,
        expected_public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    fn import_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
        certificate_der: &[u8],
        expected_public_key: Option<&[u8]>,
    ) -> Result<()>;

    fn delete_certificate(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()>;

    fn delete_key(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        management_key: &ManagementKey,
        slot: PivSlot,
    ) -> Result<()>;

    fn reset(&self, id: &DeviceId, expected_serial: &str) -> Result<()>;
}

pub trait DeviceManagement: Send + Sync {
    fn set_enabled_applications(
        &self,
        id: &DeviceId,
        expected_serial: &str,
        usb: &[Application],
        nfc: Option<&[Application]>,
        lock_code: Option<&Secret>,
    ) -> Result<()>;
}
