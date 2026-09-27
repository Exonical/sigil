//! Vendor-neutral credential domain. No transport handles or UI types belong here.

use std::sync::mpsc::Receiver;

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
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
    UnsupportedOperation(&'static str),
    #[error("platform backend is unavailable: {0}")]
    BackendUnavailable(&'static str),
    #[error("Windows smart-card service is unavailable: {0}")]
    PcscUnavailable(String),
    #[error("device inventory is unavailable")]
    InventoryUnavailable,
    #[error("FIDO access is restricted; on Windows, run Sigil as administrator")]
    FidoAccessRestricted,
    #[error("FIDO operation failed: {0}")]
    FidoOperation(String),
}

pub type Result<T> = std::result::Result<T, CredentialError>;

/// A snapshot followed by a subscription can have a race; callers should subscribe
/// before fetching a snapshot and reconcile subsequent events by device ID.
pub trait DeviceDiscovery: FidoInspection + Send + Sync {
    fn list(&self) -> Result<Vec<DeviceInfo>>;
    fn subscribe(&self) -> Result<Receiver<DeviceEvent>>;
}

pub trait CredentialDevice: Send + Sync {
    fn info(&self) -> Result<DeviceInfo>;
}

/// A PIV capability is separate from generic credential devices. Operations will be
/// added with typed slot, algorithm, and authorization types in the PIV milestone.
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
