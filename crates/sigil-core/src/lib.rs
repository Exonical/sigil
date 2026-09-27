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
    pub transports: Vec<Transport>,
    pub applications: Vec<Application>,
    /// True for fixtures. Consumers must clearly distinguish simulated hardware.
    pub simulated: bool,
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
    #[error("device inventory is unavailable")]
    InventoryUnavailable,
}

pub type Result<T> = std::result::Result<T, CredentialError>;

/// A snapshot followed by a subscription can have a race; callers should subscribe
/// before fetching a snapshot and reconcile subsequent events by device ID.
pub trait DeviceDiscovery: Send + Sync {
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
