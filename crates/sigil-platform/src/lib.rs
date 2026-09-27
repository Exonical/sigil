//! Boundary for OS discovery and transport. Native enumeration begins in M2.

use sigil_core::{CredentialError, DeviceDiscovery, DeviceEvent, DeviceInfo, Result};
use std::sync::mpsc::Receiver;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

pub struct NativeDiscovery;

impl DeviceDiscovery for NativeDiscovery {
    fn list(&self) -> Result<Vec<DeviceInfo>> {
        Err(CredentialError::BackendUnavailable(
            "native device discovery is planned for milestone 2",
        ))
    }

    fn subscribe(&self) -> Result<Receiver<DeviceEvent>> {
        Err(CredentialError::BackendUnavailable(
            "native device events are planned for milestone 2",
        ))
    }
}
