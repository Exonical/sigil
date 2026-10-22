use std::collections::HashMap;

use dioxus::prelude::*;
use sigil_app::CredentialService;
use sigil_connect::ConnectionMode;
use sigil_core::{
    DeviceId, DeviceInfo, DiscoverableCredential, FidoStatus, Fingerprint, PivInfo, PivSlot,
    PivSlotInfo,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Home,
    Accounts,
    Passkeys,
    Certificates,
    Slots,
    Settings,
}

impl Page {
    pub fn title(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Accounts => "Accounts",
            Self::Passkeys => "Passkeys",
            Self::Certificates => "Certificates",
            Self::Slots => "Slots",
            Self::Settings => "Settings",
        }
    }

    pub fn application_chip(self) -> &'static str {
        match self {
            Self::Home => "DEVICE",
            Self::Accounts => "OATH",
            Self::Passkeys => "FIDO2",
            Self::Certificates => "PIV",
            Self::Slots => "OTP",
            Self::Settings => "SETTINGS",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PivAction {
    ChangePin,
    ChangePuk,
    UnblockPin,
    ChangeManagementKey,
    GenerateKey(PivSlot),
    ImportCertificate(PivSlot),
    ExportCertificate(PivSlot),
    CreateCsr(PivSlot),
    Attest(PivSlot),
    DeleteCertificate(PivSlot),
    DeleteKey(PivSlot),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedAction {
    Initialize,
    RotatePuk,
    RotateManagementKey,
    UnblockPin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogKind {
    ToggleApplications,
    FactoryReset,
    SetupFips,
    Piv(PivAction),
    Managed(ManagedAction),
    /// Enroll a certificate; the optional slot preselects the matching profile.
    Enroll(Option<PivSlot>),
}

#[derive(Clone)]
pub struct AppState {
    pub credentials: CredentialService,
    pub mode: ConnectionMode,
    /// Where the connected agent writes its log, if it reported one.
    pub agent_log_location: Option<String>,
    pub auth_config: crate::auth::AuthConfig,
    pub auth: SyncSignal<crate::auth::AuthStatus>,
    pub session: SyncSignal<Option<std::sync::Arc<sigil_auth::Session>>>,
    pub auth_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub managed: Option<std::sync::Arc<dyn sigil_connect::ManagedPivAgent>>,
    pub devices: SyncSignal<Vec<DeviceInfo>>,
    pub selected_device: SyncSignal<Option<DeviceId>>,
    pub page: Signal<Page>,
    pub nav_collapsed: Signal<bool>,
    pub panel_collapsed: Signal<bool>,
    pub panel_open: Signal<bool>,
    pub selected_slot: Signal<Option<PivSlot>>,
    pub dialog: SyncSignal<Option<DialogKind>>,
    pub toast: SyncSignal<Option<String>>,
    pub status: SyncSignal<Option<String>>,
    pub piv_info: SyncSignal<Option<(DeviceId, PivInfo)>>,
    pub piv_slots: SyncSignal<Option<(DeviceId, Vec<PivSlotInfo>)>>,
    pub generated_piv_spki: SyncSignal<HashMap<(DeviceId, PivSlot), Vec<u8>>>,
    pub fido_status: SyncSignal<Option<(DeviceId, FidoStatus)>>,
    pub passkeys: SyncSignal<Option<(DeviceId, Vec<DiscoverableCredential>)>>,
    pub fingerprints: SyncSignal<Option<(DeviceId, Vec<Fingerprint>)>>,
    pub fips_banner_dismissed: Signal<bool>,
    /// Certificate profiles the backend offers for a device. Empty when they could not be loaded.
    pub certificate_profiles:
        SyncSignal<Option<(DeviceId, Vec<sigil_connect::CertificateProfile>)>>,
}

impl AppState {
    pub fn current_device(&self) -> Option<DeviceInfo> {
        let devices = self.devices.read();
        self.selected_device
            .read()
            .as_ref()
            .and_then(|selected| devices.iter().find(|device| &device.id == selected))
            .or_else(|| devices.first())
            .cloned()
    }
}

/// Writes a sync signal from a background thread. Unlike set, this does nothing once the
/// window or page that owns the signal is gone, so a late result cannot panic the process.
pub trait SetLive<T> {
    fn set_live(&mut self, value: T);
}

impl<T: Send + Sync + 'static> SetLive<T> for SyncSignal<T> {
    fn set_live(&mut self, value: T) {
        if let Ok(mut current) = self.try_write() {
            *current = value;
        }
    }
}
