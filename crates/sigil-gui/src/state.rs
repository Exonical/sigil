use dioxus::prelude::{ReadableExt, Signal, SyncSignal};
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
            Self::Slots => "YUBICO OTP",
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
pub enum DialogKind {
    ToggleApplications,
    FactoryReset,
    SetupFips,
    Piv(PivAction),
}

#[derive(Clone)]
pub struct AppState {
    pub credentials: CredentialService,
    pub mode: ConnectionMode,
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
    pub fido_status: SyncSignal<Option<(DeviceId, FidoStatus)>>,
    pub passkeys: SyncSignal<Option<(DeviceId, Vec<DiscoverableCredential>)>>,
    pub fingerprints: SyncSignal<Option<(DeviceId, Vec<Fingerprint>)>>,
    pub fips_banner_dismissed: Signal<bool>,
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
