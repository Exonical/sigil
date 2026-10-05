//! Protocol definitions, domain conversions, and status mapping for the local agent API.

use prost::Message;
use sigil_core as core;
use tonic::{Code, Status};

pub mod v1 {
    tonic::include_proto!("sigil.agent.v1");
}

fn invalid_proto(detail: impl std::fmt::Display) -> core::CredentialError {
    core::CredentialError::SmartCardOperation(format!("invalid agent protocol value: {detail}"))
}

fn transport_to_proto(value: &core::Transport) -> i32 {
    match value {
        core::Transport::UsbSmartCard => v1::Transport::UsbSmartCard as i32,
        core::Transport::UsbHid => v1::Transport::UsbHid as i32,
        core::Transport::UsbOtp => v1::Transport::UsbOtp as i32,
        core::Transport::Nfc => v1::Transport::Nfc as i32,
    }
}

fn transport_from_proto(value: i32) -> core::Result<core::Transport> {
    match v1::Transport::try_from(value).map_err(|_| invalid_proto(value))? {
        v1::Transport::UsbSmartCard => Ok(core::Transport::UsbSmartCard),
        v1::Transport::UsbHid => Ok(core::Transport::UsbHid),
        v1::Transport::UsbOtp => Ok(core::Transport::UsbOtp),
        v1::Transport::Nfc => Ok(core::Transport::Nfc),
        v1::Transport::Unspecified => Err(invalid_proto("unspecified transport")),
    }
}

fn application_to_proto(value: &core::Application) -> i32 {
    match value {
        core::Application::Piv => v1::Application::Piv as i32,
        core::Application::Fido2 => v1::Application::Fido2 as i32,
        core::Application::U2f => v1::Application::U2f as i32,
        core::Application::Otp => v1::Application::Otp as i32,
        core::Application::OpenPgp => v1::Application::OpenPgp as i32,
        core::Application::Oath => v1::Application::Oath as i32,
    }
}

fn application_from_proto(value: i32) -> core::Result<core::Application> {
    match v1::Application::try_from(value).map_err(|_| invalid_proto(value))? {
        v1::Application::Piv => Ok(core::Application::Piv),
        v1::Application::Fido2 => Ok(core::Application::Fido2),
        v1::Application::U2f => Ok(core::Application::U2f),
        v1::Application::Otp => Ok(core::Application::Otp),
        v1::Application::OpenPgp => Ok(core::Application::OpenPgp),
        v1::Application::Oath => Ok(core::Application::Oath),
        v1::Application::Unspecified => Err(invalid_proto("unspecified application")),
    }
}

impl From<&core::FirmwareVersion> for v1::FirmwareVersion {
    fn from(value: &core::FirmwareVersion) -> Self {
        Self {
            major: u32::from(value.major),
            minor: u32::from(value.minor),
            patch: u32::from(value.patch),
        }
    }
}

impl TryFrom<v1::FirmwareVersion> for core::FirmwareVersion {
    type Error = core::CredentialError;

    fn try_from(value: v1::FirmwareVersion) -> core::Result<Self> {
        Ok(Self {
            major: value
                .major
                .try_into()
                .map_err(|_| invalid_proto("firmware major"))?,
            minor: value
                .minor
                .try_into()
                .map_err(|_| invalid_proto("firmware minor"))?,
            patch: value
                .patch
                .try_into()
                .map_err(|_| invalid_proto("firmware patch"))?,
        })
    }
}

impl From<&core::DeviceInfo> for v1::DeviceInfo {
    fn from(value: &core::DeviceInfo) -> Self {
        Self {
            id: value.id.0.clone(),
            vendor: value.vendor.clone(),
            model: value.model.clone(),
            serial: value.serial.clone(),
            firmware: value.firmware.as_ref().map(Into::into),
            form_factor: value.form_factor.clone(),
            connection: value.connection.as_ref().map(transport_to_proto),
            transports: value.transports.iter().map(transport_to_proto).collect(),
            applications: value
                .applications
                .iter()
                .map(application_to_proto)
                .collect(),
            supported_applications: value
                .supported_applications
                .iter()
                .map(application_to_proto)
                .collect(),
            simulated: value.simulated,
            metadata_access: match value.metadata_access {
                core::MetadataAccess::Unknown => v1::MetadataAccess::Unknown as i32,
                core::MetadataAccess::Available => v1::MetadataAccess::Available as i32,
                core::MetadataAccess::Restricted => v1::MetadataAccess::Restricted as i32,
            },
            fips: value.fips,
        }
    }
}

impl TryFrom<v1::DeviceInfo> for core::DeviceInfo {
    type Error = core::CredentialError;

    fn try_from(value: v1::DeviceInfo) -> core::Result<Self> {
        Ok(Self {
            id: core::DeviceId(value.id),
            vendor: value.vendor,
            model: value.model,
            serial: value.serial,
            firmware: value.firmware.map(TryInto::try_into).transpose()?,
            form_factor: value.form_factor,
            connection: value.connection.map(transport_from_proto).transpose()?,
            transports: value
                .transports
                .into_iter()
                .map(transport_from_proto)
                .collect::<core::Result<_>>()?,
            applications: value
                .applications
                .into_iter()
                .map(application_from_proto)
                .collect::<core::Result<_>>()?,
            supported_applications: value
                .supported_applications
                .into_iter()
                .map(application_from_proto)
                .collect::<core::Result<_>>()?,
            simulated: value.simulated,
            metadata_access: match v1::MetadataAccess::try_from(value.metadata_access)
                .map_err(|_| invalid_proto(value.metadata_access))?
            {
                v1::MetadataAccess::Unknown => core::MetadataAccess::Unknown,
                v1::MetadataAccess::Available => core::MetadataAccess::Available,
                v1::MetadataAccess::Restricted => core::MetadataAccess::Restricted,
            },
            fips: value.fips,
        })
    }
}

impl From<&core::FidoStatus> for v1::FidoStatus {
    fn from(value: &core::FidoStatus) -> Self {
        Self {
            versions: value.versions.clone(),
            pin_set: value.pin_set,
            pin_retries: value.pin_retries,
            credential_management: value.credential_management,
            fingerprint_enrollment: value.fingerprint_enrollment,
        }
    }
}

impl From<v1::FidoStatus> for core::FidoStatus {
    fn from(value: v1::FidoStatus) -> Self {
        Self {
            versions: value.versions,
            pin_set: value.pin_set,
            pin_retries: value.pin_retries,
            credential_management: value.credential_management,
            fingerprint_enrollment: value.fingerprint_enrollment,
        }
    }
}

impl From<&core::Fingerprint> for v1::Fingerprint {
    fn from(value: &core::Fingerprint) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
        }
    }
}

impl From<v1::Fingerprint> for core::Fingerprint {
    fn from(value: v1::Fingerprint) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl From<&core::FingerprintProgress> for v1::FingerprintProgress {
    fn from(value: &core::FingerprintProgress) -> Self {
        Self {
            message: value.message.clone(),
            remaining_samples: value.remaining_samples,
        }
    }
}

impl From<v1::FingerprintProgress> for core::FingerprintProgress {
    fn from(value: v1::FingerprintProgress) -> Self {
        Self {
            message: value.message,
            remaining_samples: value.remaining_samples,
        }
    }
}

impl From<&core::DiscoverableCredential> for v1::DiscoverableCredential {
    fn from(value: &core::DiscoverableCredential) -> Self {
        Self {
            rp_id: value.rp_id.clone(),
            rp_name: value.rp_name.clone(),
            user_name: value.user_name.clone(),
            user_display_name: value.user_display_name.clone(),
            credential_id: value.credential_id.clone(),
        }
    }
}

impl From<v1::DiscoverableCredential> for core::DiscoverableCredential {
    fn from(value: v1::DiscoverableCredential) -> Self {
        Self {
            rp_id: value.rp_id,
            rp_name: value.rp_name,
            user_name: value.user_name,
            user_display_name: value.user_display_name,
            credential_id: value.credential_id,
        }
    }
}

fn algorithm_to_proto(value: core::PivAlgorithm) -> v1::PivAlgorithm {
    use core::PivAlgorithm as A;
    use v1::PivAlgorithmKind as K;
    let (kind, unknown_id) = match value {
        A::Rsa1024 => (K::Rsa1024, 0),
        A::Rsa2048 => (K::Rsa2048, 0),
        A::Rsa3072 => (K::Rsa3072, 0),
        A::Rsa4096 => (K::Rsa4096, 0),
        A::EccP256 => (K::EccP256, 0),
        A::EccP384 => (K::EccP384, 0),
        A::Ed25519 => (K::Ed25519, 0),
        A::X25519 => (K::X25519, 0),
        A::Tdes => (K::Tdes, 0),
        A::Aes128 => (K::Aes128, 0),
        A::Aes192 => (K::Aes192, 0),
        A::Aes256 => (K::Aes256, 0),
        A::Unknown(id) => (K::Unknown, u32::from(id)),
    };
    v1::PivAlgorithm {
        kind: kind as i32,
        unknown_id,
    }
}

fn algorithm_from_proto(value: v1::PivAlgorithm) -> core::Result<core::PivAlgorithm> {
    use core::PivAlgorithm as A;
    use v1::PivAlgorithmKind as K;
    Ok(
        match K::try_from(value.kind).map_err(|_| invalid_proto(value.kind))? {
            K::Rsa1024 => A::Rsa1024,
            K::Rsa2048 => A::Rsa2048,
            K::Rsa3072 => A::Rsa3072,
            K::Rsa4096 => A::Rsa4096,
            K::EccP256 => A::EccP256,
            K::EccP384 => A::EccP384,
            K::Ed25519 => A::Ed25519,
            K::X25519 => A::X25519,
            K::Tdes => A::Tdes,
            K::Aes128 => A::Aes128,
            K::Aes192 => A::Aes192,
            K::Aes256 => A::Aes256,
            K::Unknown => A::Unknown(
                value
                    .unknown_id
                    .try_into()
                    .map_err(|_| invalid_proto("unknown PIV algorithm id"))?,
            ),
            K::Unspecified => return Err(invalid_proto("unspecified PIV algorithm")),
        },
    )
}

fn pin_policy_to_proto(value: core::PinPolicy) -> i32 {
    use core::PinPolicy as P;
    match value {
        P::Default => v1::PinPolicy::Default as i32,
        P::Never => v1::PinPolicy::Never as i32,
        P::Once => v1::PinPolicy::Once as i32,
        P::Always => v1::PinPolicy::Always as i32,
        P::MatchOnce => v1::PinPolicy::MatchOnce as i32,
        P::MatchAlways => v1::PinPolicy::MatchAlways as i32,
    }
}

fn pin_policy_from_proto(value: i32) -> core::Result<core::PinPolicy> {
    use core::PinPolicy as P;
    Ok(
        match v1::PinPolicy::try_from(value).map_err(|_| invalid_proto(value))? {
            v1::PinPolicy::Default => P::Default,
            v1::PinPolicy::Never => P::Never,
            v1::PinPolicy::Once => P::Once,
            v1::PinPolicy::Always => P::Always,
            v1::PinPolicy::MatchOnce => P::MatchOnce,
            v1::PinPolicy::MatchAlways => P::MatchAlways,
            v1::PinPolicy::Unspecified => return Err(invalid_proto("unspecified PIN policy")),
        },
    )
}

fn touch_policy_to_proto(value: core::TouchPolicy) -> i32 {
    use core::TouchPolicy as P;
    match value {
        P::Default => v1::TouchPolicy::Default as i32,
        P::Never => v1::TouchPolicy::Never as i32,
        P::Always => v1::TouchPolicy::Always as i32,
        P::Cached => v1::TouchPolicy::Cached as i32,
    }
}

fn touch_policy_from_proto(value: i32) -> core::Result<core::TouchPolicy> {
    use core::TouchPolicy as P;
    Ok(
        match v1::TouchPolicy::try_from(value).map_err(|_| invalid_proto(value))? {
            v1::TouchPolicy::Default => P::Default,
            v1::TouchPolicy::Never => P::Never,
            v1::TouchPolicy::Always => P::Always,
            v1::TouchPolicy::Cached => P::Cached,
            v1::TouchPolicy::Unspecified => return Err(invalid_proto("unspecified touch policy")),
        },
    )
}

fn key_origin_to_proto(value: core::KeyOrigin) -> i32 {
    match value {
        core::KeyOrigin::Generated => v1::KeyOrigin::Generated as i32,
        core::KeyOrigin::Imported => v1::KeyOrigin::Imported as i32,
    }
}

fn key_origin_from_proto(value: i32) -> core::Result<core::KeyOrigin> {
    match v1::KeyOrigin::try_from(value).map_err(|_| invalid_proto(value))? {
        v1::KeyOrigin::Generated => Ok(core::KeyOrigin::Generated),
        v1::KeyOrigin::Imported => Ok(core::KeyOrigin::Imported),
        v1::KeyOrigin::Unspecified => Err(invalid_proto("unspecified key origin")),
    }
}

impl From<&core::PivKeyMetadata> for v1::PivKeyMetadata {
    fn from(value: &core::PivKeyMetadata) -> Self {
        Self {
            algorithm: Some(algorithm_to_proto(value.algorithm)),
            pin_policy: pin_policy_to_proto(value.pin_policy),
            touch_policy: touch_policy_to_proto(value.touch_policy),
            origin: value.origin.map(key_origin_to_proto),
        }
    }
}

impl TryFrom<v1::PivKeyMetadata> for core::PivKeyMetadata {
    type Error = core::CredentialError;

    fn try_from(value: v1::PivKeyMetadata) -> core::Result<Self> {
        Ok(Self {
            algorithm: algorithm_from_proto(
                value
                    .algorithm
                    .ok_or_else(|| invalid_proto("missing key algorithm"))?,
            )?,
            pin_policy: pin_policy_from_proto(value.pin_policy)?,
            touch_policy: touch_policy_from_proto(value.touch_policy)?,
            origin: value.origin.map(key_origin_from_proto).transpose()?,
        })
    }
}

impl From<&core::KeyStatus> for v1::KeyStatus {
    fn from(value: &core::KeyStatus) -> Self {
        use v1::key_status::Status;
        Self {
            status: Some(match value {
                core::KeyStatus::Present(metadata) => Status::Present(metadata.into()),
                core::KeyStatus::Absent => Status::Absent(true),
                core::KeyStatus::Unknown => Status::Unknown(true),
            }),
        }
    }
}

impl TryFrom<v1::KeyStatus> for core::KeyStatus {
    type Error = core::CredentialError;

    fn try_from(value: v1::KeyStatus) -> core::Result<Self> {
        use v1::key_status::Status;
        match value
            .status
            .ok_or_else(|| invalid_proto("missing key status"))?
        {
            Status::Present(metadata) => Ok(Self::Present(metadata.try_into()?)),
            Status::Absent(_) => Ok(Self::Absent),
            Status::Unknown(_) => Ok(Self::Unknown),
        }
    }
}

impl From<&core::CertificateSummary> for v1::CertificateSummary {
    fn from(value: &core::CertificateSummary) -> Self {
        Self {
            subject: value.subject.clone(),
            issuer: value.issuer.clone(),
            serial: value.serial.clone(),
            not_before: value.not_before.clone(),
            not_after: value.not_after.clone(),
            public_key_algorithm: value.public_key_algorithm.map(algorithm_to_proto),
            sha256_fingerprint: value.sha256_fingerprint.clone(),
        }
    }
}

impl TryFrom<v1::CertificateSummary> for core::CertificateSummary {
    type Error = core::CredentialError;

    fn try_from(value: v1::CertificateSummary) -> core::Result<Self> {
        Ok(Self {
            subject: value.subject,
            issuer: value.issuer,
            serial: value.serial,
            not_before: value.not_before,
            not_after: value.not_after,
            public_key_algorithm: value
                .public_key_algorithm
                .map(algorithm_from_proto)
                .transpose()?,
            sha256_fingerprint: value.sha256_fingerprint,
        })
    }
}

impl From<&core::PivSlotInfo> for v1::PivSlotInfo {
    fn from(value: &core::PivSlotInfo) -> Self {
        Self {
            slot_byte: u32::from(value.slot.byte()),
            certificate: value.certificate.as_ref().map(Into::into),
            key: Some((&value.key).into()),
        }
    }
}

impl TryFrom<v1::PivSlotInfo> for core::PivSlotInfo {
    type Error = core::CredentialError;

    fn try_from(value: v1::PivSlotInfo) -> core::Result<Self> {
        let slot_byte: u8 = value
            .slot_byte
            .try_into()
            .map_err(|_| invalid_proto("PIV slot byte"))?;
        Ok(Self {
            slot: core::PivSlot::from_byte(slot_byte)
                .ok_or_else(|| core::CredentialError::InvalidSlot(slot_byte.to_string()))?,
            certificate: value.certificate.map(TryInto::try_into).transpose()?,
            key: value
                .key
                .ok_or_else(|| invalid_proto("missing key state"))?
                .try_into()?,
        })
    }
}

impl From<&core::RetryStatus> for v1::RetryStatus {
    fn from(value: &core::RetryStatus) -> Self {
        Self {
            remaining: u32::from(value.remaining),
            total: value.total.map(u32::from),
            default_value: value.default_value,
        }
    }
}

impl TryFrom<v1::RetryStatus> for core::RetryStatus {
    type Error = core::CredentialError;

    fn try_from(value: v1::RetryStatus) -> core::Result<Self> {
        Ok(Self {
            remaining: value
                .remaining
                .try_into()
                .map_err(|_| invalid_proto("retry count"))?,
            total: value
                .total
                .map(TryInto::try_into)
                .transpose()
                .map_err(|_| invalid_proto("retry total"))?,
            default_value: value.default_value,
        })
    }
}

impl From<&core::ManagementKeyStatus> for v1::ManagementKeyStatus {
    fn from(value: &core::ManagementKeyStatus) -> Self {
        Self {
            algorithm: Some(algorithm_to_proto(value.algorithm)),
            default_value: value.default_value,
            touch_policy: value.touch_policy.map(touch_policy_to_proto),
        }
    }
}

impl TryFrom<v1::ManagementKeyStatus> for core::ManagementKeyStatus {
    type Error = core::CredentialError;

    fn try_from(value: v1::ManagementKeyStatus) -> core::Result<Self> {
        Ok(Self {
            algorithm: algorithm_from_proto(
                value
                    .algorithm
                    .ok_or_else(|| invalid_proto("missing management-key algorithm"))?,
            )?,
            default_value: value.default_value,
            touch_policy: value
                .touch_policy
                .map(touch_policy_from_proto)
                .transpose()?,
        })
    }
}

impl From<&core::PivInfo> for v1::PivInfo {
    fn from(value: &core::PivInfo) -> Self {
        Self {
            version: value.version.as_ref().map(Into::into),
            pin: value.pin.as_ref().map(Into::into),
            puk: value.puk.as_ref().map(Into::into),
            management_key: value.management_key.as_ref().map(Into::into),
        }
    }
}

impl TryFrom<v1::PivInfo> for core::PivInfo {
    type Error = core::CredentialError;

    fn try_from(value: v1::PivInfo) -> core::Result<Self> {
        Ok(Self {
            version: value.version.map(TryInto::try_into).transpose()?,
            pin: value.pin.map(TryInto::try_into).transpose()?,
            puk: value.puk.map(TryInto::try_into).transpose()?,
            management_key: value.management_key.map(TryInto::try_into).transpose()?,
        })
    }
}

impl From<&core::DeviceEvent> for v1::DeviceEvent {
    fn from(value: &core::DeviceEvent) -> Self {
        use v1::device_event::Event;
        Self {
            event: Some(match value {
                core::DeviceEvent::Connected(device) => Event::Connected(device.into()),
                core::DeviceEvent::Updated(device) => Event::Updated(device.into()),
                core::DeviceEvent::Disconnected(id) => Event::DisconnectedId(id.0.clone()),
            }),
        }
    }
}

impl TryFrom<v1::DeviceEvent> for core::DeviceEvent {
    type Error = core::CredentialError;

    fn try_from(value: v1::DeviceEvent) -> core::Result<Self> {
        use v1::device_event::Event;
        match value
            .event
            .ok_or_else(|| invalid_proto("missing device event"))?
        {
            Event::Connected(device) => Ok(Self::Connected(device.try_into()?)),
            Event::Updated(device) => Ok(Self::Updated(device.try_into()?)),
            Event::DisconnectedId(id) => Ok(Self::Disconnected(core::DeviceId(id))),
        }
    }
}

fn agent_error(value: &core::CredentialError) -> v1::AgentError {
    let (kind, detail) = match value {
        core::CredentialError::DeviceNotFound(detail) => (1, detail.clone()),
        core::CredentialError::DeviceRemoved => (2, String::new()),
        core::CredentialError::UnsupportedOperation(detail) => (3, detail.clone()),
        core::CredentialError::BackendUnavailable(detail) => (4, detail.clone()),
        core::CredentialError::PcscUnavailable(detail) => (5, detail.clone()),
        core::CredentialError::InventoryUnavailable => (6, String::new()),
        core::CredentialError::FidoAccessRestricted => (7, String::new()),
        core::CredentialError::FidoPinNotSet => (20, String::new()),
        core::CredentialError::FidoOperation(detail) => (8, detail.clone()),
        core::CredentialError::InvalidSlot(detail) => (9, detail.clone()),
        core::CredentialError::PivUnavailable => (10, String::new()),
        core::CredentialError::SmartCardOperation(detail) => (11, detail.clone()),
        core::CredentialError::CardStatus(status) => (12, format!("{status:04X}")),
        core::CredentialError::CertificateParse(detail) => (13, detail.clone()),
        core::CredentialError::CertificateNotFound(detail) => (14, detail.clone()),
        core::CredentialError::OperationUnauthorized(detail) => (15, detail.clone()),
        core::CredentialError::CallerRejected(detail) => (16, detail.clone()),
        core::CredentialError::AgentUnavailable(detail) => (17, detail.clone()),
        core::CredentialError::ProtocolMismatch { agent, client } => {
            (18, format!("{agent}:{client}"))
        }
        core::CredentialError::AgentUntrusted(detail) => (19, detail.clone()),
        core::CredentialError::PinIncorrect { remaining } => (21, remaining.to_string()),
        core::CredentialError::PukIncorrect { remaining } => (22, remaining.to_string()),
        core::CredentialError::PinBlocked => (23, String::new()),
        core::CredentialError::PukBlocked => (24, String::new()),
        core::CredentialError::ManagementKeyIncorrect => (25, String::new()),
        core::CredentialError::DeviceMismatch => (26, String::new()),
        core::CredentialError::PivFipsNotApproved => (27, String::new()),
    };
    v1::AgentError { kind, detail }
}

fn credential_error(value: v1::AgentError) -> core::CredentialError {
    match value.kind {
        1 => core::CredentialError::DeviceNotFound(value.detail),
        2 => core::CredentialError::DeviceRemoved,
        3 => core::CredentialError::UnsupportedOperation(value.detail),
        4 => core::CredentialError::BackendUnavailable(value.detail),
        5 => core::CredentialError::PcscUnavailable(value.detail),
        6 => core::CredentialError::InventoryUnavailable,
        7 => core::CredentialError::FidoAccessRestricted,
        20 => core::CredentialError::FidoPinNotSet,
        8 => core::CredentialError::FidoOperation(value.detail),
        9 => core::CredentialError::InvalidSlot(value.detail),
        10 => core::CredentialError::PivUnavailable,
        11 => core::CredentialError::SmartCardOperation(value.detail),
        12 => core::CredentialError::CardStatus(
            u16::from_str_radix(&value.detail, 16).unwrap_or_default(),
        ),
        13 => core::CredentialError::CertificateParse(value.detail),
        14 => core::CredentialError::CertificateNotFound(value.detail),
        15 => core::CredentialError::OperationUnauthorized(value.detail),
        16 => core::CredentialError::CallerRejected(value.detail),
        17 => core::CredentialError::AgentUnavailable(value.detail),
        18 => {
            let (agent, client) = value.detail.split_once(':').unwrap_or(("0", "0"));
            core::CredentialError::ProtocolMismatch {
                agent: agent.parse().unwrap_or_default(),
                client: client.parse().unwrap_or_default(),
            }
        }
        19 => core::CredentialError::AgentUntrusted(value.detail),
        21 => core::CredentialError::PinIncorrect {
            remaining: value.detail.parse().unwrap_or_default(),
        },
        22 => core::CredentialError::PukIncorrect {
            remaining: value.detail.parse().unwrap_or_default(),
        },
        23 => core::CredentialError::PinBlocked,
        24 => core::CredentialError::PukBlocked,
        25 => core::CredentialError::ManagementKeyIncorrect,
        26 => core::CredentialError::DeviceMismatch,
        27 => core::CredentialError::PivFipsNotApproved,
        _ => core::CredentialError::AgentUnavailable("agent returned an unknown error".into()),
    }
}

fn status_code(value: &core::CredentialError) -> Code {
    match value {
        core::CredentialError::DeviceNotFound(_)
        | core::CredentialError::CertificateNotFound(_) => Code::NotFound,
        core::CredentialError::DeviceRemoved
        | core::CredentialError::BackendUnavailable(_)
        | core::CredentialError::PcscUnavailable(_)
        | core::CredentialError::AgentUnavailable(_) => Code::Unavailable,
        core::CredentialError::UnsupportedOperation(_) => Code::Unimplemented,
        core::CredentialError::InventoryUnavailable
        | core::CredentialError::SmartCardOperation(_) => Code::Internal,
        core::CredentialError::FidoAccessRestricted
        | core::CredentialError::OperationUnauthorized(_)
        | core::CredentialError::CallerRejected(_)
        | core::CredentialError::AgentUntrusted(_) => Code::PermissionDenied,
        core::CredentialError::FidoOperation(_)
        | core::CredentialError::FidoPinNotSet
        | core::CredentialError::PivUnavailable
        | core::CredentialError::CardStatus(_)
        | core::CredentialError::PinIncorrect { .. }
        | core::CredentialError::PukIncorrect { .. }
        | core::CredentialError::PinBlocked
        | core::CredentialError::PukBlocked
        | core::CredentialError::ManagementKeyIncorrect
        | core::CredentialError::DeviceMismatch
        | core::CredentialError::PivFipsNotApproved => Code::FailedPrecondition,
        core::CredentialError::InvalidSlot(_) => Code::InvalidArgument,
        core::CredentialError::CertificateParse(_) => Code::DataLoss,
        core::CredentialError::ProtocolMismatch { .. } => Code::FailedPrecondition,
    }
}

pub fn status_from_error(error: &core::CredentialError) -> Status {
    let details = agent_error(error).encode_to_vec();
    Status::with_details(
        status_code(error),
        error.to_string(),
        bytes::Bytes::from(details),
    )
}

pub fn error_from_status(status: &Status) -> core::CredentialError {
    v1::AgentError::decode(status.details())
        .map(credential_error)
        .unwrap_or_else(|_| core::CredentialError::AgentUnavailable(status.message().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        Application, DeviceId, FirmwareVersion, KeyOrigin, KeyStatus, ManagementKeyStatus,
        MetadataAccess, PinPolicy, PivAlgorithm, PivInfo, PivKeyMetadata, PivSlot, PivSlotInfo,
        RetryStatus, TouchPolicy, Transport,
    };
    use sigil_core as core;

    fn device() -> core::DeviceInfo {
        core::DeviceInfo {
            id: DeviceId("device-123".into()),
            vendor: "Yubico".into(),
            model: "YubiKey".into(),
            serial: Some("123".into()),
            firmware: Some(FirmwareVersion {
                major: 5,
                minor: 7,
                patch: 1,
            }),
            form_factor: Some("USB-C".into()),
            fips: Some(true),
            connection: Some(Transport::UsbSmartCard),
            transports: vec![Transport::UsbSmartCard, Transport::Nfc],
            applications: vec![Application::Piv, Application::Fido2],
            supported_applications: vec![Application::Piv, Application::Fido2, Application::Otp],
            simulated: false,
            metadata_access: MetadataAccess::Available,
        }
    }

    fn summary() -> core::CertificateSummary {
        core::CertificateSummary {
            subject: "CN=test".into(),
            issuer: "CN=issuer".into(),
            serial: "01ab".into(),
            not_before: "2025-01-01T00:00:00Z".into(),
            not_after: "2035-01-01T00:00:00Z".into(),
            public_key_algorithm: Some(PivAlgorithm::EccP256),
            sha256_fingerprint: "00".repeat(32),
        }
    }

    #[test]
    fn device_info_round_trips() {
        let value = device();
        assert_eq!(
            core::DeviceInfo::try_from(v1::DeviceInfo::from(&value)).unwrap(),
            value
        );
    }

    #[test]
    fn piv_slot_info_round_trips_every_key_state() {
        let metadata = PivKeyMetadata {
            algorithm: PivAlgorithm::Unknown(0x77),
            pin_policy: PinPolicy::MatchOnce,
            touch_policy: TouchPolicy::Cached,
            origin: Some(KeyOrigin::Imported),
        };
        for key in [
            KeyStatus::Present(metadata),
            KeyStatus::Absent,
            KeyStatus::Unknown,
        ] {
            let value = PivSlotInfo {
                slot: PivSlot::AUTHENTICATION,
                certificate: Some(summary()),
                key,
            };
            assert_eq!(
                core::PivSlotInfo::try_from(v1::PivSlotInfo::from(&value)).unwrap(),
                value
            );
        }
    }

    #[test]
    fn piv_info_and_fido_status_round_trip() {
        let piv = PivInfo {
            version: Some(FirmwareVersion {
                major: 5,
                minor: 7,
                patch: 1,
            }),
            pin: Some(RetryStatus {
                remaining: 3,
                total: Some(3),
                default_value: Some(false),
            }),
            puk: None,
            management_key: Some(ManagementKeyStatus {
                algorithm: PivAlgorithm::Aes192,
                default_value: Some(false),
                touch_policy: Some(TouchPolicy::Never),
            }),
        };
        assert_eq!(
            core::PivInfo::try_from(v1::PivInfo::from(&piv)).unwrap(),
            piv
        );
        let fido = core::FidoStatus {
            versions: vec!["FIDO_2_1".into()],
            pin_set: Some(true),
            pin_retries: Some(8),
            credential_management: true,
            fingerprint_enrollment: true,
        };
        assert_eq!(core::FidoStatus::from(v1::FidoStatus::from(&fido)), fido);
    }

    #[test]
    fn every_credential_error_round_trips_through_status_details() {
        let errors = vec![
            core::CredentialError::DeviceNotFound("id".into()),
            core::CredentialError::DeviceRemoved,
            core::CredentialError::UnsupportedOperation("operation".into()),
            core::CredentialError::BackendUnavailable("backend".into()),
            core::CredentialError::PcscUnavailable("pcsc".into()),
            core::CredentialError::InventoryUnavailable,
            core::CredentialError::FidoAccessRestricted,
            core::CredentialError::FidoPinNotSet,
            core::CredentialError::PinIncorrect { remaining: 2 },
            core::CredentialError::PukIncorrect { remaining: 4 },
            core::CredentialError::PinBlocked,
            core::CredentialError::PukBlocked,
            core::CredentialError::ManagementKeyIncorrect,
            core::CredentialError::FidoOperation("fido".into()),
            core::CredentialError::InvalidSlot("bad".into()),
            core::CredentialError::PivUnavailable,
            core::CredentialError::SmartCardOperation("card".into()),
            core::CredentialError::CardStatus(0x6a82),
            core::CredentialError::CertificateParse("der".into()),
            core::CredentialError::CertificateNotFound("9a".into()),
            core::CredentialError::OperationUnauthorized("denied".into()),
            core::CredentialError::CallerRejected("sid".into()),
            core::CredentialError::AgentUnavailable("pipe".into()),
            core::CredentialError::AgentUntrusted("pipe".into()),
            core::CredentialError::ProtocolMismatch {
                agent: 2,
                client: 1,
            },
            core::CredentialError::PinIncorrect { remaining: 2 },
            core::CredentialError::PukIncorrect { remaining: 4 },
            core::CredentialError::PinBlocked,
            core::CredentialError::PukBlocked,
            core::CredentialError::ManagementKeyIncorrect,
            core::CredentialError::DeviceMismatch,
            core::CredentialError::PivFipsNotApproved,
        ];
        for error in errors {
            let status = status_from_error(&error);
            assert_eq!(error_from_status(&status), error);
            if error == core::CredentialError::FidoPinNotSet {
                assert_eq!(status.code(), Code::FailedPrecondition);
                assert_eq!(status.message(), error.to_string());
            }
            if matches!(
                error,
                core::CredentialError::PinIncorrect { .. }
                    | core::CredentialError::PukIncorrect { .. }
                    | core::CredentialError::PinBlocked
                    | core::CredentialError::PukBlocked
                    | core::CredentialError::ManagementKeyIncorrect
                    | core::CredentialError::DeviceMismatch
                    | core::CredentialError::PivFipsNotApproved
            ) {
                assert_eq!(status.code(), Code::FailedPrecondition);
            }
        }
    }
}
