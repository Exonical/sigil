use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{CredentialError, FirmwareVersion};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PivSlot(u8);

impl PivSlot {
    pub const AUTHENTICATION: Self = Self(0x9a);
    pub const SIGNATURE: Self = Self(0x9c);
    pub const KEY_MANAGEMENT: Self = Self(0x9d);
    pub const CARD_AUTHENTICATION: Self = Self(0x9e);
    pub const ATTESTATION: Self = Self(0xf9);
    pub const STANDARD: [Self; 4] = [
        Self::AUTHENTICATION,
        Self::SIGNATURE,
        Self::KEY_MANAGEMENT,
        Self::CARD_AUTHENTICATION,
    ];

    pub fn retired(index: u8) -> Option<Self> {
        (1..=20).contains(&index).then(|| Self(0x81 + index))
    }

    pub fn retired_slots() -> impl Iterator<Item = Self> {
        (1..=20).filter_map(Self::retired)
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        let slot = Self(byte);
        (Self::STANDARD.contains(&slot)
            || Self::retired_slots().any(|retired| retired == slot)
            || slot == Self::ATTESTATION)
            .then_some(slot)
    }

    pub const fn byte(self) -> u8 {
        self.0
    }

    pub fn name(&self) -> String {
        match *self {
            Self::AUTHENTICATION => "Authentication".into(),
            Self::SIGNATURE => "Digital Signature".into(),
            Self::KEY_MANAGEMENT => "Key Management".into(),
            Self::CARD_AUTHENTICATION => "Card Authentication".into(),
            Self::ATTESTATION => "Attestation".into(),
            Self(value) if (0x82..=0x95).contains(&value) => {
                format!("Retired Key Management {}", value - 0x81)
            }
            _ => unreachable!("PivSlot values are validated at construction"),
        }
    }
}

impl FromStr for PivSlot {
    type Err = CredentialError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let normalized = input.trim().to_ascii_lowercase();
        let parsed = match normalized.as_str() {
            "authentication" => Some(Self::AUTHENTICATION),
            "signature" | "digital-signature" => Some(Self::SIGNATURE),
            "key-management" => Some(Self::KEY_MANAGEMENT),
            "card-authentication" => Some(Self::CARD_AUTHENTICATION),
            "attestation" => Some(Self::ATTESTATION),
            _ => {
                if let Some(number) = normalized.strip_prefix("retired") {
                    number.parse::<u8>().ok().and_then(Self::retired)
                } else {
                    let hex = normalized.strip_prefix("0x").unwrap_or(&normalized);
                    u8::from_str_radix(hex, 16).ok().and_then(Self::from_byte)
                }
            }
        };
        parsed.ok_or_else(|| CredentialError::InvalidSlot(input.into()))
    }
}

impl fmt::Display for PivSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:02x}", self.0)
    }
}

impl Serialize for PivSlot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PivSlot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        input.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PivAlgorithm {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
    Ed25519,
    X25519,
    Tdes,
    Aes128,
    Aes192,
    Aes256,
    Unknown(u8),
}

impl fmt::Display for PivAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rsa1024 => "RSA 1024",
            Self::Rsa2048 => "RSA 2048",
            Self::Rsa3072 => "RSA 3072",
            Self::Rsa4096 => "RSA 4096",
            Self::EccP256 => "ECC P-256",
            Self::EccP384 => "ECC P-384",
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
            Self::Tdes => "3DES",
            Self::Aes128 => "AES-128",
            Self::Aes192 => "AES-192",
            Self::Aes256 => "AES-256",
            Self::Unknown(_) => "Unknown",
        })?;
        if let Self::Unknown(value) = self {
            write!(formatter, " ({value:02x})")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinPolicy {
    Default,
    Never,
    Once,
    Always,
    MatchOnce,
    MatchAlways,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TouchPolicy {
    Default,
    Never,
    Always,
    Cached,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PivKeyAlgorithm {
    EccP256,
    EccP384,
}

impl PivKeyAlgorithm {
    pub const fn yubikey_id(self) -> u8 {
        match self {
            Self::EccP256 => 0x11,
            Self::EccP384 => 0x14,
        }
    }

    pub const fn piv_algorithm(self) -> PivAlgorithm {
        match self {
            Self::EccP256 => PivAlgorithm::EccP256,
            Self::EccP384 => PivAlgorithm::EccP384,
        }
    }

    pub const fn digest_len(self) -> usize {
        match self {
            Self::EccP256 => 32,
            Self::EccP384 => 48,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PivKeyConfiguration {
    pub slot: PivSlot,
    pub algorithm: PivKeyAlgorithm,
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrigin {
    Generated,
    Imported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PivKeyMetadata {
    pub algorithm: PivAlgorithm,
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
    pub origin: Option<KeyOrigin>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum KeyStatus {
    Present(PivKeyMetadata),
    Absent,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub public_key_algorithm: Option<PivAlgorithm>,
    pub sha256_fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PivSlotInfo {
    pub slot: PivSlot,
    pub certificate: Option<CertificateSummary>,
    pub key: KeyStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryStatus {
    pub remaining: u8,
    pub total: Option<u8>,
    pub default_value: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementKeyStatus {
    pub algorithm: PivAlgorithm,
    pub default_value: Option<bool>,
    pub touch_policy: Option<TouchPolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PivInfo {
    pub version: Option<FirmwareVersion>,
    pub pin: Option<RetryStatus>,
    pub puk: Option<RetryStatus>,
    pub management_key: Option<ManagementKeyStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PivCertificate {
    pub slot: PivSlot,
    pub summary: CertificateSummary,
    pub der: Vec<u8>,
}

/// The result of checking a PIV attestation chain and the fields it asserts. A failed check is reported here rather
/// than as an error, so the attestation can still be inspected.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AttestationInspection {
    pub verified: bool,
    pub verification_error: Option<String>,
    /// Subject common name of the root the chain verified to.
    pub attestation_root: Option<String>,
    pub attested_serial: Option<u64>,
    pub attested_slot: Option<u8>,
    pub firmware: Option<String>,
    pub pin_policy: Option<u8>,
    pub touch_policy: Option<u8>,
    /// DER SubjectPublicKeyInfo of the attested key.
    pub subject_public_key_info: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PivAttestation {
    pub attestation_der: Vec<u8>,
    pub intermediate_der: Vec<u8>,
    pub inspection: AttestationInspection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateFormat {
    Pem,
    Der,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_displays_and_serializes_slots() {
        for input in [
            "9a",
            "9A",
            "0x9a",
            "authentication",
            "SiGnAtUrE",
            "retired1",
        ] {
            let slot: PivSlot = input.parse().expect("valid slot");
            let json = serde_json::to_string(&slot).expect("serialize slot");
            let restored: PivSlot = serde_json::from_str(&json).expect("deserialize slot");
            assert_eq!(slot, restored);
        }
        assert_eq!(PivSlot::AUTHENTICATION.to_string(), "9a");
        assert_eq!(PivSlot::retired(1), Some(PivSlot(0x82)));
        assert_eq!(PivSlot::retired(20), Some(PivSlot(0x95)));
        assert_eq!(PivSlot::retired(0), None);
        assert_eq!(PivSlot::retired(21), None);
        assert_eq!(
            PivSlot::from_str("key-management").unwrap().name(),
            "Key Management"
        );
        assert_eq!(
            PivSlot::from_str("card-authentication").unwrap().name(),
            "Card Authentication"
        );
        assert_eq!(
            PivSlot::from_str("attestation").unwrap().name(),
            "Attestation"
        );
        assert_eq!(
            PivSlot::from_str("retired20").unwrap().name(),
            "Retired Key Management 20"
        );
        for invalid in ["9b", "80", "81", "96", "garbage"] {
            assert_eq!(
                invalid.parse::<PivSlot>(),
                Err(CredentialError::InvalidSlot(invalid.into()))
            );
        }
    }
}
