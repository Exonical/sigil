use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{CredentialError, PivAlgorithm, Result};

pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl Eq for Secret {}

#[derive(Debug, PartialEq, Eq)]
pub struct PivPin(Secret);

impl PivPin {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let secret = Secret::new(bytes);
        if valid_piv_code(secret.expose()) {
            Ok(Self(secret))
        } else {
            Err(CredentialError::SmartCardOperation(
                "PIV PIN must be 6 to 8 characters".into(),
            ))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.expose()
    }

    pub fn padded(&self) -> Zeroizing<[u8; 8]> {
        pad_piv_code(self.as_bytes())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PivPuk(Secret);

impl PivPuk {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let secret = Secret::new(bytes);
        if valid_piv_code(secret.expose()) {
            Ok(Self(secret))
        } else {
            Err(CredentialError::SmartCardOperation(
                "PIV PUK must be 6 to 8 characters".into(),
            ))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.expose()
    }

    pub fn padded(&self) -> Zeroizing<[u8; 8]> {
        pad_piv_code(self.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementKeyAlgorithm {
    Aes128,
    Aes192,
    Aes256,
}

impl ManagementKeyAlgorithm {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    pub fn from_piv_algorithm(algorithm: PivAlgorithm) -> Result<Self> {
        match algorithm {
            PivAlgorithm::Aes128 => Ok(Self::Aes128),
            PivAlgorithm::Aes192 => Ok(Self::Aes192),
            PivAlgorithm::Aes256 => Ok(Self::Aes256),
            PivAlgorithm::Tdes => Err(CredentialError::UnsupportedOperation(
                "3DES management keys are not supported".into(),
            )),
            _ => Err(CredentialError::UnsupportedOperation(
                "management key algorithm is not AES".into(),
            )),
        }
    }

    pub const fn piv_algorithm(self) -> PivAlgorithm {
        match self {
            Self::Aes128 => PivAlgorithm::Aes128,
            Self::Aes192 => PivAlgorithm::Aes192,
            Self::Aes256 => PivAlgorithm::Aes256,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ManagementKey {
    algorithm: ManagementKeyAlgorithm,
    key: Secret,
}

impl ManagementKey {
    pub fn new(algorithm: ManagementKeyAlgorithm, key: Vec<u8>) -> Result<Self> {
        let secret = Secret::new(key);
        if secret.expose().len() != algorithm.key_len() {
            return Err(CredentialError::SmartCardOperation(
                "management key length does not match its AES algorithm".into(),
            ));
        }
        Ok(Self {
            algorithm,
            key: secret,
        })
    }

    pub fn algorithm(&self) -> ManagementKeyAlgorithm {
        self.algorithm
    }

    pub fn key(&self) -> &Secret {
        &self.key
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.key.expose()
    }
}

fn valid_piv_code(bytes: &[u8]) -> bool {
    (6..=8).contains(&bytes.len()) && bytes.is_ascii()
}

fn pad_piv_code(bytes: &[u8]) -> Zeroizing<[u8; 8]> {
    let mut padded = Zeroizing::new([0xff; 8]);
    padded[..bytes.len()].copy_from_slice(bytes);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_pads_pin_and_puk_without_exposing_debug_values() {
        let pin = PivPin::new(b"123456".to_vec()).unwrap();
        let puk = PivPuk::new(b"12345678".to_vec()).unwrap();
        assert_eq!(pin.padded().as_slice(), b"123456\xff\xff");
        assert_eq!(puk.padded().as_slice(), b"12345678");
        assert!(!format!("{pin:?}").contains("123456"));
        assert!(!format!("{puk:?}").contains("12345678"));
        for value in [b"12345".as_slice(), b"123456789", b"12345\xff"] {
            assert!(
                PivPin::new(value.to_vec())
                    .unwrap_err()
                    .to_string()
                    .contains("PIV PIN must be 6 to 8 characters")
            );
            assert!(
                PivPuk::new(value.to_vec())
                    .unwrap_err()
                    .to_string()
                    .contains("PIV PUK must be 6 to 8 characters")
            );
        }
    }

    #[test]
    fn management_keys_require_the_algorithm_length_and_reject_tdes() {
        for (algorithm, size) in [
            (ManagementKeyAlgorithm::Aes128, 16),
            (ManagementKeyAlgorithm::Aes192, 24),
            (ManagementKeyAlgorithm::Aes256, 32),
        ] {
            let key = ManagementKey::new(algorithm, vec![0x5a; size]).unwrap();
            assert_eq!(key.as_bytes().len(), size);
            assert!(!format!("{key:?}").contains("5a"));
        }
        assert!(ManagementKey::new(ManagementKeyAlgorithm::Aes192, vec![0; 16]).is_err());
        assert!(matches!(
            ManagementKeyAlgorithm::from_piv_algorithm(PivAlgorithm::Tdes),
            Err(CredentialError::UnsupportedOperation(_))
        ));
    }
}
