//! Hooks for the parts of PIV that SP 800-73 does not define. Everything the standard covers is written once in
//! `ops`; a vendor overrides only what its card implements differently or in addition.

use sigil_core::{
    CredentialError, DeviceInfo, KeyStatus, ManagementKey, PinPolicy, PivAttestation, PivInfo,
    PivPuk, PivSlot, Result, RetryStatus,
};

use crate::{CardTransport, pin_retries, select};

/// What a vendor's card supports beyond the standard read path. Operations gated on a capability fail before any
/// APDU is sent when it is false.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PivCapabilities {
    /// SP 800-73 write operations: PIN and PUK change, unblock, key generation, signing, certificate import and delete.
    pub piv_writes: bool,
    /// Per-slot key metadata, when the vendor reports it.
    pub key_metadata: bool,
    /// Non-default PIN and touch policies at key generation.
    pub pin_touch_policy: bool,
    pub set_management_key: bool,
    pub attestation: bool,
    pub delete_key: bool,
    pub reset: bool,
    /// Resetting a factory-default token to a managed management key and PUK.
    pub factory_initialize: bool,
}

pub(crate) fn unsupported(vendor: &str, operation: &str) -> CredentialError {
    CredentialError::UnsupportedOperation(format!("{operation} not supported on {vendor} tokens"))
}

pub trait PivVendor: Send + Sync {
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> PivCapabilities {
        PivCapabilities::default()
    }

    /// Reads the serial the token reports and checks it against `expected`. Runs inside the caller's transaction and
    /// leaves PIV selected.
    fn verify_serial(&self, transport: &mut dyn CardTransport, expected: &str) -> Result<String>;

    fn info(&self, transport: &mut dyn CardTransport) -> Result<PivInfo> {
        standard_info(transport)
    }

    fn listed_slots(&self) -> Vec<PivSlot> {
        let mut slots = PivSlot::STANDARD.to_vec();
        slots.extend(PivSlot::retired_slots());
        slots
    }

    fn slot_key_status(
        &self,
        _transport: &mut dyn CardTransport,
        _slot: PivSlot,
    ) -> Result<KeyStatus> {
        Ok(KeyStatus::Unknown)
    }

    /// The slot's public key as SubjectPublicKeyInfo DER, when the token can report it.
    fn slot_public_key(
        &self,
        _transport: &mut dyn CardTransport,
        _slot: PivSlot,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// Sets the management key. The caller has already authenticated with the current key.
    fn set_management_key(
        &self,
        _transport: &mut dyn CardTransport,
        _new_key: &ManagementKey,
    ) -> Result<()> {
        Err(unsupported(self.name(), "set management key"))
    }

    fn attest(&self, _transport: &mut dyn CardTransport, _slot: PivSlot) -> Result<PivAttestation> {
        Err(unsupported(self.name(), "attestation"))
    }

    /// Deletes a key. The caller has already authenticated with the management key.
    fn delete_key(&self, _transport: &mut dyn CardTransport, _slot: PivSlot) -> Result<()> {
        Err(unsupported(self.name(), "key delete"))
    }

    fn reset(&self, _transport: &mut dyn CardTransport) -> Result<()> {
        Err(unsupported(self.name(), "reset"))
    }

    /// The factory management key for a token whose info shows factory defaults.
    fn factory_management_key(&self, _info: &PivInfo) -> Result<ManagementKey> {
        Err(unsupported(self.name(), "factory initialization"))
    }

    fn factory_puk(&self) -> Result<PivPuk> {
        Err(unsupported(self.name(), "factory initialization"))
    }

    fn is_factory_default(&self, _info: &PivInfo) -> bool {
        false
    }

    /// Vendor rules for a PIN or PUK being set on this device.
    fn validate_new_code(&self, _device: &DeviceInfo, _code: &[u8]) -> Result<()> {
        Ok(())
    }

    fn validate_pin_policy(&self, _device: &DeviceInfo, _policy: PinPolicy) -> Result<()> {
        Ok(())
    }

    /// Whether an import writes a CHUID when the token has none. SP 800-73-4 expects one before certificates are
    /// stored; tokens that only read CHUIDs leave this off.
    fn ensure_chuid_on_import(&self) -> bool {
        false
    }

    /// Maps a vendor-specific status from a write to a domain error.
    fn map_error(&self, _device: &DeviceInfo, error: CredentialError) -> CredentialError {
        error
    }
}

/// SP 800-73 read of the PIV PIN retry counter. The PUK and management key are not read.
pub fn standard_info(transport: &mut dyn CardTransport) -> Result<PivInfo> {
    select(transport)?;
    let pin = pin_retries(transport)?.map(|remaining| RetryStatus {
        remaining,
        total: None,
        default_value: None,
    });
    Ok(PivInfo {
        version: None,
        pin,
        puk: None,
        management_key: None,
    })
}
