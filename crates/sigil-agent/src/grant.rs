#[cfg(feature = "dev-grants")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use p256::ecdsa::Signature;
#[cfg(any(feature = "dev-grants", test))]
use p256::ecdsa::SigningKey;
#[cfg(feature = "dev-grants")]
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{VerifyingKey, signature::Verifier};
#[cfg(feature = "dev-grants")]
use p256::pkcs8::DecodePrivateKey;
use prost::Message;
use sigil_core::{CredentialError, Result};
use sigil_proto::v1::{Operation, OperationGrant, SignedGrant};

const CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_GRANT_LIFETIME_SECONDS: i64 = 300;
#[cfg(feature = "dev-grants")]
static NEXT_DEV_GRANT: AtomicU64 = AtomicU64::new(1);

type GrantResult<T> = std::result::Result<T, CredentialError>;

#[derive(Clone, Debug)]
pub struct GrantExpectation {
    pub operation: Operation,
    pub station_id: String,
    pub token_serial: String,
    pub caller_os_user: Option<String>,
    pub piv_slot: Option<u8>,
}

#[derive(Default)]
struct ReplaySet(HashMap<String, i64>);

pub struct GrantVerifier {
    trusted_keys: HashMap<String, VerifyingKey>,
    used_grants: Arc<Mutex<ReplaySet>>,
}

impl GrantVerifier {
    pub fn new(trusted_keys: HashMap<String, VerifyingKey>) -> Self {
        Self {
            trusted_keys,
            used_grants: Arc::new(Mutex::new(ReplaySet::default())),
        }
    }

    pub fn verify(
        &self,
        signed: &SignedGrant,
        expected: &GrantExpectation,
        now: i64,
    ) -> GrantResult<OperationGrant> {
        let key = self
            .trusted_keys
            .get(&signed.key_id)
            .ok_or_else(|| unauthorized("grant signing key is not trusted"))?;
        let signature = Signature::from_der(&signed.signature)
            .map_err(|_| unauthorized("grant signature is invalid"))?;
        key.verify(&signed.grant, &signature)
            .map_err(|_| unauthorized("grant signature is invalid"))?;

        let grant = OperationGrant::decode(signed.grant.as_slice())
            .map_err(|_| unauthorized("signed grant is not a valid protobuf"))?;
        if grant.version != 1 {
            return Err(unauthorized("unsupported grant version"));
        }
        let operation = Operation::try_from(grant.operation)
            .map_err(|_| unauthorized("unknown grant operation"))?;
        if operation == Operation::Unspecified || operation != expected.operation {
            return Err(unauthorized("grant operation does not match the request"));
        }
        let lifetime = grant
            .expires_at_unix
            .checked_sub(grant.not_before_unix)
            .ok_or_else(|| unauthorized("grant validity interval is invalid"))?;
        if !(0..=MAX_GRANT_LIFETIME_SECONDS).contains(&lifetime) {
            return Err(unauthorized("grant lifetime exceeds 300 seconds"));
        }
        if now < grant.not_before_unix.saturating_sub(CLOCK_SKEW_SECONDS)
            || now > grant.expires_at_unix.saturating_add(CLOCK_SKEW_SECONDS)
        {
            return Err(unauthorized("grant is not currently valid"));
        }
        if grant.station_id != expected.station_id {
            return Err(unauthorized("grant station does not match this agent"));
        }
        if grant.token_serial != expected.token_serial {
            return Err(unauthorized("grant token serial does not match the device"));
        }
        if !grant.caller_os_user.is_empty()
            && expected.caller_os_user.as_deref() != Some(grant.caller_os_user.as_str())
        {
            return Err(unauthorized(
                "grant caller does not match the connected user",
            ));
        }
        let expected_slot = expected.piv_slot.map(u32::from).unwrap_or_default();
        if grant.piv_slot != expected_slot {
            return Err(unauthorized("grant PIV slot does not match the request"));
        }
        if grant.grant_id.is_empty() {
            return Err(unauthorized("grant ID is empty"));
        }

        let mut used = self
            .used_grants
            .lock()
            .map_err(|_| unauthorized("grant replay cache is unavailable"))?;
        used.0
            .retain(|_, expires| expires.saturating_add(CLOCK_SKEW_SECONDS) >= now);
        if used.0.contains_key(&grant.grant_id) {
            return Err(unauthorized("grant has already been used"));
        }
        used.0.insert(grant.grant_id.clone(), grant.expires_at_unix);
        Ok(grant)
    }
}

fn unauthorized(message: &str) -> CredentialError {
    CredentialError::OperationUnauthorized(message.into())
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
pub struct GrantRequest {
    pub operation: Operation,
    pub station_id: String,
    pub token_serial: String,
    pub caller_os_user: String,
    pub piv_slot: Option<u8>,
}

pub trait GrantProvider: Send + Sync {
    fn obtain(
        &self,
        caller: &crate::caller::CallerIdentity,
        request: &GrantRequest,
    ) -> Result<SignedGrant>;
}

#[derive(Default)]
pub struct Unconfigured;

impl GrantProvider for Unconfigured {
    fn obtain(
        &self,
        _caller: &crate::caller::CallerIdentity,
        _request: &GrantRequest,
    ) -> Result<SignedGrant> {
        Err(CredentialError::OperationUnauthorized(
            "backend authorization is not configured".into(),
        ))
    }
}

#[cfg(feature = "dev-grants")]
#[cfg(not(debug_assertions))]
compile_error!("the dev-grants feature must never be enabled in release builds");

#[cfg(feature = "dev-grants")]
pub struct DevSigner {
    station_id: String,
    key_id: String,
    signing_key: SigningKey,
}

#[cfg(feature = "dev-grants")]
impl DevSigner {
    pub fn from_pem_path(
        station_id: impl Into<String>,
        key_id: impl Into<String>,
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        let pem = std::fs::read_to_string(path.as_ref()).map_err(|error| {
            CredentialError::OperationUnauthorized(format!(
                "could not read development grant key: {error}"
            ))
        })?;
        let signing_key = SigningKey::from_pkcs8_pem(&pem).map_err(|error| {
            CredentialError::OperationUnauthorized(format!(
                "invalid development grant key: {error}"
            ))
        })?;
        Ok(Self {
            station_id: station_id.into(),
            key_id: key_id.into(),
            signing_key,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }
}

#[cfg(feature = "dev-grants")]
impl GrantProvider for DevSigner {
    fn obtain(
        &self,
        caller: &crate::caller::CallerIdentity,
        request: &GrantRequest,
    ) -> Result<SignedGrant> {
        tracing::warn!(target: "sigil::audit", grant_key_id = %self.key_id, "DEVELOPMENT grant signer used");
        let now = now_unix();
        let grant = OperationGrant {
            version: 1,
            grant_id: format!(
                "dev-{}-{}",
                now,
                NEXT_DEV_GRANT.fetch_add(1, Ordering::Relaxed)
            ),
            operation: request.operation as i32,
            subject: caller.os_user.clone(),
            station_id: self.station_id.clone(),
            token_serial: request.token_serial.clone(),
            caller_os_user: request.caller_os_user.clone(),
            not_before_unix: now,
            expires_at_unix: now + 120,
            piv_slot: request.piv_slot.map(u32::from).unwrap_or_default(),
        };
        let bytes = grant.encode_to_vec();
        let signature: Signature = self.signing_key.sign(&bytes);
        Ok(SignedGrant {
            grant: bytes,
            signature: signature.to_der().as_bytes().to_vec(),
            key_id: self.key_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePublicKey;
    use serde::Deserialize;
    use sigil_proto::v1::Operation;

    const NOW: i64 = 1_750_000_000;
    const KEY_ID: &str = "test-key";

    fn key() -> SigningKey {
        SigningKey::from_bytes((&[7u8; 32]).into()).expect("test signing key")
    }

    fn expectation(operation: Operation) -> GrantExpectation {
        GrantExpectation {
            operation,
            station_id: "station-1".into(),
            token_serial: "12345678".into(),
            caller_os_user: Some("S-1-5-21-test".into()),
            piv_slot: matches!(
                operation,
                Operation::PivGenerateKey
                    | Operation::PivImportCertificate
                    | Operation::PivDeleteCertificate
                    | Operation::PivDeleteKey
            )
            .then_some(0x9a),
        }
    }

    fn grant(operation: Operation) -> OperationGrant {
        OperationGrant {
            version: 1,
            grant_id: format!("grant-{operation:?}"),
            operation: operation as i32,
            subject: "backend-user".into(),
            station_id: "station-1".into(),
            token_serial: "12345678".into(),
            caller_os_user: "S-1-5-21-test".into(),
            not_before_unix: NOW - 1,
            expires_at_unix: NOW + 120,
            piv_slot: if matches!(
                operation,
                Operation::PivGenerateKey
                    | Operation::PivImportCertificate
                    | Operation::PivDeleteCertificate
            ) {
                0x9a
            } else {
                0
            },
        }
    }

    fn sign(grant: OperationGrant, signing_key: &SigningKey) -> SignedGrant {
        let bytes = grant.encode_to_vec();
        let signature: Signature = signing_key.sign(&bytes);
        SignedGrant {
            grant: bytes,
            signature: signature.to_der().as_bytes().to_vec(),
            key_id: KEY_ID.into(),
        }
    }

    fn verifier(signing_key: &SigningKey) -> GrantVerifier {
        GrantVerifier::new(HashMap::from([(
            KEY_ID.into(),
            VerifyingKey::from(signing_key),
        )]))
    }

    #[test]
    fn accepts_signed_grants_and_rejects_replays() {
        let signing_key = key();
        let verifier = verifier(&signing_key);
        let signed = sign(grant(Operation::PivGenerateKey), &signing_key);
        assert_eq!(
            verifier
                .verify(&signed, &expectation(Operation::PivGenerateKey), NOW)
                .unwrap()
                .grant_id,
            "grant-PivGenerateKey"
        );
        assert!(matches!(
            verifier.verify(&signed, &expectation(Operation::PivGenerateKey), NOW),
            Err(CredentialError::OperationUnauthorized(_))
        ));
        for operation in [
            Operation::PivImportCertificate,
            Operation::PivDeleteCertificate,
            Operation::PivUnblockPin,
            Operation::PivChangePuk,
            Operation::PivChangeManagementKey,
            Operation::PivSetRetries,
            Operation::PivManagedInitialize,
        ] {
            let signed = sign(grant(operation), &signing_key);
            verifier
                .verify(&signed, &expectation(operation), NOW)
                .unwrap();
        }
    }

    #[test]
    fn rejects_unknown_keys_bad_signatures_and_bad_protobuf() {
        let signing_key = key();
        let verifier = verifier(&signing_key);
        let signed = sign(grant(Operation::PivGenerateKey), &signing_key);
        let mut unknown = signed.clone();
        unknown.key_id = "unknown".into();
        assert!(
            verifier
                .verify(&unknown, &expectation(Operation::PivGenerateKey), NOW)
                .is_err()
        );
        let mut bad_signature = signed.clone();
        bad_signature.signature[0] ^= 1;
        assert!(
            verifier
                .verify(&bad_signature, &expectation(Operation::PivGenerateKey), NOW)
                .is_err()
        );
        let malformed_grant = b"not protobuf".to_vec();
        let malformed_signature: Signature = signing_key.sign(&malformed_grant);
        let malformed = SignedGrant {
            grant: malformed_grant,
            signature: malformed_signature.to_der().as_bytes().to_vec(),
            key_id: KEY_ID.into(),
        };
        assert!(
            verifier
                .verify(&malformed, &expectation(Operation::PivGenerateKey), NOW)
                .is_err()
        );
    }

    #[test]
    fn rejects_version_operation_and_time_violations() {
        let signing_key = key();
        let verifier = verifier(&signing_key);
        for grant_value in [
            OperationGrant {
                version: 2,
                ..grant(Operation::PivGenerateKey)
            },
            grant(Operation::PivDeleteCertificate),
            OperationGrant {
                not_before_unix: NOW + 100,
                expires_at_unix: NOW + 200,
                ..grant(Operation::PivGenerateKey)
            },
            OperationGrant {
                not_before_unix: NOW - 200,
                expires_at_unix: NOW - 100,
                ..grant(Operation::PivGenerateKey)
            },
            OperationGrant {
                not_before_unix: NOW - 1,
                expires_at_unix: NOW + 301,
                ..grant(Operation::PivGenerateKey)
            },
            OperationGrant {
                grant_id: String::new(),
                ..grant(Operation::PivGenerateKey)
            },
        ] {
            let signed = sign(grant_value, &signing_key);
            assert!(
                verifier
                    .verify(&signed, &expectation(Operation::PivGenerateKey), NOW)
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_context_and_piv_slot_mismatches() {
        let signing_key = key();
        let verifier = verifier(&signing_key);
        let signed = sign(grant(Operation::PivGenerateKey), &signing_key);
        for expected in [
            GrantExpectation {
                station_id: "other".into(),
                ..expectation(Operation::PivGenerateKey)
            },
            GrantExpectation {
                token_serial: "other".into(),
                ..expectation(Operation::PivGenerateKey)
            },
            GrantExpectation {
                caller_os_user: Some("other".into()),
                ..expectation(Operation::PivGenerateKey)
            },
            GrantExpectation {
                piv_slot: Some(0x9d),
                ..expectation(Operation::PivGenerateKey)
            },
        ] {
            assert!(verifier.verify(&signed, &expected, NOW).is_err());
        }
        let mut unexpected_slot = grant(Operation::PivUnblockPin);
        unexpected_slot.piv_slot = 0x9a;
        let signed = sign(unexpected_slot, &signing_key);
        assert!(
            verifier
                .verify(&signed, &expectation(Operation::PivUnblockPin), NOW)
                .is_err()
        );
    }

    #[test]
    fn verifies_go_golden_piv_grant_and_rejects_mismatched_serial() {
        #[derive(Deserialize)]
        struct ExpectedGrant {
            version: u32,
            grant_id: String,
            operation: String,
            subject: String,
            station_id: String,
            token_serial: String,
            caller_os_user: String,
            not_before_unix: i64,
            expires_at_unix: i64,
            piv_slot: u32,
            key_id: String,
        }

        let expected: ExpectedGrant = serde_json::from_str(include_str!(
            "../../../testdata/grants/golden-v1/expected.json"
        ))
        .expect("Go golden expected.json");
        let key = VerifyingKey::from_public_key_pem(include_str!(
            "../../../testdata/grants/golden-v1/public_key.pem"
        ))
        .expect("Go golden public key");
        let signed = SignedGrant::decode(
            include_bytes!("../../../testdata/grants/golden-v1/signed_grant.bin").as_slice(),
        )
        .expect("Go golden SignedGrant protobuf");
        let verifier = GrantVerifier::new(HashMap::from([(expected.key_id.clone(), key)]));
        let operation = Operation::PivGenerateKey;
        assert_eq!(expected.operation, "PIV_GENERATE_KEY");
        let expectation = GrantExpectation {
            operation,
            station_id: expected.station_id.clone(),
            token_serial: expected.token_serial.clone(),
            caller_os_user: Some(expected.caller_os_user.clone()),
            piv_slot: Some(u8::try_from(expected.piv_slot).expect("PIV slot fits u8")),
        };
        let grant = verifier
            .verify(&signed, &expectation, expected.not_before_unix + 1)
            .expect("Rust verifier accepts Go-signed fixture");
        assert_eq!(grant.version, expected.version);
        assert_eq!(grant.grant_id, expected.grant_id);
        assert_eq!(grant.operation, operation as i32);
        assert_eq!(grant.subject, expected.subject);
        assert_eq!(grant.station_id, expected.station_id);
        assert_eq!(grant.token_serial, expected.token_serial);
        assert_eq!(grant.caller_os_user, expected.caller_os_user);
        assert_eq!(grant.not_before_unix, expected.not_before_unix);
        assert_eq!(grant.expires_at_unix, expected.expires_at_unix);
        assert_eq!(grant.piv_slot, expected.piv_slot);

        let mismatched_serial = GrantExpectation {
            token_serial: "wrong-serial".into(),
            ..expectation
        };
        assert!(matches!(
            verifier.verify(&signed, &mismatched_serial, expected.not_before_unix + 1),
            Err(CredentialError::OperationUnauthorized(_))
        ));
    }

    #[cfg(feature = "dev-grants")]
    #[test]
    fn dev_signer_issues_piv_slot_grants() {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};

        let signing_key = key();
        let key_path =
            std::env::temp_dir().join(format!("sigil-dev-grant-{}.pem", std::process::id()));
        std::fs::write(
            &key_path,
            signing_key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("PKCS#8 test key")
                .as_bytes(),
        )
        .expect("write temporary development key");
        let signer =
            DevSigner::from_pem_path("station-1", KEY_ID, &key_path).expect("development signer");
        let _ = std::fs::remove_file(&key_path);
        let caller = crate::caller::CallerIdentity {
            os_user: "S-1-5-21-test".into(),
            session_id: Some(1),
            pid: std::process::id(),
        };
        let signed = signer
            .obtain(
                &caller,
                &GrantRequest {
                    operation: Operation::PivGenerateKey,
                    station_id: "station-1".into(),
                    token_serial: "12345678".into(),
                    caller_os_user: caller.os_user.clone(),
                    piv_slot: Some(0x9a),
                },
            )
            .expect("signed PIV grant");
        assert_eq!(
            verifier(&signing_key)
                .verify(&signed, &expectation(Operation::PivGenerateKey), now_unix())
                .unwrap()
                .piv_slot,
            0x9a
        );
    }
}
