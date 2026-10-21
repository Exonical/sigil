use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature as EcSignature, VerifyingKey as EcVerifyingKey, signature::Verifier};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{AuthError, Result};

/// Clock skew allowed when checking token times.
const CLOCK_SKEW_SECONDS: i64 = 60;

/// DER DigestInfo prefix for SHA-256 (RFC 8017 section 9.2).
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

#[derive(Clone)]
enum JwkKey {
    Rsa {
        kid: Option<String>,
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Ec {
        kid: Option<String>,
        x: Vec<u8>,
        y: Vec<u8>,
    },
}

/// Public keys from the identity provider's JWKS document (RS256 and ES256 only).
#[derive(Clone)]
pub struct Jwks {
    keys: Vec<JwkKey>,
}

impl Jwks {
    pub fn parse(document: &Value) -> Result<Self> {
        let entries = document
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| AuthError::InvalidResponse("JWKS has no keys array".into()))?;
        let mut keys = Vec::new();
        for entry in entries {
            let kid = entry.get("kid").and_then(Value::as_str).map(str::to_owned);
            let field = |name: &str| -> Option<Vec<u8>> {
                entry
                    .get(name)
                    .and_then(Value::as_str)
                    .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            };
            match entry.get("kty").and_then(Value::as_str) {
                Some("RSA") => {
                    if let (Some(n), Some(e)) = (field("n"), field("e")) {
                        keys.push(JwkKey::Rsa { kid, n, e });
                    }
                }
                Some("EC") if entry.get("crv").and_then(Value::as_str) == Some("P-256") => {
                    if let (Some(x), Some(y)) = (field("x"), field("y")) {
                        keys.push(JwkKey::Ec { kid, x, y });
                    }
                }
                _ => {}
            }
        }
        if keys.is_empty() {
            return Err(AuthError::InvalidResponse("JWKS has no usable keys".into()));
        }
        Ok(Self { keys })
    }

    /// Verifies a compact JWS and returns its payload. The header algorithm must match the key type.
    pub fn verify(&self, token: &str) -> Result<Value> {
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AuthError::InvalidIdToken(
                "token is not a compact JWS".into(),
            ));
        };
        let header: Value = decode_json(header)?;
        let algorithm = header
            .get("alg")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let kid = header.get("kid").and_then(Value::as_str);
        let signing_input = format!("{}.{}", payload_header(token), payload);
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| AuthError::InvalidIdToken("signature is not base64url".into()))?;

        let candidates = self.keys.iter().filter(|key| match (key, kid) {
            (
                JwkKey::Rsa { kid: Some(own), .. } | JwkKey::Ec { kid: Some(own), .. },
                Some(wanted),
            ) => own == wanted,
            _ => true,
        });
        let mut checked = false;
        for key in candidates {
            match (algorithm, key) {
                ("RS256", JwkKey::Rsa { n, e, .. }) => {
                    checked = true;
                    let public =
                        RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
                            .map_err(|_| AuthError::InvalidIdToken("RSA key is invalid".into()))?;
                    let digest = Sha256::digest(signing_input.as_bytes());
                    let scheme = Pkcs1v15Sign {
                        hash_len: Some(digest.len()),
                        prefix: SHA256_DIGEST_INFO.to_vec().into_boxed_slice(),
                    };
                    if public.verify(scheme, &digest, &signature).is_ok() {
                        return decode_json(payload);
                    }
                }
                ("ES256", JwkKey::Ec { x, y, .. }) => {
                    checked = true;
                    let mut point = Vec::with_capacity(65);
                    point.push(4);
                    point.extend_from_slice(x);
                    point.extend_from_slice(y);
                    let verifying = EcVerifyingKey::from_sec1_bytes(&point)
                        .map_err(|_| AuthError::InvalidIdToken("EC key is invalid".into()))?;
                    let signature = EcSignature::try_from(signature.as_slice())
                        .map_err(|_| AuthError::InvalidIdToken("signature is malformed".into()))?;
                    if verifying
                        .verify(signing_input.as_bytes(), &signature)
                        .is_ok()
                    {
                        return decode_json(payload);
                    }
                }
                _ => {}
            }
        }
        if checked {
            Err(AuthError::InvalidIdToken(
                "signature does not verify".into(),
            ))
        } else {
            Err(AuthError::InvalidIdToken(format!(
                "no trusted key for algorithm {algorithm}"
            )))
        }
    }
}

fn payload_header(token: &str) -> &str {
    token.split('.').next().unwrap_or_default()
}

fn decode_json<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AuthError::InvalidIdToken("segment is not base64url".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AuthError::InvalidIdToken("segment is not JSON".into()))
}

/// Reads a JWT payload without verifying it. Only use this for values the backend re-verifies,
/// such as the access token expiry.
pub(crate) fn unverified_payload(token: &str) -> Result<Value> {
    let segment = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AuthError::InvalidIdToken("token is not a JWT".into()))?;
    decode_json(segment)
}

pub struct IdTokenExpectation<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: Option<&'a str>,
    pub now: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityClaims {
    pub subject: String,
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub expires_at: i64,
}

/// Checks the issuer, audience, nonce, and time claims of a verified ID token payload.
pub fn validate_claims(
    payload: &Value,
    expectation: &IdTokenExpectation<'_>,
) -> Result<IdentityClaims> {
    let invalid = |reason: &str| AuthError::InvalidIdToken(reason.to_owned());
    if payload.get("iss").and_then(Value::as_str) != Some(expectation.issuer) {
        return Err(invalid("issuer does not match"));
    }
    let audiences: Vec<&str> = match payload.get("aud") {
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&expectation.client_id) {
        return Err(invalid("audience does not include this client"));
    }
    if audiences.len() > 1
        && payload.get("azp").and_then(Value::as_str) != Some(expectation.client_id)
    {
        return Err(invalid("authorized party is not this client"));
    }
    if let Some(expected) = expectation.nonce
        && payload.get("nonce").and_then(Value::as_str) != Some(expected)
    {
        return Err(invalid("nonce does not match"));
    }
    let expires_at = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| invalid("expiry is missing"))?;
    if expires_at + CLOCK_SKEW_SECONDS < expectation.now {
        return Err(invalid("token has expired"));
    }
    if let Some(not_before) = payload.get("nbf").and_then(Value::as_i64)
        && not_before - CLOCK_SKEW_SECONDS > expectation.now
    {
        return Err(invalid("token is not valid yet"));
    }
    let subject = payload
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("subject is missing"))?
        .to_owned();
    let username = ["preferred_username", "name", "email"]
        .iter()
        .find_map(|claim| payload.get(*claim).and_then(Value::as_str))
        .unwrap_or(&subject)
        .to_owned();
    let groups = payload
        .get("groups")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(IdentityClaims {
        subject,
        username,
        email: payload
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_owned),
        groups,
        expires_at,
    })
}

/// Expiry of an access token, read without verification (the backend verifies it).
pub(crate) fn access_token_expiry(token: &str) -> Option<i64> {
    unverified_payload(token)
        .ok()
        .and_then(|payload| payload.get("exp").and_then(Value::as_i64))
}
