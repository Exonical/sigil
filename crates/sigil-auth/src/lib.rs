//! OpenID Connect sign-in for the Sigil CLI and GUI.
//!
//! This crate is used by the user-facing clients only. The agent never signs in; it
//! verifies the backend's own mTLS identity and grants.

mod config;
mod flow;
mod http;
mod jwt;
mod session;
mod storage;

pub use config::{OidcSettings, load_settings};
pub use flow::{Discovery, discover, open_in_browser, sign_in_tokens};
pub use http::HttpClient;
pub use jwt::{IdTokenExpectation, IdentityClaims, Jwks, validate_claims};
pub use session::{Identity, Session, sign_out};
pub use storage::{MemoryStore, TokenStore, platform_store, target_name};

#[cfg(windows)]
pub use storage::CredentialManagerStore;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("sign-in is not configured by machine policy")]
    NotConfigured,
    #[error("sign-in configuration is invalid: {0}")]
    Config(String),
    #[error("identity provider request failed: {0}")]
    Http(String),
    #[error("identity provider discovery failed: {0}")]
    Discovery(String),
    #[error("sign-in was rejected: {0}")]
    Rejected(String),
    #[error("identity provider response is invalid: {0}")]
    InvalidResponse(String),
    #[error("ID token is not valid: {0}")]
    InvalidIdToken(String),
    #[error("sign-in callback state did not match")]
    StateMismatch,
    #[error("sign-in timed out waiting for the browser")]
    Timeout,
    #[error("sign-in was cancelled")]
    Cancelled,
    #[error("signed out; sign in again")]
    SignedOut,
    #[error("credential store error: {0}")]
    Storage(String),
    #[error("could not open the browser: {0}")]
    Browser(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}
