use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    AuthError, HttpClient, Result,
    config::OidcSettings,
    flow::{
        Discovery, SignedInTokens, TokenResponse, discover, fetch_jwks, sign_in_tokens, token_error,
    },
    jwt::{IdTokenExpectation, Jwks, validate_claims},
    now_unix,
    storage::{TokenStore, target_name},
};

/// Access tokens are refreshed when fewer than this many seconds remain.
const REFRESH_MARGIN_SECONDS: i64 = 60;

/// Display identity from the ID token. Contains no secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub subject: String,
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredRecord {
    refresh_token: String,
    identity: Identity,
}

struct Inner {
    discovery: Option<Discovery>,
    jwks: Option<Jwks>,
    access: Zeroizing<String>,
    access_expires_at: i64,
    refresh: Option<Zeroizing<String>>,
}

/// A signed-in user. The access token lives in memory only; the refresh token is kept in the store.
pub struct Session {
    settings: OidcSettings,
    http: HttpClient,
    store: Arc<dyn TokenStore>,
    target: String,
    identity: Mutex<Identity>,
    inner: tokio::sync::Mutex<Inner>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Signs in interactively. `present` receives the authorization URL to show or open.
    pub async fn sign_in<F: Future<Output = ()>>(
        settings: &OidcSettings,
        store: Arc<dyn TokenStore>,
        present: impl FnOnce(&url::Url),
        cancel: F,
    ) -> Result<Self> {
        let tokens = sign_in_tokens(settings, present, cancel).await?;
        let http = HttpClient::new(settings.ca_file.as_deref())?;
        let target = target_name(settings);
        if let Some(refresh) = &tokens.refresh_token {
            save_record(store.as_ref(), &target, refresh, &tokens.identity)?;
        }
        Ok(Self::from_tokens(settings, http, store, target, tokens))
    }

    /// Restores a session from the stored refresh token. Returns `None` when nothing is stored or the
    /// stored token was revoked (in which case the stored record is removed).
    pub async fn load_or_none(
        settings: &OidcSettings,
        store: Arc<dyn TokenStore>,
    ) -> Result<Option<Self>> {
        let target = target_name(settings);
        let Some(raw) = store.load(&target)? else {
            return Ok(None);
        };
        let Ok(record) = serde_json::from_str::<StoredRecord>(&raw) else {
            store.delete(&target)?;
            return Ok(None);
        };
        drop(raw);
        let session = Self {
            settings: settings.clone(),
            http: HttpClient::new(settings.ca_file.as_deref())?,
            store,
            target,
            identity: Mutex::new(record.identity),
            inner: tokio::sync::Mutex::new(Inner {
                discovery: None,
                jwks: None,
                access: Zeroizing::new(String::new()),
                access_expires_at: 0,
                refresh: Some(Zeroizing::new(record.refresh_token)),
            }),
        };
        {
            let mut inner = session.inner.lock().await;
            match session.refresh_locked(&mut inner).await {
                Ok(()) => {}
                Err(AuthError::SignedOut) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        Ok(Some(session))
    }

    fn from_tokens(
        settings: &OidcSettings,
        http: HttpClient,
        store: Arc<dyn TokenStore>,
        target: String,
        tokens: SignedInTokens,
    ) -> Self {
        Self {
            settings: settings.clone(),
            http,
            store,
            target,
            identity: Mutex::new(tokens.identity),
            inner: tokio::sync::Mutex::new(Inner {
                discovery: Some(tokens.discovery),
                jwks: Some(tokens.jwks),
                access: tokens.access_token,
                access_expires_at: tokens.access_expires_at,
                refresh: tokens.refresh_token,
            }),
        }
    }

    /// Returns a current access token, refreshing it first when it is close to expiry.
    pub async fn access_token(&self) -> Result<Zeroizing<String>> {
        let mut inner = self.inner.lock().await;
        if inner.access.is_empty() || inner.access_expires_at - now_unix() < REFRESH_MARGIN_SECONDS
        {
            self.refresh_locked(&mut inner).await?;
        }
        Ok(Zeroizing::new(inner.access.to_string()))
    }

    pub fn identity(&self) -> Identity {
        self.identity
            .lock()
            .map(|identity| identity.clone())
            .unwrap_or_default()
    }

    /// Unix time at which the current access token expires.
    pub async fn access_expires_at(&self) -> i64 {
        self.inner.lock().await.access_expires_at
    }

    async fn refresh_locked(&self, inner: &mut Inner) -> Result<()> {
        let refresh = inner.refresh.clone().ok_or(AuthError::SignedOut)?;
        if inner.discovery.is_none() {
            inner.discovery = Some(discover(&self.http, &self.settings).await?);
        }
        let Some(discovery) = inner.discovery.clone() else {
            return Err(AuthError::Discovery("discovery is unavailable".into()));
        };
        let response = self
            .http
            .post_form(
                &discovery.token_endpoint,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh.as_str()),
                    ("client_id", &self.settings.client_id),
                ],
            )
            .await?;
        if !response.status().is_success() {
            let error = token_error(response.body());
            if matches!(error, AuthError::SignedOut) {
                self.store.delete(&self.target)?;
                inner.refresh = None;
                inner.access = Zeroizing::new(String::new());
                inner.access_expires_at = 0;
            }
            return Err(error);
        }
        let tokens = TokenResponse::parse(response.body())?;

        if let Some(id_token) = tokens.id_token.as_deref() {
            if inner.jwks.is_none() {
                inner.jwks = Some(fetch_jwks(&self.http, &discovery).await?);
            }
            let Some(jwks) = inner.jwks.as_ref() else {
                return Err(AuthError::Discovery("JWKS is unavailable".into()));
            };
            let payload = jwks.verify(id_token)?;
            let claims = validate_claims(
                &payload,
                &IdTokenExpectation {
                    issuer: &discovery.issuer,
                    client_id: &self.settings.client_id,
                    nonce: None,
                    now: now_unix(),
                },
            )?;
            if claims.subject != self.identity().subject {
                self.store.delete(&self.target)?;
                inner.refresh = None;
                inner.access = Zeroizing::new(String::new());
                inner.access_expires_at = 0;
                return Err(AuthError::SignedOut);
            }
            let identity = Identity {
                subject: claims.subject,
                username: claims.username,
                email: claims.email,
                groups: claims.groups,
            };
            if let Ok(mut current) = self.identity.lock() {
                *current = identity;
            }
        }

        inner.access_expires_at = tokens.access_expires_at(now_unix());
        inner.access = Zeroizing::new(tokens.access_token);
        if let Some(rotated) = tokens.refresh_token {
            inner.refresh = Some(Zeroizing::new(rotated));
        }
        let identity = self.identity();
        if let Some(refresh) = inner.refresh.as_ref() {
            save_record(self.store.as_ref(), &self.target, refresh, &identity)?;
        }
        Ok(())
    }
}

fn save_record(
    store: &dyn TokenStore,
    target: &str,
    refresh: &str,
    identity: &Identity,
) -> Result<()> {
    let record = serde_json::to_string(&StoredRecord {
        refresh_token: refresh.to_owned(),
        identity: identity.clone(),
    })
    .map_err(|_| AuthError::Storage("could not encode the sign-in record".into()))?;
    store.save(target, &record)
}

/// Signs out: revokes the refresh token when the provider advertises revocation (best effort),
/// then removes the stored record.
pub async fn sign_out(settings: &OidcSettings, store: Arc<dyn TokenStore>) -> Result<()> {
    let target = target_name(settings);
    if let Some(raw) = store.load(&target)?
        && let Ok(record) = serde_json::from_str::<StoredRecord>(&raw)
    {
        let http = HttpClient::new(settings.ca_file.as_deref())?;
        if let Ok(discovery) = discover(&http, settings).await
            && let Some(revocation) = discovery.revocation_endpoint.as_ref()
        {
            let _ = http
                .post_form(
                    revocation,
                    &[
                        ("token", record.refresh_token.as_str()),
                        ("token_type_hint", "refresh_token"),
                        ("client_id", &settings.client_id),
                    ],
                )
                .await;
        }
    }
    store.delete(&target)
}
