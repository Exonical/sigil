use std::{collections::HashMap, future::Future, net::Ipv4Addr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    AuthError, HttpClient, Result,
    config::OidcSettings,
    jwt::{IdTokenExpectation, Jwks, access_token_expiry, validate_claims},
    now_unix,
};

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const REQUEST_HEAD_LIMIT: usize = 16 * 1024;
const SCOPES: &str = "openid profile email offline_access";

#[derive(Clone, Debug)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
    pub revocation_endpoint: Option<Url>,
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
}

pub async fn discover(http: &HttpClient, settings: &OidcSettings) -> Result<Discovery> {
    let mut base = settings.issuer.clone();
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    let url = base
        .join(".well-known/openid-configuration")
        .map_err(|_| AuthError::Discovery("could not build the discovery URL".into()))?;
    let value = http
        .get_json(&url)
        .await
        .map_err(|error| AuthError::Discovery(error.to_string()))?;
    let document: DiscoveryDocument = serde_json::from_value(value)
        .map_err(|_| AuthError::Discovery("discovery document is invalid".into()))?;
    if document.issuer != settings.issuer.as_str() {
        return Err(AuthError::Discovery(
            "discovery issuer does not match the configured issuer".into(),
        ));
    }
    let endpoint = |value: &str, name: &str| -> Result<Url> {
        let url = Url::parse(value)
            .map_err(|_| AuthError::Discovery(format!("{name} is not a valid URL")))?;
        if url.scheme() != "https" {
            return Err(AuthError::Discovery(format!("{name} must use https")));
        }
        Ok(url)
    };
    Ok(Discovery {
        issuer: document.issuer,
        authorization_endpoint: endpoint(
            &document.authorization_endpoint,
            "authorization endpoint",
        )?,
        token_endpoint: endpoint(&document.token_endpoint, "token endpoint")?,
        jwks_uri: endpoint(&document.jwks_uri, "JWKS URI")?,
        revocation_endpoint: document
            .revocation_endpoint
            .as_deref()
            .map(|value| endpoint(value, "revocation endpoint"))
            .transpose()?,
    })
}

pub async fn fetch_jwks(http: &HttpClient, discovery: &Discovery) -> Result<Jwks> {
    let document = http
        .get_json(&discovery.jwks_uri)
        .await
        .map_err(|error| AuthError::Discovery(error.to_string()))?;
    Jwks::parse(&document)
}

#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

/// Maps a non-200 token endpoint reply. `invalid_grant` means the refresh token is no longer valid.
pub(crate) fn token_error(body: &[u8]) -> AuthError {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
        #[serde(default)]
        error_description: Option<String>,
    }
    match serde_json::from_slice::<ErrorBody>(body) {
        Ok(error) if error.error == "invalid_grant" => AuthError::SignedOut,
        Ok(error) => AuthError::Rejected(
            error
                .error_description
                .unwrap_or(error.error)
                .chars()
                .take(200)
                .collect(),
        ),
        Err(_) => AuthError::Rejected("the identity provider rejected the request".into()),
    }
}

pub(crate) fn random_urlsafe(bytes: usize) -> Result<String> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer)
        .map_err(|_| AuthError::Config("the OS random source is unavailable".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

/// Everything a successful sign-in produces. The refresh token and access token are zeroized on drop.
pub struct SignedInTokens {
    pub discovery: Discovery,
    pub jwks: Jwks,
    pub access_token: Zeroizing<String>,
    pub access_expires_at: i64,
    pub refresh_token: Option<Zeroizing<String>>,
    pub identity: crate::session::Identity,
}

/// Runs the authorization-code + PKCE flow with a loopback redirect.
///
/// `present` receives the authorization URL (open it in a browser and/or display it).
/// `cancel` completes the flow with [`AuthError::Cancelled`] when it resolves.
pub async fn sign_in_tokens<F>(
    settings: &OidcSettings,
    present: impl FnOnce(&Url),
    cancel: F,
) -> Result<SignedInTokens>
where
    F: Future<Output = ()>,
{
    let http = HttpClient::new(settings.ca_file.as_deref())?;
    let discovery = discover(&http, settings).await?;
    let jwks = fetch_jwks(&http, &discovery).await?;

    let verifier = Zeroizing::new(random_urlsafe(32)?);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_urlsafe(24)?;
    let nonce = random_urlsafe(24)?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| {
            AuthError::Http(format!("could not open the loopback listener: {error}"))
        })?;
    let port = listener
        .local_addr()
        .map_err(|error| AuthError::Http(error.to_string()))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let mut authorization = discovery.authorization_endpoint.clone();
    authorization
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &settings.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", SCOPES)
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    present(&authorization);

    let code = timeout(CALLBACK_TIMEOUT, async {
        tokio::select! {
            code = wait_for_callback(&listener, &state) => code,
            () = cancel => Err(AuthError::Cancelled),
        }
    })
    .await
    .map_err(|_| AuthError::Timeout)??;

    let response = http
        .post_form(
            &discovery.token_endpoint,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &redirect_uri),
                ("client_id", &settings.client_id),
                ("code_verifier", &verifier),
            ],
        )
        .await?;
    if !response.status().is_success() {
        return Err(token_error(response.body()));
    }
    let tokens: TokenResponse = serde_json::from_slice(response.body())
        .map_err(|_| AuthError::InvalidResponse("token response is invalid".into()))?;
    let id_token = tokens
        .id_token
        .as_deref()
        .ok_or_else(|| AuthError::InvalidResponse("token response has no ID token".into()))?;
    let payload = jwks.verify(id_token)?;
    let claims = validate_claims(
        &payload,
        &IdTokenExpectation {
            issuer: &discovery.issuer,
            client_id: &settings.client_id,
            nonce: Some(&nonce),
            now: now_unix(),
        },
    )?;
    let access_expires_at = now_unix()
        + tokens
            .expires_in
            .or_else(|| access_token_expiry(&tokens.access_token).map(|exp| exp - now_unix()))
            .unwrap_or(300);
    Ok(SignedInTokens {
        discovery,
        jwks,
        access_token: Zeroizing::new(tokens.access_token),
        access_expires_at,
        refresh_token: tokens.refresh_token.map(Zeroizing::new),
        identity: crate::session::Identity {
            subject: claims.subject,
            username: claims.username,
            email: claims.email,
            groups: claims.groups,
        },
    })
}

/// Waits for one `/callback` request whose `state` matches. Other paths get a 404 and are ignored.
async fn wait_for_callback(listener: &TcpListener, expected_state: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|error| AuthError::Http(error.to_string()))?;
        let head = match timeout(Duration::from_secs(10), read_request_head(&mut stream)).await {
            Ok(Ok(head)) => head,
            _ => continue,
        };
        let Some(target) = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .filter(|target| target.starts_with('/'))
        else {
            continue;
        };
        let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
            continue;
        };
        if url.path() != "/callback" {
            respond(&mut stream, 404, "Not found").await;
            continue;
        }
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        if params.get("state").map(String::as_str) != Some(expected_state) {
            respond(
                &mut stream,
                400,
                "Sign-in could not be completed. Close this window and try again.",
            )
            .await;
            return Err(AuthError::StateMismatch);
        }
        if params.contains_key("error") {
            respond(
                &mut stream,
                400,
                "Sign-in was not completed. You can close this window.",
            )
            .await;
            return Err(AuthError::Rejected(
                "the identity provider returned an error".into(),
            ));
        }
        let Some(code) = params.get("code").filter(|code| !code.is_empty()) else {
            respond(
                &mut stream,
                400,
                "Sign-in could not be completed. You can close this window.",
            )
            .await;
            return Err(AuthError::InvalidResponse(
                "callback has no authorization code".into(),
            ));
        };
        respond(
            &mut stream,
            200,
            "Sign-in complete; you can close this window.",
        )
        .await;
        return Ok(code.clone());
    }
}

async fn read_request_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if head.len() > REQUEST_HEAD_LIMIT {
            return Err(std::io::Error::other("request head is too large"));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

async fn respond(stream: &mut TcpStream, status: u16, message: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let body =
        format!("<!doctype html><meta charset=\"utf-8\"><title>Sigil</title><p>{message}</p>");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Opens a URL with the system browser.
#[cfg(windows)]
pub fn open_in_browser(url: &Url) -> Result<()> {
    use std::ptr::null;
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

    let wide = |value: &str| -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let verb = wide("open");
    let target = wide(url.as_str());
    // SAFETY: verb and target are NUL-terminated and live for the call; optional arguments are null.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            null(),
            null(),
            SW_SHOWNORMAL,
        )
    };
    if result as usize <= 32 {
        return Err(AuthError::Browser(
            "Windows refused to open the sign-in page".into(),
        ));
    }
    Ok(())
}

/// Opens a URL with the system browser.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn open_in_browser(url: &Url) -> Result<()> {
    std::process::Command::new("xdg-open")
        .arg(url.as_str())
        .spawn()
        .map(|_| ())
        .map_err(|error| AuthError::Browser(error.to_string()))
}

/// Opens a URL with the system browser.
#[cfg(not(any(windows, all(unix, not(target_os = "macos")))))]
pub fn open_in_browser(_url: &Url) -> Result<()> {
    Err(AuthError::Browser(
        "no system browser launcher on this platform".into(),
    ))
}
