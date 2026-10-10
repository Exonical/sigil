//! End-to-end OIDC tests against an in-process TLS identity provider.

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sigil_auth::{
    AuthError, HttpClient, MemoryStore, OidcSettings, Session, TokenStore, target_name,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsAcceptor;
use url::Url;

const BASE_PATH: &str = "/application/o/sigil/";
const CLIENT_ID: &str = "sigil";

#[derive(Clone, Default)]
struct Options {
    discovery_issuer: Option<String>,
    token_issuer: Option<String>,
    audience: Option<String>,
    nonce: Option<String>,
    id_token_exp_offset: i64,
    access_expires_in: i64,
    revocation: bool,
}

#[derive(Clone)]
struct Pending {
    challenge: String,
    nonce: String,
    redirect_uri: String,
}

#[derive(Default)]
struct Counters {
    refreshes: u32,
    revocations: u32,
}

struct Provider {
    issuer: String,
    signing: SigningKey,
    options: Mutex<Options>,
    codes: Mutex<HashMap<String, Pending>>,
    refresh_tokens: Mutex<HashSet<String>>,
    counters: Mutex<Counters>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn random_token(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).unwrap();
    format!("{prefix}-{}", URL_SAFE_NO_PAD.encode(bytes))
}

impl Provider {
    fn sign(&self, claims: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signing_input = format!("{header}.{payload}");
        let signature: Signature = self.signing.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn jwks(&self) -> Value {
        let point = self.signing.verifying_key().to_sec1_point(false);
        json!({"keys": [{
            "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    fn id_token(&self, nonce: &str) -> String {
        let options = self.options.lock().unwrap().clone();
        let issued = now();
        self.sign(json!({
            "iss": options.token_issuer.unwrap_or_else(|| self.issuer.clone()),
            "aud": options.audience.unwrap_or_else(|| CLIENT_ID.into()),
            "sub": "user-123",
            "preferred_username": "alice",
            "email": "alice@example.test",
            "groups": ["sigil-admins"],
            "nonce": options.nonce.unwrap_or_else(|| nonce.to_owned()),
            "iat": issued,
            "exp": issued + 300 + options.id_token_exp_offset,
        }))
    }

    fn access_token(&self) -> String {
        let options = self.options.lock().unwrap().clone();
        let expires_in = if options.access_expires_in > 0 {
            options.access_expires_in
        } else {
            3600
        };
        self.sign(json!({ "iss": self.issuer, "aud": "sigil", "sub": "user-123", "exp": now() + expires_in }))
    }

    fn issue_refresh(&self) -> String {
        let token = random_token("refresh");
        self.refresh_tokens.lock().unwrap().insert(token.clone());
        token
    }

    /// Simulates the provider revoking every outstanding refresh token.
    fn invalidate_refresh_tokens(&self) {
        self.refresh_tokens.lock().unwrap().clear();
    }

    fn refresh_count(&self) -> u32 {
        self.counters.lock().unwrap().refreshes
    }

    fn revocation_count(&self) -> u32 {
        self.counters.lock().unwrap().revocations
    }

    async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let method = request.method().clone();
        let url = Url::parse(&format!("https://localhost{}", request.uri())).unwrap();
        let body = request.into_body().collect().await.unwrap().to_bytes();
        let path = url.path().to_owned();
        let relative = path.strip_prefix(BASE_PATH).unwrap_or("");
        let options = self.options.lock().unwrap().clone();

        match (method, relative) {
            (Method::GET, ".well-known/openid-configuration") => {
                let issuer = options
                    .discovery_issuer
                    .unwrap_or_else(|| self.issuer.clone());
                let mut document = json!({
                    "issuer": issuer,
                    "authorization_endpoint": format!("{}authorize/", self.issuer),
                    "token_endpoint": format!("{}token/", self.issuer),
                    "jwks_uri": format!("{}jwks/", self.issuer),
                });
                if options.revocation {
                    document["revocation_endpoint"] = json!(format!("{}revoke/", self.issuer));
                }
                json_response(StatusCode::OK, &document)
            }
            (Method::GET, "jwks/") => json_response(StatusCode::OK, &self.jwks()),
            (Method::GET, "authorize/") => {
                let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
                let code = random_token("code");
                self.codes.lock().unwrap().insert(
                    code.clone(),
                    Pending {
                        challenge: params["code_challenge"].clone(),
                        nonce: params["nonce"].clone(),
                        redirect_uri: params["redirect_uri"].clone(),
                    },
                );
                let mut location = Url::parse(&params["redirect_uri"]).unwrap();
                location
                    .query_pairs_mut()
                    .append_pair("code", &code)
                    .append_pair("state", &params["state"]);
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header("location", location.as_str())
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            (Method::POST, "token/") => {
                let form: HashMap<String, String> =
                    url::form_urlencoded::parse(&body).into_owned().collect();
                match form.get("grant_type").map(String::as_str) {
                    Some("authorization_code") => self.exchange_code(&form),
                    Some("refresh_token") => self.refresh(&form),
                    _ => oauth_error("unsupported_grant_type", None),
                }
            }
            (Method::POST, "revoke/") => {
                self.counters.lock().unwrap().revocations += 1;
                let form: HashMap<String, String> =
                    url::form_urlencoded::parse(&body).into_owned().collect();
                if let Some(token) = form.get("token") {
                    self.refresh_tokens.lock().unwrap().remove(token);
                }
                json_response(StatusCode::OK, &json!({}))
            }
            _ => json_response(StatusCode::NOT_FOUND, &json!({"error": "not_found"})),
        }
    }

    fn exchange_code(&self, form: &HashMap<String, String>) -> Response<Full<Bytes>> {
        let Some(code) = form.get("code") else {
            return oauth_error("invalid_request", Some("code is missing"));
        };
        let Some(pending) = self.codes.lock().unwrap().remove(code) else {
            return oauth_error("invalid_grant", Some("unknown code"));
        };
        let verifier = form.get("code_verifier").cloned().unwrap_or_default();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        if expected != pending.challenge {
            return oauth_error(
                "invalid_grant",
                Some("PKCE verifier does not match the challenge"),
            );
        }
        if form.get("redirect_uri") != Some(&pending.redirect_uri) {
            return oauth_error("invalid_grant", Some("redirect URI does not match"));
        }
        let refresh = self.issue_refresh();
        json_response(
            StatusCode::OK,
            &json!({
                "access_token": self.access_token(),
                "id_token": self.id_token(&pending.nonce),
                "refresh_token": refresh,
                "token_type": "Bearer",
                "expires_in": access_lifetime(self),
            }),
        )
    }

    fn refresh(&self, form: &HashMap<String, String>) -> Response<Full<Bytes>> {
        let Some(token) = form.get("refresh_token") else {
            return oauth_error("invalid_request", Some("refresh_token is missing"));
        };
        if !self.refresh_tokens.lock().unwrap().remove(token) {
            return oauth_error("invalid_grant", Some("refresh token is not valid"));
        }
        self.counters.lock().unwrap().refreshes += 1;
        let refresh = self.issue_refresh();
        json_response(
            StatusCode::OK,
            &json!({
                "access_token": self.access_token(),
                "id_token": self.id_token(""),
                "refresh_token": refresh,
                "token_type": "Bearer",
                "expires_in": access_lifetime(self),
            }),
        )
    }
}

fn access_lifetime(provider: &Provider) -> i64 {
    let configured = provider.options.lock().unwrap().access_expires_in;
    if configured > 0 { configured } else { 3600 }
}

fn json_response(status: StatusCode, value: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(value.to_string())))
        .unwrap()
}

fn oauth_error(error: &str, description: Option<&str>) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::BAD_REQUEST,
        &json!({"error": error, "error_description": description.unwrap_or_default()}),
    )
}

struct Harness {
    settings: OidcSettings,
    provider: Arc<Provider>,
    ca_file: PathBuf,
    _directory: tempfile::TempDir,
}

async fn start_provider() -> Harness {
    let directory = tempfile::tempdir().unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Sigil test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let server = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();
    let ca_file = directory.path().join("ca.pem");
    std::fs::write(&ca_file, ca.pem()).unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let issuer = format!("https://localhost:{port}{BASE_PATH}");
    let provider = Arc::new(Provider {
        issuer: issuer.clone(),
        signing: SigningKey::from_slice(&[7u8; 32]).unwrap(),
        options: Mutex::new(Options {
            access_expires_in: 3600,
            ..Options::default()
        }),
        codes: Mutex::new(HashMap::new()),
        refresh_tokens: Mutex::new(HashSet::new()),
        counters: Mutex::new(Counters::default()),
    });

    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![server.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
    )
    .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let serving = Arc::clone(&provider);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let provider = Arc::clone(&serving);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |request| {
                    let provider = Arc::clone(&provider);
                    async move { Ok::<_, Infallible>(provider.handle(request).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    let settings = OidcSettings {
        issuer: Url::parse(&issuer).unwrap(),
        client_id: CLIENT_ID.into(),
        ca_file: Some(ca_file.clone()),
    };
    Harness {
        settings,
        provider,
        ca_file,
        _directory: directory,
    }
}

#[derive(Clone, Copy)]
enum Browser {
    /// Visits the authorization URL and follows the redirect to the loopback callback.
    Complete,
    /// Visits the authorization URL but returns a callback with a different state.
    WrongState,
}

/// Plays the browser: follows the provider redirect and delivers the callback over plain HTTP,
/// exactly as a browser on this machine would.
fn spawn_browser(ca_file: PathBuf, mode: Browser) -> impl FnOnce(&Url) {
    move |authorization: &Url| {
        let authorization = authorization.clone();
        tokio::spawn(async move {
            let http = HttpClient::new(Some(&ca_file)).unwrap();
            let redirect = http
                .send(Method::GET, &authorization, &[], Bytes::new())
                .await
                .unwrap();
            assert_eq!(redirect.status(), StatusCode::FOUND);
            let location = redirect.headers()["location"].to_str().unwrap();
            let mut callback = Url::parse(location).unwrap();
            if matches!(mode, Browser::WrongState) {
                let pairs: Vec<(String, String)> = callback
                    .query_pairs()
                    .map(|(key, value)| {
                        let value = if key == "state" {
                            "forged".to_owned()
                        } else {
                            value.into_owned()
                        };
                        (key.into_owned(), value)
                    })
                    .collect();
                callback.query_pairs_mut().clear().extend_pairs(pairs);
            }
            deliver_callback(&callback).await;
        });
    }
}

async fn deliver_callback(callback: &Url) {
    let host = callback.host_str().unwrap();
    let port = callback.port().unwrap();
    let mut stream = TcpStream::connect((host, port)).await.unwrap();
    let mut target = callback.path().to_owned();
    if let Some(query) = callback.query() {
        target.push('?');
        target.push_str(query);
    }
    let request =
        format!("GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
}

fn never() -> impl std::future::Future<Output = ()> {
    std::future::pending()
}

#[tokio::test]
async fn sign_in_completes_pkce_flow_and_stores_refresh_token() {
    let harness = start_provider().await;
    let store: Arc<dyn TokenStore> = Arc::new(MemoryStore::default());
    let session = Session::sign_in(
        &harness.settings,
        Arc::clone(&store),
        spawn_browser(harness.ca_file.clone(), Browser::Complete),
        never(),
    )
    .await
    .expect("sign-in succeeds with a matching PKCE verifier");

    let identity = session.identity();
    assert_eq!(identity.username, "alice");
    assert_eq!(identity.email.as_deref(), Some("alice@example.test"));
    assert_eq!(identity.groups, vec!["sigil-admins".to_owned()]);
    let token = session.access_token().await.unwrap();
    assert!(!token.is_empty());
    assert!(
        store
            .load(&target_name(&harness.settings))
            .unwrap()
            .is_some(),
        "refresh record is persisted"
    );
}

#[tokio::test]
async fn mismatched_state_is_rejected() {
    let harness = start_provider().await;
    let store: Arc<dyn TokenStore> = Arc::new(MemoryStore::default());
    let result = Session::sign_in(
        &harness.settings,
        Arc::clone(&store),
        spawn_browser(harness.ca_file.clone(), Browser::WrongState),
        never(),
    )
    .await;
    assert!(
        matches!(result, Err(AuthError::StateMismatch)),
        "got {result:?}"
    );
    assert!(
        store
            .load(&target_name(&harness.settings))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn wrong_nonce_audience_issuer_and_expiry_are_rejected() {
    type Mutation = Box<dyn Fn(&mut Options)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "nonce",
            Box::new(|options: &mut Options| options.nonce = Some("not-the-nonce".into())),
        ),
        (
            "audience",
            Box::new(|options: &mut Options| options.audience = Some("someone-else".into())),
        ),
        (
            "issuer",
            Box::new(|options: &mut Options| {
                options.token_issuer = Some("https://evil.example/application/o/sigil/".into());
            }),
        ),
        (
            "expiry",
            Box::new(|options: &mut Options| options.id_token_exp_offset = -3600),
        ),
    ];
    for (name, mutate) in cases {
        let harness = start_provider().await;
        mutate(&mut harness.provider.options.lock().unwrap());
        let store: Arc<dyn TokenStore> = Arc::new(MemoryStore::default());
        let result = Session::sign_in(
            &harness.settings,
            Arc::clone(&store),
            spawn_browser(harness.ca_file.clone(), Browser::Complete),
            never(),
        )
        .await;
        assert!(
            matches!(result, Err(AuthError::InvalidIdToken(_))),
            "{name}: expected InvalidIdToken, got {result:?}"
        );
        assert!(
            store
                .load(&target_name(&harness.settings))
                .unwrap()
                .is_none(),
            "{name}: nothing stored"
        );
    }
}

#[tokio::test]
async fn discovery_issuer_mismatch_is_rejected_before_the_browser_opens() {
    let harness = start_provider().await;
    harness.provider.options.lock().unwrap().discovery_issuer =
        Some("https://evil.example/".into());
    let opened = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&opened);
    let store: Arc<dyn TokenStore> = Arc::new(MemoryStore::default());
    let result = Session::sign_in(
        &harness.settings,
        store,
        move |_url| *flag.lock().unwrap() = true,
        never(),
    )
    .await;
    assert!(
        matches!(result, Err(AuthError::Discovery(_))),
        "got {result:?}"
    );
    assert!(!*opened.lock().unwrap());
}

#[tokio::test]
async fn refresh_rotates_the_stored_token_and_refreshes_near_expiry() {
    let harness = start_provider().await;
    harness.provider.options.lock().unwrap().access_expires_in = 30;
    let store: Arc<dyn TokenStore> = Arc::new(MemoryStore::default());
    let target = target_name(&harness.settings);
    let session = Session::sign_in(
        &harness.settings,
        Arc::clone(&store),
        spawn_browser(harness.ca_file.clone(), Browser::Complete),
        never(),
    )
    .await
    .unwrap();
    let before = store.load(&target).unwrap().unwrap().to_string();

    // The access token lasts 30 seconds, which is inside the refresh margin, so this refreshes.
    let _ = session.access_token().await.unwrap();
    assert_eq!(harness.provider.refresh_count(), 1);
    let after = store.load(&target).unwrap().unwrap().to_string();
    assert_ne!(before, after, "rotated refresh token was persisted");

    // A fresh session restores from the rotated token.
    let restored = Session::load_or_none(&harness.settings, Arc::clone(&store))
        .await
        .unwrap()
        .expect("restored session");
    assert_eq!(restored.identity().username, "alice");
    assert_eq!(harness.provider.refresh_count(), 2);
}

#[tokio::test]
async fn invalid_grant_clears_stored_sign_in() {
    let harness = start_provider().await;
    let store: Arc<dyn TokenStore> = Arc::new(MemoryStore::default());
    let target = target_name(&harness.settings);
    let _session = Session::sign_in(
        &harness.settings,
        Arc::clone(&store),
        spawn_browser(harness.ca_file.clone(), Browser::Complete),
        never(),
    )
    .await
    .unwrap();

    harness.provider.invalidate_refresh_tokens();
    let restored = Session::load_or_none(&harness.settings, Arc::clone(&store))
        .await
        .expect("invalid_grant is not a hard error");
    assert!(
        restored.is_none(),
        "revoked sign-in is reported as signed out"
    );
    assert!(
        store.load(&target).unwrap().is_none(),
        "stored record is removed"
    );
}

#[tokio::test]
async fn sign_out_revokes_and_removes_the_record() {
    let harness = start_provider().await;
    harness.provider.options.lock().unwrap().revocation = true;
    let store: Arc<dyn TokenStore> = Arc::new(MemoryStore::default());
    let target = target_name(&harness.settings);
    let _session = Session::sign_in(
        &harness.settings,
        Arc::clone(&store),
        spawn_browser(harness.ca_file.clone(), Browser::Complete),
        never(),
    )
    .await
    .unwrap();
    sigil_auth::sign_out(&harness.settings, Arc::clone(&store))
        .await
        .unwrap();
    assert_eq!(harness.provider.revocation_count(), 1);
    assert!(store.load(&target).unwrap().is_none());
}

/// Live check against the dev Authentik: discovery and JWKS only, no credentials and no browser.
/// Run with `SIGIL_OIDC_ISSUER`, `SIGIL_OIDC_CLIENT_ID`, and `SIGIL_OIDC_CA_FILE` set.
#[tokio::test]
#[ignore = "requires the dev Authentik; set SIGIL_OIDC_ISSUER, SIGIL_OIDC_CLIENT_ID, SIGIL_OIDC_CA_FILE"]
async fn live_discovery_and_jwks_against_dev_authentik() {
    let settings = sigil_auth::load_settings()
        .expect("settings are valid")
        .expect("debug environment configures sign-in");
    let http = HttpClient::new(settings.ca_file.as_deref()).unwrap();
    let discovery = sigil_auth::discover(&http, &settings)
        .await
        .expect("discovery succeeds with the dev CA");
    assert_eq!(discovery.issuer, settings.issuer.as_str());
    let jwks = http
        .get_json(&discovery.jwks_uri)
        .await
        .expect("JWKS is served");
    sigil_auth::Jwks::parse(&jwks).expect("JWKS has usable keys");
    println!(
        "discovery ok: issuer={} token_endpoint={}",
        discovery.issuer, discovery.token_endpoint
    );
}

#[cfg(windows)]
#[test]
fn credential_manager_round_trip_uses_a_unique_target() {
    use sigil_auth::{CredentialManagerStore, TokenStore as _};

    let store = CredentialManagerStore;
    let target = format!("Sigil:test:{}", random_token("target"));
    assert!(store.load(&target).unwrap().is_none());
    store.save(&target, "{\"refresh_token\":\"test\"}").unwrap();
    assert_eq!(
        store.load(&target).unwrap().as_deref().map(String::as_str),
        Some("{\"refresh_token\":\"test\"}")
    );
    store.delete(&target).unwrap();
    assert!(store.load(&target).unwrap().is_none());
}
