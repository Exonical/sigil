use std::{path::Path, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Method, Request, Response, header};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject as _},
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::{AuthError, Result};

const IO_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Minimal HTTPS client for identity provider calls. It trusts only the configured CA file
/// when one is set, and the platform roots otherwise. There is no insecure mode.
#[derive(Clone)]
pub struct HttpClient {
    tls: Arc<ClientConfig>,
}

impl HttpClient {
    pub fn new(ca_file: Option<&Path>) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| AuthError::Config(error.to_string()))?;
        let mut config = match ca_file {
            Some(path) => {
                let pem = std::fs::read(path).map_err(|error| {
                    AuthError::Config(format!("could not read CA file: {error}"))
                })?;
                let certificates = CertificateDer::pem_slice_iter(&pem)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| AuthError::Config("CA file is not valid PEM".into()))?;
                if certificates.is_empty() {
                    return Err(AuthError::Config("CA file contains no certificates".into()));
                }
                let mut roots = RootCertStore::empty();
                for certificate in certificates {
                    roots
                        .add(certificate)
                        .map_err(|error| AuthError::Config(error.to_string()))?;
                }
                builder.with_root_certificates(roots).with_no_client_auth()
            }
            None => {
                use rustls_platform_verifier::BuilderVerifierExt;
                builder
                    .with_platform_verifier()
                    .map_err(|error| AuthError::Config(error.to_string()))?
                    .with_no_client_auth()
            }
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: Arc::new(config),
        })
    }

    /// Sends one request over a fresh TLS connection and returns the complete response.
    pub async fn send(
        &self,
        method: Method,
        url: &Url,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<Response<Bytes>> {
        if url.scheme() != "https" {
            return Err(AuthError::Http("only https endpoints are supported".into()));
        }
        let host = url
            .host_str()
            .ok_or_else(|| AuthError::Http("endpoint URL has no host".into()))?
            .to_owned();
        let port = url.port_or_known_default().unwrap_or(443);
        let mut path = url.path().to_owned();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }

        let tcp = timeout(IO_TIMEOUT, TcpStream::connect((host.as_str(), port)))
            .await
            .map_err(|_| AuthError::Http("connection timed out".into()))?
            .map_err(|error| AuthError::Http(format!("connection failed: {error}")))?;
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| AuthError::Http("endpoint host is not a valid server name".into()))?;
        let tls = timeout(
            IO_TIMEOUT,
            TlsConnector::from(Arc::clone(&self.tls)).connect(server_name, tcp),
        )
        .await
        .map_err(|_| AuthError::Http("TLS handshake timed out".into()))?
        .map_err(|error| AuthError::Http(format!("TLS handshake failed: {error}")))?;

        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|error| AuthError::Http(error.to_string()))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let host_header = if port == 443 {
            host
        } else {
            format!("{host}:{port}")
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, host_header)
            .header(header::CONNECTION, "close")
            .header(header::ACCEPT, "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(Full::new(body))
            .map_err(|error| AuthError::Http(error.to_string()))?;
        let response = timeout(IO_TIMEOUT, sender.send_request(request))
            .await
            .map_err(|_| AuthError::Http("request timed out".into()))?
            .map_err(|error| AuthError::Http(error.to_string()))?;
        let (parts, incoming) = response.into_parts();
        let collected = timeout(IO_TIMEOUT, incoming.collect())
            .await
            .map_err(|_| AuthError::Http("response timed out".into()))?
            .map_err(|error| AuthError::Http(error.to_string()))?
            .to_bytes();
        if collected.len() > MAX_RESPONSE_BYTES {
            return Err(AuthError::Http("response is too large".into()));
        }
        Ok(Response::from_parts(parts, collected))
    }

    pub async fn get_json(&self, url: &Url) -> Result<serde_json::Value> {
        let response = self.send(Method::GET, url, &[], Bytes::new()).await?;
        if !response.status().is_success() {
            return Err(AuthError::Http(format!(
                "GET returned HTTP {}",
                response.status().as_u16()
            )));
        }
        serde_json::from_slice(response.body())
            .map_err(|_| AuthError::InvalidResponse("expected a JSON document".into()))
    }

    pub async fn post_form(&self, url: &Url, fields: &[(&str, &str)]) -> Result<Response<Bytes>> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        self.send(
            Method::POST,
            url,
            &[("content-type", "application/x-www-form-urlencoded")],
            Bytes::from(body),
        )
        .await
    }
}
