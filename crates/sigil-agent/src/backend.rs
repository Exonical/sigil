use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject as _},
};
use sigil_core::{DeviceInfo, Transport};
use sigil_proto::{
    backend::v1 as backendv1,
    v1::{Operation, SignedGrant},
};
use tokio::{net::TcpStream, time::timeout};
use tonic::{
    Request, Status,
    transport::{Channel, Endpoint, Uri},
};
use tower::service_fn;
use zeroize::Zeroizing;

use crate::config::{AgentConfig, BackendCertificateStore, BackendConfig};

const BACKEND_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const MAX_ACCESS_TOKEN_BYTES: usize = 16 * 1024;

pub struct ManagedRequest {
    pub access_token: Zeroizing<String>,
    pub operation: Operation,
    pub vendor: String,
    pub serial: String,
    pub caller_os_user: String,
    pub piv_slot: Option<u8>,
}

pub struct ManagedSecret {
    pub value: Zeroizing<Vec<u8>>,
    pub algorithm: String,
}

pub struct ManagedGrant {
    pub signed_grant: SignedGrant,
    pub current_management_key: Option<ManagedSecret>,
    pub current_puk: Option<ManagedSecret>,
    pub rotation_id: Option<String>,
    pub new_management_key: Option<ManagedSecret>,
    pub new_puk: Option<ManagedSecret>,
}

#[async_trait]
pub trait ManagedAuthority: Send + Sync {
    async fn authorize(&self, request: ManagedRequest) -> Result<ManagedGrant, Status>;
    async fn complete_rotation(&self, rotation_id: &str, applied: bool) -> Result<(), Status>;
    async fn report_tokens(&self, tokens: Vec<backendv1::ObservedToken>) -> Result<(), Status>;
    async fn report_audit(&self, events: Vec<backendv1::AgentAuditEvent>) -> Result<u64, Status>;
    async fn list_certificate_profiles(
        &self,
        request: backendv1::ListProfilesRequest,
    ) -> Result<backendv1::ListProfilesResponse, Status>;
    async fn issue_certificate(
        &self,
        request: backendv1::IssueCertificateRequest,
    ) -> Result<backendv1::IssueCertificateResponse, Status>;
}

#[derive(Clone)]
pub struct GrpcBackend {
    url: String,
    tls: Arc<BackendTlsSettings>,
}

#[derive(Clone)]
struct BackendTlsSettings {
    server_roots: Option<RootCertStore>,
    identity: ClientIdentity,
}

#[derive(Clone)]
enum ClientIdentity {
    #[cfg(windows)]
    WindowsStore(StoreIdentity),
    #[cfg(any(debug_assertions, test))]
    PemFiles {
        cert_file: PathBuf,
        key_file: PathBuf,
    },
    #[cfg(not(windows))]
    Unsupported,
}

#[cfg(windows)]
#[derive(Clone)]
struct StoreIdentity {
    store: BackendCertificateStore,
    station_dns: String,
    thumbprint: Option<String>,
    issuer: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentityInfo {
    pub subject: String,
    pub thumbprint: String,
    pub dns_sans: Vec<String>,
    pub not_after: String,
}

impl GrpcBackend {
    pub fn from_agent_config(config: &AgentConfig) -> anyhow::Result<Option<Self>> {
        let Some((backend, server_ca_file)) = config.backend()? else {
            return Ok(None);
        };
        Self::new(config, backend, server_ca_file).map(Some)
    }

    fn new(
        config: &AgentConfig,
        backend: BackendConfig,
        server_ca_file: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let server_roots = server_ca_file.as_deref().map(read_root_store).transpose()?;
        let identity = select_identity_config(config, &backend)?;
        Ok(Self {
            url: backend.url,
            tls: Arc::new(BackendTlsSettings {
                server_roots,
                identity,
            }),
        })
    }

    pub fn selected_identity_info(&self) -> anyhow::Result<ClientIdentityInfo> {
        match &self.tls.identity {
            #[cfg(windows)]
            ClientIdentity::WindowsStore(options) => select_windows_certificate(options)
                .map(|selected| selected.metadata.identity_info()),
            #[allow(unreachable_patterns)]
            _ => anyhow::bail!(
                "client certificate details are available only for Windows certificate stores"
            ),
        }
    }

    async fn connect(
        &self,
    ) -> Result<backendv1::agent_gateway_client::AgentGatewayClient<Channel>, Status> {
        let origin = self
            .url
            .parse::<Uri>()
            .map_err(|error| Status::invalid_argument(format!("invalid backend URL: {error}")))?;
        let authority = origin
            .authority()
            .ok_or_else(|| Status::invalid_argument("backend URL has no authority"))?
            .clone();
        let connector_uri = Uri::builder()
            .scheme("http")
            .authority(authority)
            .path_and_query("/")
            .build()
            .map_err(|error| Status::invalid_argument(format!("invalid backend URL: {error}")))?;
        let endpoint = Endpoint::from_shared(connector_uri.to_string())
            .map_err(|error| Status::invalid_argument(format!("invalid backend URL: {error}")))?
            .origin(origin)
            .connect_timeout(BACKEND_TIMEOUT)
            .timeout(BACKEND_TIMEOUT);
        let backend = self.clone();
        let connector = service_fn(move |uri: Uri| {
            let backend = backend.clone();
            async move { backend.connect_uri(uri).await }
        });
        let channel = endpoint
            .connect_with_connector(connector)
            .await
            .map_err(|error| {
                Status::unavailable(format!("backend connection failed: {error:?}"))
            })?;
        Ok(backendv1::agent_gateway_client::AgentGatewayClient::new(
            channel,
        ))
    }

    async fn connect_uri(
        &self,
        uri: Uri,
    ) -> Result<hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<TcpStream>>, std::io::Error>
    {
        let host = uri.host().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "backend URL has no host")
        })?;
        let port = uri.port_u16().unwrap_or(443);
        let tls_config = self.tls.client_config().map_err(std::io::Error::other)?;
        let tcp = timeout(BACKEND_TIMEOUT, TcpStream::connect((host, port)))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "backend connect timed out")
            })??;
        let server_name = ServerName::try_from(host.to_owned()).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?;
        let stream = timeout(
            BACKEND_TIMEOUT,
            tokio_rustls::TlsConnector::from(Arc::new(tls_config)).connect(server_name, tcp),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "backend TLS handshake timed out",
            )
        })?
        .map_err(std::io::Error::other)?;
        Ok(hyper_util::rt::TokioIo::new(stream))
    }
}

#[async_trait]
impl ManagedAuthority for GrpcBackend {
    async fn authorize(&self, request: ManagedRequest) -> Result<ManagedGrant, Status> {
        if request.access_token.len() > MAX_ACCESS_TOKEN_BYTES {
            return Err(Status::invalid_argument(
                "managed access token exceeds 16 KiB",
            ));
        }
        let mut client = self.connect().await?;
        let access_token = request.access_token.as_str().to_owned();
        let proto_request = backendv1::AuthorizeManagedOperationRequest {
            access_token,
            operation: request.operation as i32,
            token_vendor: request.vendor,
            token_serial: request.serial,
            caller_os_user: request.caller_os_user,
            piv_slot: request.piv_slot.map(u32::from).unwrap_or_default(),
        };
        drop(request.access_token);
        let response = client
            .authorize_managed_operation(Request::new(proto_request))
            .await?
            .into_inner();

        let signed_grant = response
            .grant
            .ok_or_else(|| Status::internal("backend omitted the managed-operation grant"))?;
        Ok(ManagedGrant {
            signed_grant,
            current_management_key: take_secret(response.current_management_key),
            current_puk: take_secret(response.current_puk),
            rotation_id: (!response.rotation_id.is_empty()).then_some(response.rotation_id),
            new_management_key: take_secret(response.new_management_key),
            new_puk: take_secret(response.new_puk),
        })
    }

    async fn complete_rotation(&self, rotation_id: &str, applied: bool) -> Result<(), Status> {
        let mut client = self.connect().await?;
        client
            .complete_rotation(Request::new(backendv1::CompleteRotationRequest {
                rotation_id: rotation_id.to_owned(),
                applied,
            }))
            .await?;
        Ok(())
    }

    async fn report_tokens(&self, tokens: Vec<backendv1::ObservedToken>) -> Result<(), Status> {
        let mut client = self.connect().await?;
        client
            .report_tokens(Request::new(backendv1::ReportTokensRequest { tokens }))
            .await?;
        Ok(())
    }

    async fn list_certificate_profiles(
        &self,
        request: backendv1::ListProfilesRequest,
    ) -> Result<backendv1::ListProfilesResponse, Status> {
        if request.access_token.len() > MAX_ACCESS_TOKEN_BYTES {
            return Err(Status::invalid_argument(
                "managed access token exceeds 16 KiB",
            ));
        }
        let mut client = self.connect().await?;
        Ok(client
            .list_profiles(Request::new(request))
            .await?
            .into_inner())
    }

    async fn issue_certificate(
        &self,
        request: backendv1::IssueCertificateRequest,
    ) -> Result<backendv1::IssueCertificateResponse, Status> {
        if request.access_token.len() > MAX_ACCESS_TOKEN_BYTES {
            return Err(Status::invalid_argument(
                "managed access token exceeds 16 KiB",
            ));
        }
        let mut client = self.connect().await?;
        Ok(client
            .issue_certificate(Request::new(request))
            .await?
            .into_inner())
    }

    async fn report_audit(&self, events: Vec<backendv1::AgentAuditEvent>) -> Result<u64, Status> {
        let mut client = self.connect().await?;
        Ok(client
            .report_audit(Request::new(backendv1::ReportAuditRequest { events }))
            .await?
            .into_inner()
            .accepted_through)
    }
}

impl BackendTlsSettings {
    fn client_config(&self) -> anyhow::Result<ClientConfig> {
        use rustls_platform_verifier::BuilderVerifierExt;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions = [&rustls::version::TLS13];
        let verifier_builder =
            ClientConfig::builder_with_provider(provider).with_protocol_versions(&versions)?;
        let client_builder = if let Some(roots) = &self.server_roots {
            verifier_builder.with_root_certificates(roots.clone())
        } else {
            verifier_builder.with_platform_verifier()?
        };

        let mut client_config = match &self.identity {
            #[cfg(windows)]
            ClientIdentity::WindowsStore(options) => {
                let selected = select_windows_certificate(options)?;
                client_builder.with_client_cert_resolver(Arc::new(CngClientCertResolver {
                    key: selected.certified_key,
                }))
            }
            #[cfg(any(debug_assertions, test))]
            ClientIdentity::PemFiles {
                cert_file,
                key_file,
            } => {
                let certs = CertificateDer::pem_file_iter(cert_file)
                    .map_err(|error| {
                        anyhow::anyhow!("could not open backend client certificate: {error}")
                    })?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| {
                        anyhow::anyhow!("could not parse backend client certificate: {error}")
                    })?;
                if certs.is_empty() {
                    anyhow::bail!("backend client certificate file contains no certificates");
                }
                let key =
                    rustls::pki_types::PrivateKeyDer::from_pem_file(key_file).map_err(|error| {
                        anyhow::anyhow!("could not parse backend client private key: {error}")
                    })?;
                client_builder
                    .with_client_auth_cert(certs, key)
                    .map_err(anyhow::Error::from)?
            }
            #[cfg(not(windows))]
            ClientIdentity::Unsupported => {
                anyhow::bail!("Windows certificate-store mTLS is unsupported on this platform")
            }
        };
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(client_config)
    }
}

fn read_root_store(path: &std::path::Path) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|error| anyhow::anyhow!("could not open backend server CA file: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow::anyhow!("could not parse backend server CA file: {error}"))?;
    if certificates.is_empty() {
        anyhow::bail!("backend server CA file contains no certificates");
    }
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|error| anyhow::anyhow!("invalid backend server CA certificate: {error}"))?;
    }
    Ok(roots)
}

fn take_secret(secret: Option<backendv1::EscrowedSecret>) -> Option<ManagedSecret> {
    secret.map(|mut secret| ManagedSecret {
        value: Zeroizing::new(std::mem::take(&mut secret.value)),
        algorithm: std::mem::take(&mut secret.algorithm),
    })
}

fn select_identity_config(
    config: &AgentConfig,
    backend: &BackendConfig,
) -> anyhow::Result<ClientIdentity> {
    #[cfg(any(debug_assertions, test))]
    match (
        backend.client_certificate.cert_file.as_deref(),
        backend.client_certificate.key_file.as_deref(),
    ) {
        (Some(cert_file), Some(key_file)) => {
            return Ok(ClientIdentity::PemFiles {
                cert_file: config.trusted_path(cert_file)?,
                key_file: config.trusted_path(key_file)?,
            });
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("backend PEM identity requires both cert_file and key_file");
        }
        (None, None) => {}
    }

    #[cfg(windows)]
    {
        #[cfg(debug_assertions)]
        let station_dns = backend
            .client_certificate
            .expected_dns_name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| config.station_id());
        #[cfg(not(debug_assertions))]
        let station_dns = config.station_id();
        Ok(ClientIdentity::WindowsStore(StoreIdentity {
            store: backend.client_certificate.store,
            station_dns: station_dns.to_ascii_lowercase(),
            thumbprint: backend.client_certificate.thumbprint.clone(),
            issuer: backend.client_certificate.issuer.clone(),
        }))
    }

    #[cfg(not(windows))]
    {
        let _ = config;
        Ok(ClientIdentity::Unsupported)
    }
}

#[derive(Clone, Debug)]
struct CertificateMetadata {
    thumbprint: String,
    subject: String,
    issuer: String,
    dns_sans: Vec<String>,
    not_before_unix: i64,
    not_after_unix: i64,
    not_after_display: String,
    client_auth: bool,
    has_private_key: bool,
}

impl CertificateMetadata {
    fn identity_info(&self) -> ClientIdentityInfo {
        ClientIdentityInfo {
            subject: self.subject.clone(),
            thumbprint: self.thumbprint.clone(),
            dns_sans: self.dns_sans.clone(),
            not_after: self.not_after_display.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct CertificateFilters<'a> {
    thumbprint: Option<&'a str>,
    issuer: Option<&'a str>,
}

fn select_certificate_index(
    candidates: &[CertificateMetadata],
    station_dns: &str,
    filters: &CertificateFilters<'_>,
    now_unix: i64,
) -> Option<usize> {
    let station_dns = station_dns.to_ascii_lowercase();
    let thumbprint = filters.thumbprint.map(normalize_thumbprint);
    candidates
        .iter()
        .enumerate()
        .filter(|(_, certificate)| {
            certificate.has_private_key
                && certificate.client_auth
                && certificate.not_before_unix <= now_unix
                && certificate.not_after_unix >= now_unix
                && certificate
                    .dns_sans
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&station_dns))
                && thumbprint
                    .as_deref()
                    .is_none_or(|pin| certificate.thumbprint.eq_ignore_ascii_case(pin))
                && filters.issuer.is_none_or(|issuer| {
                    certificate
                        .issuer
                        .to_ascii_lowercase()
                        .contains(&issuer.to_ascii_lowercase())
                })
        })
        .max_by_key(|(_, certificate)| certificate.not_before_unix)
        .map(|(index, _)| index)
}

fn normalize_thumbprint(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .flat_map(char::to_uppercase)
        .collect()
}

pub fn observed_token(info: &DeviceInfo) -> Option<backendv1::ObservedToken> {
    let serial = info.serial.as_ref()?;
    Some(backendv1::ObservedToken {
        vendor: info.vendor.clone(),
        model: info.model.clone(),
        serial: serial.clone(),
        firmware: info
            .firmware
            .as_ref()
            .map(|version| format!("{}.{}.{}", version.major, version.minor, version.patch))
            .unwrap_or_default(),
        form_factor: info.form_factor.clone().unwrap_or_default(),
        connection: info
            .connection
            .as_ref()
            .map(transport_name)
            .unwrap_or_default(),
    })
}

pub fn token_identity(info: &DeviceInfo) -> Option<(String, String)> {
    let observed = observed_token(info)?;
    Some((observed.vendor, observed.serial))
}

fn transport_name(transport: &Transport) -> String {
    match transport {
        Transport::UsbSmartCard => "usb_smart_card",
        Transport::UsbHid => "usb_hid",
        Transport::UsbOtp => "usb_otp",
        Transport::Nfc => "nfc",
    }
    .into()
}

#[cfg(windows)]
#[derive(Debug)]
struct CngClientCertResolver {
    key: Arc<rustls::sign::CertifiedKey>,
}

#[cfg(windows)]
impl rustls::client::ResolvesClientCert for CngClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.key
            .key
            .choose_scheme(sigschemes)
            .map(|_| Arc::clone(&self.key))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(windows)]
struct SelectedWindowsCertificate {
    certified_key: Arc<rustls::sign::CertifiedKey>,
    metadata: CertificateMetadata,
}

#[cfg(windows)]
fn select_windows_certificate(
    options: &StoreIdentity,
) -> anyhow::Result<SelectedWindowsCertificate> {
    use rustls_cng::{
        signer::CngSigningKey,
        store::{CertStore, CertStoreType},
    };
    use sha1::{Digest, Sha1};
    use x509_parser::{
        extensions::{GeneralName, ParsedExtension},
        parse_x509_certificate,
    };

    let store_name = match options.store {
        BackendCertificateStore::LocalMachine => "LocalMachine\\My",
        BackendCertificateStore::CurrentUser => "CurrentUser\\My",
    };
    let store_type = match options.store {
        BackendCertificateStore::LocalMachine => CertStoreType::LocalMachine,
        BackendCertificateStore::CurrentUser => CertStoreType::CurrentUser,
    };
    let store = CertStore::open(store_type, "MY")
        .map_err(|error| anyhow::anyhow!("could not open {store_name}: {error}"))?;
    let pin = options
        .thumbprint
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(normalize_thumbprint);
    if let Some(pin) = &pin
        && (pin.len() != 40 || !pin.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        anyhow::bail!("configured backend thumbprint must be a 40-character SHA-1 thumbprint");
    }
    let contexts = if let Some(pin) = &pin {
        let thumbprint = (0..20)
            .map(|index| u8::from_str_radix(&pin[index * 2..index * 2 + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        store
            .find_by_sha1(thumbprint)
            .map_err(|error| anyhow::anyhow!("could not search {store_name}: {error}"))?
    } else {
        store
            .find_all()
            .map_err(|error| anyhow::anyhow!("could not enumerate {store_name}: {error}"))?
    };

    let mut metadata = Vec::with_capacity(contexts.len());
    let mut signing_keys = Vec::with_capacity(contexts.len());
    let filters = CertificateFilters {
        thumbprint: pin.as_deref(),
        issuer: options
            .issuer
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();
    let mut matching_certificate_without_private_key = false;
    let mut matching_private_key_unavailable = false;
    for context in &contexts {
        let Ok((_, certificate)) = parse_x509_certificate(context.as_der()) else {
            metadata.push(None);
            signing_keys.push(None);
            continue;
        };
        let digest = Sha1::digest(context.as_der());
        let thumbprint = digest.iter().map(|byte| format!("{byte:02X}")).collect();
        let dns_sans = certificate
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|extension| {
                extension
                    .value
                    .general_names
                    .iter()
                    .filter_map(|name| match name {
                        GeneralName::DNSName(name) => Some((*name).to_owned()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let client_auth = certificate.extensions().iter().any(|extension| {
            matches!(
                extension.parsed_extension(),
                ParsedExtension::ExtendedKeyUsage(usage) if usage.client_auth
            )
        });
        let mut candidate = CertificateMetadata {
            thumbprint,
            subject: certificate.subject().to_string(),
            issuer: certificate.issuer().to_string(),
            dns_sans,
            not_before_unix: certificate.validity().not_before.timestamp(),
            not_after_unix: certificate.validity().not_after.timestamp(),
            not_after_display: certificate.validity().not_after.to_string(),
            client_auth,
            has_private_key: true,
        };
        let matches_without_key =
            select_certificate_index(&[candidate.clone()], &options.station_dns, &filters, now)
                .is_some();
        if matches_without_key {
            matching_certificate_without_private_key = true;
        }
        let key = if matches_without_key {
            context
                .acquire_key(true)
                .ok()
                .and_then(|key| CngSigningKey::new(key).ok())
                .map(|key| Arc::new(key) as Arc<dyn rustls::sign::SigningKey>)
        } else {
            None
        };
        candidate.has_private_key = key.is_some();
        matching_private_key_unavailable |= matches_without_key && key.is_none();
        metadata.push(Some(candidate));
        signing_keys.push(key);
    }
    let candidates = metadata
        .iter()
        .filter_map(|metadata| metadata.clone())
        .collect::<Vec<_>>();
    let selected = select_certificate_index(&candidates, &options.station_dns, &filters, now)
        .ok_or_else(|| {
            if matching_certificate_without_private_key && matching_private_key_unavailable {
                anyhow::anyhow!(
                    "a matching client-auth certificate for {} was found in {store_name}, but its CNG private key could not be accessed",
                    options.station_dns
                )
            } else {
                anyhow::anyhow!(
                    "no valid client-auth certificate for {} in {store_name}; require clientAuth EKU, a private key, a current validity period, DNS SAN {}, and configured thumbprint/issuer filters",
                    options.station_dns,
                    options.station_dns
                )
            }
        })?;
    let selected_metadata = candidates[selected].clone();
    let selected_in_original = metadata
        .iter()
        .enumerate()
        .filter_map(|(index, value)| value.as_ref().map(|value| (index, value)))
        .find(|(_, value)| value.thumbprint == selected_metadata.thumbprint)
        .map(|(index, _)| index)
        .ok_or_else(|| anyhow::anyhow!("selected certificate disappeared from {store_name}"))?;
    let signing_key = signing_keys[selected_in_original]
        .take()
        .ok_or_else(|| anyhow::anyhow!("selected certificate has no usable CNG private key"))?;
    let context = &contexts[selected_in_original];
    let mut cert_chain = context
        .as_chain_der()
        .map_err(|error| anyhow::anyhow!("could not build client certificate chain: {error}"))?
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    if cert_chain
        .first()
        .is_none_or(|certificate| certificate.as_ref() != context.as_der())
    {
        cert_chain.insert(0, CertificateDer::from(context.as_der().to_vec()));
    }
    let certified_key = Arc::new(rustls::sign::CertifiedKey {
        cert: cert_chain,
        key: signing_key,
        ocsp: None,
    });
    Ok(SelectedWindowsCertificate {
        certified_key,
        metadata: selected_metadata,
    })
}

pub(crate) fn current_unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr},
        path::Path,
        sync::Mutex,
    };

    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, SanType,
    };
    use sigil_core::DeviceDiscovery;
    use sigil_mock::MockDiscovery;
    use sigil_proto::backend::v1::{
        AgentAuditEvent, AuthorizeManagedOperationRequest, AuthorizeManagedOperationResponse,
        CompleteRotationRequest, CompleteRotationResponse, ReportAuditRequest, ReportAuditResponse,
        ReportTokensRequest, ReportTokensResponse, RequestGrantRequest, RequestGrantResponse,
        agent_gateway_server::{AgentGateway, AgentGatewayServer},
    };
    use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Certificate as TonicCertificate, Identity, Server, ServerTlsConfig};

    fn metadata(
        thumbprint: &str,
        issuer: &str,
        dns: &str,
        not_before_unix: i64,
        not_after_unix: i64,
    ) -> CertificateMetadata {
        CertificateMetadata {
            thumbprint: thumbprint.into(),
            subject: "CN=test".into(),
            issuer: issuer.into(),
            dns_sans: vec![dns.into()],
            not_before_unix,
            not_after_unix,
            not_after_display: not_after_unix.to_string(),
            client_auth: true,
            has_private_key: true,
        }
    }

    #[test]
    fn certificate_selection_filters_and_prefers_newest() {
        let candidates = vec![
            metadata("01".repeat(20).as_str(), "CN=CA", "station.test", 10, 100),
            metadata("02".repeat(20).as_str(), "CN=CA", "STATION.TEST", 20, 100),
            metadata(
                "03".repeat(20).as_str(),
                "CN=Other",
                "station.test",
                30,
                100,
            ),
        ];
        let index = select_certificate_index(
            &candidates,
            "station.test",
            &CertificateFilters::default(),
            50,
        );
        assert_eq!(index, Some(2));
        let filtered = select_certificate_index(
            &candidates,
            "station.test",
            &CertificateFilters {
                thumbprint: Some(" 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02"),
                issuer: Some("cn=ca"),
            },
            50,
        );
        assert_eq!(filtered, Some(1));
    }

    #[test]
    fn certificate_selection_rejects_bad_eku_dns_validity_and_filters() {
        let mut candidates = vec![
            metadata("01".repeat(20).as_str(), "CN=CA", "station.test", 10, 100),
            metadata("02".repeat(20).as_str(), "CN=CA", "other.test", 10, 100),
            metadata("03".repeat(20).as_str(), "CN=CA", "station.test", 10, 40),
        ];
        candidates[0].client_auth = false;
        candidates[1].has_private_key = false;
        assert_eq!(
            select_certificate_index(
                &candidates,
                "station.test",
                &CertificateFilters::default(),
                50,
            ),
            None
        );
        candidates[0].client_auth = true;
        candidates[1].has_private_key = true;
        assert_eq!(
            select_certificate_index(
                &candidates,
                "station.test",
                &CertificateFilters {
                    issuer: Some("missing"),
                    ..CertificateFilters::default()
                },
                50,
            ),
            None
        );
    }

    #[derive(Default)]
    struct FakeGateway {
        tokens: Arc<Mutex<Vec<backendv1::ObservedToken>>>,
        audit: Arc<Mutex<Vec<AgentAuditEvent>>>,
    }

    #[tonic::async_trait]
    impl AgentGateway for FakeGateway {
        async fn list_profiles(
            &self,
            _request: Request<backendv1::ListProfilesRequest>,
        ) -> Result<tonic::Response<backendv1::ListProfilesResponse>, Status> {
            Err(Status::unimplemented("fake gateway has no profiles"))
        }

        async fn issue_certificate(
            &self,
            _request: Request<backendv1::IssueCertificateRequest>,
        ) -> Result<tonic::Response<backendv1::IssueCertificateResponse>, Status> {
            Err(Status::unimplemented("fake gateway does not issue"))
        }

        async fn request_grant(
            &self,
            _request: Request<RequestGrantRequest>,
        ) -> Result<tonic::Response<RequestGrantResponse>, Status> {
            Err(Status::unimplemented("not used"))
        }

        async fn authorize_managed_operation(
            &self,
            _request: Request<AuthorizeManagedOperationRequest>,
        ) -> Result<tonic::Response<AuthorizeManagedOperationResponse>, Status> {
            Err(Status::unimplemented("not used"))
        }

        async fn complete_rotation(
            &self,
            _request: Request<CompleteRotationRequest>,
        ) -> Result<tonic::Response<CompleteRotationResponse>, Status> {
            Ok(tonic::Response::new(CompleteRotationResponse {}))
        }

        async fn report_audit(
            &self,
            request: Request<ReportAuditRequest>,
        ) -> Result<tonic::Response<ReportAuditResponse>, Status> {
            let mut audit = self.audit.lock().expect("fake audit mutex");
            audit.extend(request.into_inner().events);
            let accepted_through = audit
                .iter()
                .map(|event| event.sequence)
                .max()
                .unwrap_or_default();
            Ok(tonic::Response::new(ReportAuditResponse {
                accepted_through,
            }))
        }

        async fn report_tokens(
            &self,
            request: Request<ReportTokensRequest>,
        ) -> Result<tonic::Response<ReportTokensResponse>, Status> {
            self.tokens
                .lock()
                .expect("fake token mutex")
                .extend(request.into_inner().tokens);
            Ok(tonic::Response::new(ReportTokensResponse {}))
        }
    }

    struct TestCertificates {
        ca_pem: String,
        unrelated_ca_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
        untrusted_client_cert_pem: String,
        untrusted_client_key_pem: String,
    }

    fn test_certificates() -> TestCertificates {
        let (ca_cert, ca_key) = make_ca("Sigil test CA");
        let (other_ca, other_ca_key) = make_ca("Other test CA");
        let (server_cert, server_key) = make_leaf(
            "Sigil fake backend",
            vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca_cert,
            &ca_key,
        );
        let (client_cert, client_key) = make_leaf(
            "Sigil test station",
            vec![SanType::DnsName(
                "station.test".try_into().expect("valid station DNS"),
            )],
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca_cert,
            &ca_key,
        );
        let (untrusted_client_cert, untrusted_client_key) = make_leaf(
            "Untrusted test station",
            vec![SanType::DnsName(
                "station.test".try_into().expect("valid station DNS"),
            )],
            ExtendedKeyUsagePurpose::ClientAuth,
            &other_ca,
            &other_ca_key,
        );
        TestCertificates {
            ca_pem: ca_cert.pem(),
            unrelated_ca_pem: other_ca.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
            untrusted_client_cert_pem: untrusted_client_cert.pem(),
            untrusted_client_key_pem: untrusted_client_key.serialize_pem(),
        }
    }

    fn make_ca(name: &str) -> (Certificate, KeyPair) {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate().expect("CA key");
        let certificate = params.self_signed(&key).expect("CA certificate");
        (certificate, key)
    }

    fn make_leaf(
        common_name: &str,
        subject_alt_names: Vec<SanType>,
        extended_key_usage: ExtendedKeyUsagePurpose,
        issuer: &Certificate,
        issuer_key: &KeyPair,
    ) -> (Certificate, KeyPair) {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.subject_alt_names = subject_alt_names;
        params.extended_key_usages = vec![extended_key_usage];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().expect("leaf key");
        let certificate = params
            .signed_by(&key, issuer, issuer_key)
            .expect("leaf certificate");
        (certificate, key)
    }

    async fn start_fake_gateway(
        certificates: &TestCertificates,
        gateway: FakeGateway,
    ) -> (String, oneshot::Sender<()>, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fake gateway listener");
        let port = listener.local_addr().expect("listener address").port();
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                format!("{}{}", certificates.server_cert_pem, certificates.ca_pem),
                certificates.server_key_pem.clone(),
            ))
            .client_ca_root(TonicCertificate::from_pem(certificates.ca_pem.clone()));
        let (stop, stopped) = oneshot::channel();
        let server = Server::builder()
            .tls_config(tls)
            .expect("fake gateway TLS")
            .add_service(AgentGatewayServer::new(gateway))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            });
        let task = tokio::spawn(async move {
            let _ = server.await;
        });
        (format!("https://127.0.0.1:{port}"), stop, task)
    }

    fn write_backend_config(
        directory: &Path,
        url: &str,
        ca_pem: &str,
        client_cert_pem: &str,
        client_key_pem: &str,
    ) -> GrpcBackend {
        fs::write(directory.join("server-ca.pem"), ca_pem).expect("write server CA");
        fs::write(directory.join("client.pem"), client_cert_pem).expect("write client certificate");
        fs::write(directory.join("client-key.pem"), client_key_pem).expect("write client key");
        let config_path = directory.join("agent.toml");
        fs::write(
            &config_path,
            format!(
                "station_id = \"station.test\"\n[backend]\nurl = \"{url}\"\nserver_ca_file = \"server-ca.pem\"\n[backend.client_certificate]\ncert_file = \"client.pem\"\nkey_file = \"client-key.pem\"\n"
            ),
        )
        .expect("write agent config");
        let config = AgentConfig::load_development(Some(config_path)).expect("load test config");
        GrpcBackend::from_agent_config(&config)
            .expect("configure test backend")
            .expect("test backend configured")
    }

    #[tokio::test]
    async fn grpc_backend_uses_mtls_and_rejects_untrusted_server_and_client_certificates() {
        let certificates = test_certificates();
        let gateway = FakeGateway::default();
        let gateway_state = Arc::clone(&gateway.tokens);
        let audit_state = Arc::clone(&gateway.audit);
        let (url, stop, server) = start_fake_gateway(&certificates, gateway).await;
        let directory = tempfile::tempdir().expect("test directory");
        let backend = write_backend_config(
            directory.path(),
            &url,
            &certificates.ca_pem,
            &certificates.client_cert_pem,
            &certificates.client_key_pem,
        );
        let mock = MockDiscovery::with_example();
        let device = mock.list().expect("mock devices").remove(0);
        let observed = observed_token(&device).expect("mock device with serial");
        assert_eq!(
            token_identity(&device),
            Some((observed.vendor.clone(), observed.serial.clone()))
        );
        backend
            .report_tokens(vec![observed.clone()])
            .await
            .expect("valid mTLS report");
        let accepted = backend
            .report_audit(vec![AgentAuditEvent {
                sequence: 1,
                occurred_at_unix_ms: 1,
                rpc: "BackendCheck".into(),
                operation: String::new(),
                device_id: String::new(),
                token_serial: String::new(),
                caller_os_user: "test-user".into(),
                caller_session_id: 0,
                outcome: "success".into(),
                code: String::new(),
                grant_id: String::new(),
                rotation_id: String::new(),
            }])
            .await
            .expect("valid mTLS audit report");
        assert_eq!(accepted, 1);
        assert_eq!(
            *gateway_state.lock().expect("fake tokens"),
            vec![observed.clone()]
        );
        assert_eq!(audit_state.lock().expect("fake audit").len(), 1);

        let wrong_server_directory = tempfile::tempdir().expect("wrong server CA directory");
        let wrong_server = write_backend_config(
            wrong_server_directory.path(),
            &url,
            &certificates.unrelated_ca_pem,
            &certificates.client_cert_pem,
            &certificates.client_key_pem,
        );
        assert!(
            wrong_server
                .report_tokens(vec![observed.clone()])
                .await
                .is_err()
        );

        let wrong_client_directory =
            tempfile::tempdir().expect("wrong client certificate directory");
        let wrong_client = write_backend_config(
            wrong_client_directory.path(),
            &url,
            &certificates.ca_pem,
            &certificates.untrusted_client_cert_pem,
            &certificates.untrusted_client_key_pem,
        );
        assert!(wrong_client.report_tokens(vec![observed]).await.is_err());
        let _ = stop.send(());
        let _ = server.await;
    }
}
