use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use p256::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};
use serde::Deserialize;
use sigil_core::CredentialError;

use crate::grant::{GrantProvider, GrantVerifier, Unconfigured};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub station_id: Option<String>,
    pub grant_keys: HashMap<String, PathBuf>,
    pub backend: Option<BackendConfig>,
    #[serde(skip)]
    config_dir: PathBuf,
    #[serde(skip)]
    allow_insecure_paths: bool,
    #[serde(skip)]
    audit_dir: PathBuf,
    #[cfg(feature = "dev-grants")]
    pub dev_signer_key: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct BackendConfig {
    pub url: String,
    pub server_ca_file: Option<PathBuf>,
    pub client_certificate: BackendClientCertificate,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct BackendClientCertificate {
    pub store: BackendCertificateStore,
    pub thumbprint: Option<String>,
    pub issuer: Option<String>,
    #[cfg(debug_assertions)]
    pub expected_dns_name: Option<String>,
    #[cfg(any(debug_assertions, test))]
    pub cert_file: Option<PathBuf>,
    #[cfg(any(debug_assertions, test))]
    pub key_file: Option<PathBuf>,
}

impl Default for BackendClientCertificate {
    fn default() -> Self {
        Self {
            store: BackendCertificateStore::LocalMachine,
            thumbprint: None,
            issuer: None,
            #[cfg(debug_assertions)]
            expected_dns_name: None,
            #[cfg(any(debug_assertions, test))]
            cert_file: None,
            #[cfg(any(debug_assertions, test))]
            key_file: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum BackendCertificateStore {
    #[default]
    LocalMachine,
    CurrentUser,
}

impl BackendConfig {
    pub fn trusted_server_ca(&self, config: &AgentConfig) -> anyhow::Result<Option<PathBuf>> {
        self.server_ca_file
            .as_deref()
            .map(|path| config.key_path(path))
            .transpose()
    }
}

impl AgentConfig {
    pub fn load(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let paths = crate::secure_path::prepare_agent_paths(path.as_deref())?;
        Self::load_from_path(paths.config_file, paths.audit_dir, false)
    }

    #[cfg(debug_assertions)]
    pub fn load_development(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let paths = crate::secure_path::prepare_agent_paths_insecure(path.as_deref())?;
        Self::load_from_path(paths.config_file, paths.audit_dir, true)
    }

    fn load_from_path(
        path: PathBuf,
        audit_dir: PathBuf,
        allow_insecure_paths: bool,
    ) -> anyhow::Result<Self> {
        let raw_parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut config_dir = match raw_parent.canonicalize() {
            Ok(parent) => parent,
            Err(_error) if allow_insecure_paths => {
                if raw_parent.is_absolute() {
                    raw_parent.to_owned()
                } else {
                    std::env::current_dir()?.join(raw_parent)
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "could not canonicalize config directory {}",
                        raw_parent.display()
                    )
                });
            }
        };
        let contents = match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let canonical_path = path.canonicalize().with_context(|| {
                    format!("could not canonicalize agent config {}", path.display())
                })?;
                let canonical_parent = canonical_path
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("agent config has no parent directory"))?;
                if !allow_insecure_paths && canonical_parent != config_dir {
                    anyhow::bail!(
                        "agent config {} resolves outside its protected config directory {}",
                        path.display(),
                        config_dir.display()
                    );
                }
                if allow_insecure_paths {
                    config_dir = canonical_parent.to_owned();
                }
                Some(std::fs::read_to_string(&canonical_path).with_context(|| {
                    format!("could not read agent config {}", canonical_path.display())
                })?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("could not inspect agent config {}", path.display()));
            }
        };
        let mut config = if let Some(contents) = contents {
            toml::from_str(&contents)
                .with_context(|| format!("could not parse agent config {}", path.display()))?
        } else {
            Self::default()
        };
        config.config_dir = config_dir;
        config.allow_insecure_paths = allow_insecure_paths;
        config.audit_dir = audit_dir;
        if let Some(backend) = &config.backend {
            if backend.url.trim().is_empty() || !backend.url.starts_with("https://") {
                anyhow::bail!("backend.url must be an HTTPS URL");
            }
            #[cfg(not(debug_assertions))]
            if backend.client_certificate.store == BackendCertificateStore::CurrentUser {
                anyhow::bail!("release builds only support LocalMachine\\My backend certificates");
            }
            #[cfg(any(debug_assertions, test))]
            if backend.client_certificate.cert_file.is_some()
                != backend.client_certificate.key_file.is_some()
            {
                anyhow::bail!(
                    "backend.client_certificate.cert_file and key_file must be set together"
                );
            }
            #[cfg(any(debug_assertions, test))]
            if let (Some(cert_file), Some(key_file)) = (
                backend.client_certificate.cert_file.as_deref(),
                backend.client_certificate.key_file.as_deref(),
            ) {
                config.key_path(cert_file)?;
                config.key_path(key_file)?;
            }
        }
        Ok(config)
    }

    fn key_path(&self, path: &Path) -> anyhow::Result<PathBuf> {
        crate::secure_path::trusted_key_path(&self.config_dir, path, self.allow_insecure_paths)
    }

    pub(crate) fn trusted_path(&self, path: &Path) -> anyhow::Result<PathBuf> {
        self.key_path(path)
    }

    pub fn audit_dir(&self) -> &Path {
        &self.audit_dir
    }

    pub fn station_id(&self) -> String {
        self.station_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| hostname().to_ascii_lowercase())
    }

    pub fn backend(&self) -> anyhow::Result<Option<(BackendConfig, Option<PathBuf>)>> {
        self.backend
            .as_ref()
            .map(|backend| Ok((backend.clone(), backend.trusted_server_ca(self)?)))
            .transpose()
    }

    pub fn authorization(&self) -> anyhow::Result<(Arc<dyn GrantProvider>, Arc<GrantVerifier>)> {
        let mut trusted = HashMap::new();
        for (key_id, requested_path) in &self.grant_keys {
            let path = self.key_path(requested_path)?;
            let pem = std::fs::read_to_string(&path)
                .with_context(|| format!("could not read grant public key {}", path.display()))?;
            let key = VerifyingKey::from_public_key_pem(&pem).map_err(|error| {
                CredentialError::OperationUnauthorized(format!(
                    "invalid grant public key {key_id}: {error}"
                ))
            })?;
            trusted.insert(key_id.clone(), key);
        }
        let provider: Arc<dyn GrantProvider> = configured_dev_provider(self, &mut trusted)?;
        Ok((provider, Arc::new(GrantVerifier::new(trusted))))
    }
}

#[cfg(feature = "dev-grants")]
fn configured_dev_provider(
    config: &AgentConfig,
    trusted: &mut HashMap<String, VerifyingKey>,
) -> anyhow::Result<Arc<dyn GrantProvider>> {
    if let Some(requested_path) = &config.dev_signer_key {
        let path = config.key_path(requested_path)?;
        let signer =
            crate::grant::DevSigner::from_pem_path(config.station_id(), "dev-grants", &path)?;
        trusted.insert("dev-grants".into(), signer.verifying_key());
        return Ok(Arc::new(signer));
    }
    Ok(Arc::new(Unconfigured))
}

#[cfg(not(feature = "dev-grants"))]
fn configured_dev_provider(
    _config: &AgentConfig,
    _trusted: &mut HashMap<String, VerifyingKey>,
) -> anyhow::Result<Arc<dyn GrantProvider>> {
    Ok(Arc::new(Unconfigured))
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "sigil-station".into())
}
