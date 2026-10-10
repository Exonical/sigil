use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

#[cfg(windows)]
#[path = "secure_path_windows.rs"]
mod platform;
#[cfg(unix)]
#[path = "secure_path_unix.rs"]
mod platform;

#[derive(Debug, Clone)]
pub struct AgentPaths {
    pub config_file: PathBuf,
    pub default_data_dir: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub enum ProtectedFileMode {
    Read,
    Append,
    Truncate,
    CreateNew,
}

pub fn ensure_protected_dir(path: &Path) -> Result<()> {
    platform::ensure_protected_dir(path)
}

pub fn open_protected_file(path: &Path, mode: ProtectedFileMode) -> Result<std::fs::File> {
    platform::open_protected_file(path, mode)
}

pub fn replace_protected_file(source: &Path, destination: &Path) -> Result<()> {
    platform::replace_protected_file(source, destination)
}

#[cfg(windows)]
pub fn open_service_log(path: &Path) -> Result<std::fs::File> {
    open_protected_file(path, ProtectedFileMode::Append)
}

pub fn prepare_agent_paths(config_override: Option<&Path>) -> Result<AgentPaths> {
    prepare_agent_paths_inner(config_override, false)
}

#[cfg(debug_assertions)]
pub fn prepare_agent_paths_insecure(config_override: Option<&Path>) -> Result<AgentPaths> {
    prepare_agent_paths_inner(config_override, true)
}

fn prepare_agent_paths_inner(
    config_override: Option<&Path>,
    allow_insecure: bool,
) -> Result<AgentPaths> {
    let system_dir = system_data_dir();
    let config_file = config_override
        .map(Path::to_owned)
        .unwrap_or_else(|| system_dir.join("agent.toml"));
    let config_dir = config_file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if allow_insecure {
        eprintln!(
            "WARNING: --dev-insecure-config skips Sigil path ownership and permission checks. Never use this with real hardware or service mode."
        );
        return Ok(AgentPaths {
            default_data_dir: config_dir.to_owned(),
            config_file,
        });
    }
    ensure_protected_dir(config_dir)?;
    Ok(AgentPaths {
        config_file,
        default_data_dir: system_dir,
    })
}

#[cfg(windows)]
fn system_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Sigil")
}

#[cfg(unix)]
fn system_data_dir() -> PathBuf {
    PathBuf::from("/etc/sigil")
}

/// Creates or validates the agent's protected data directory and the subdirectories it owns.
pub fn prepare_data_dir(data_dir: &Path) -> Result<()> {
    let result: Result<()> = (|| {
        ensure_protected_dir(data_dir)?;
        #[cfg(windows)]
        ensure_protected_dir(&data_dir.join("logs"))?;
        ensure_protected_dir(&data_dir.join("audit"))
    })();
    result.map_err(|error| map_data_dir_error(data_dir, error))
}

/// Turns an access-denied failure on the data directory into an actionable startup error.
/// Every other failure keeps its cause and is only given context.
pub fn map_data_dir_error(data_dir: &Path, error: anyhow::Error) -> anyhow::Error {
    let access_denied = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
    });
    if access_denied {
        anyhow::anyhow!(
            "the agent data directory {} is not writable by this process; run the agent elevated or as the SigilAgent service",
            data_dir.display()
        )
    } else {
        error.context(format!(
            "could not prepare the agent data directory {}",
            data_dir.display()
        ))
    }
}

pub(crate) fn trusted_key_path(
    config_dir: &Path,
    requested: &Path,
    allow_insecure: bool,
) -> Result<PathBuf> {
    let config_dir = config_dir
        .canonicalize()
        .or_else(|error| {
            if allow_insecure {
                Ok(config_dir.to_owned())
            } else {
                Err(error)
            }
        })
        .with_context(|| {
            format!(
                "could not canonicalize config directory {}",
                config_dir.display()
            )
        })?;
    let candidate = if requested.is_absolute() {
        requested.to_owned()
    } else {
        config_dir.join(requested)
    };
    if allow_insecure {
        return Ok(candidate);
    }
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("could not canonicalize grant key {}", candidate.display()))?;
    let parent = canonical.parent().ok_or_else(|| {
        anyhow::anyhow!("grant key has no parent directory: {}", canonical.display())
    })?;
    if !canonical.starts_with(&config_dir) {
        bail!(
            "grant key {} must resolve inside the protected config directory {}",
            canonical.display(),
            config_dir.display()
        );
    }
    ensure_protected_dir(parent)?;
    Ok(canonical)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::ensure_protected_dir;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn rejects_user_owned_or_group_world_writable_directories() {
        use std::os::unix::fs::PermissionsExt;

        let path = PathBuf::from(std::env::temp_dir()).join(format!(
            "sigil-unprotected-{}-{}",
            std::process::id(),
            NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(ensure_protected_dir(&path).is_err());
        fs::remove_dir(path).unwrap();
    }
}

#[cfg(test)]
mod data_dir_tests {
    use std::path::Path;

    use super::map_data_dir_error;

    #[test]
    fn access_denied_on_the_data_directory_names_the_path_and_the_fix() {
        let error = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .context("could not create protected directory");
        let mapped = map_data_dir_error(Path::new("data"), error);
        assert_eq!(
            mapped.to_string(),
            "the agent data directory data is not writable by this process; run the agent elevated or as the SigilAgent service"
        );
    }

    #[test]
    fn other_failures_keep_their_cause_and_gain_context() {
        let error = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound));
        let mapped = map_data_dir_error(Path::new("data"), error);
        assert_eq!(
            mapped.to_string(),
            "could not prepare the agent data directory data"
        );
        assert!(mapped.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
        }));
    }
}
