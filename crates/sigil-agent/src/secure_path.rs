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
    pub audit_dir: PathBuf,
    #[cfg(windows)]
    pub log_file: PathBuf,
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
    #[cfg(windows)]
    let data_dir = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Sigil");
    #[cfg(unix)]
    let data_dir = PathBuf::from("/etc/sigil");

    let config_file = config_override
        .map(Path::to_owned)
        .unwrap_or_else(|| data_dir.join("agent.toml"));
    let config_dir = config_file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if allow_insecure {
        eprintln!(
            "WARNING: --dev-insecure-config skips Sigil path ownership and permission checks. Never use this with real hardware or service mode."
        );
    } else {
        if config_override.is_some() {
            ensure_protected_dir(config_dir)?;
        }
        ensure_protected_dir(&data_dir)?;
        #[cfg(windows)]
        ensure_protected_dir(&data_dir.join("logs"))?;
        ensure_protected_dir(&data_dir.join("audit"))?;
        ensure_protected_dir(config_dir)?;
    }

    let audit_dir = if allow_insecure {
        let directory = config_dir.join("audit");
        std::fs::create_dir_all(&directory).with_context(|| {
            format!(
                "could not create development audit directory {}",
                directory.display()
            )
        })?;
        directory
    } else {
        data_dir.join("audit")
    };

    #[cfg(windows)]
    let paths = AgentPaths {
        config_file,
        audit_dir,
        log_file: data_dir.join("logs").join("agent.log"),
    };
    #[cfg(unix)]
    let paths = AgentPaths {
        config_file,
        audit_dir,
    };
    Ok(paths)
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
