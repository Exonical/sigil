use std::path::PathBuf;

use serde::Deserialize;
use url::Url;

use crate::{AuthError, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidcSettings {
    pub issuer: Url,
    pub client_id: String,
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct RawSettings {
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub ca_file: Option<PathBuf>,
}

/// Reads sign-in settings from machine policy, with debug-only environment overrides.
pub fn load_settings() -> Result<Option<OidcSettings>> {
    #[cfg_attr(not(debug_assertions), allow(unused_mut))]
    let mut raw = read_policy()?;
    #[cfg(debug_assertions)]
    {
        if let Ok(value) = std::env::var("SIGIL_OIDC_ISSUER") {
            raw.issuer = Some(value);
        }
        if let Ok(value) = std::env::var("SIGIL_OIDC_CLIENT_ID") {
            raw.client_id = Some(value);
        }
        if let Ok(value) = std::env::var("SIGIL_OIDC_CA_FILE") {
            raw.ca_file = Some(PathBuf::from(value));
        }
    }
    settings_from_raw(raw)
}

fn settings_from_raw(raw: RawSettings) -> Result<Option<OidcSettings>> {
    match (raw.issuer, raw.client_id) {
        (None, None) => Ok(None),
        (Some(issuer), Some(client_id)) => {
            let issuer = Url::parse(&issuer)
                .map_err(|_| AuthError::Config("the OIDC issuer is not a valid URL".into()))?;
            if issuer.scheme() != "https" || issuer.host_str().is_none() {
                return Err(AuthError::Config(
                    "the OIDC issuer must be an https URL".into(),
                ));
            }
            if client_id.trim().is_empty() {
                return Err(AuthError::Config("the OIDC client ID is empty".into()));
            }
            Ok(Some(OidcSettings {
                issuer,
                client_id,
                ca_file: raw.ca_file,
            }))
        }
        _ => Err(AuthError::Config(
            "the OIDC issuer and client ID must be configured together".into(),
        )),
    }
}

#[cfg(windows)]
fn read_policy() -> Result<RawSettings> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND},
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, RRF_RT_REG_SZ, RegCloseKey, RegGetValueW,
            RegOpenKeyExW,
        },
    };

    let wide = |value: &str| -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let key_name = wide(r"SOFTWARE\Policies\Sigil");
    let mut key: HKEY = null_mut();
    // SAFETY: key_name is NUL-terminated and key is a valid writable output pointer.
    let open = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_name.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if open == ERROR_FILE_NOT_FOUND || open == ERROR_PATH_NOT_FOUND {
        return Ok(RawSettings::default());
    }
    if open != 0 {
        return Err(AuthError::Config("machine policy could not be read".into()));
    }

    let read = |name: &str| -> Result<Option<String>> {
        let value_name = wide(name);
        let mut size_bytes = 0u32;
        // SAFETY: key is open; value_name is NUL-terminated; a null buffer requests the size only.
        let status = unsafe {
            RegGetValueW(
                key,
                null_mut(),
                value_name.as_ptr(),
                RRF_RT_REG_SZ,
                null_mut(),
                null_mut(),
                &mut size_bytes,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 && status != ERROR_MORE_DATA {
            return Err(AuthError::Config(format!(
                "machine policy value {name} is unreadable"
            )));
        }
        let mut buffer = vec![0u16; (size_bytes as usize).div_ceil(2).max(1)];
        let mut size = (buffer.len() * 2) as u32;
        // SAFETY: buffer is writable for size bytes; key and value_name are valid as above.
        let status = unsafe {
            RegGetValueW(
                key,
                null_mut(),
                value_name.as_ptr(),
                RRF_RT_REG_SZ,
                null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status != 0 {
            return Err(AuthError::Config(format!(
                "machine policy value {name} is unreadable"
            )));
        }
        let units = (size as usize / 2).saturating_sub(1);
        Ok(Some(String::from_utf16_lossy(&buffer[..units])))
    };
    let result = (|| -> Result<RawSettings> {
        Ok(RawSettings {
            issuer: read("OidcIssuer")?,
            client_id: read("OidcClientId")?,
            ca_file: read("OidcCaFile")?.map(PathBuf::from),
        })
    })();
    // SAFETY: key was returned by RegOpenKeyExW above and is closed exactly once.
    unsafe { RegCloseKey(key) };
    result
}

#[cfg(unix)]
fn read_policy() -> Result<RawSettings> {
    use std::os::unix::fs::MetadataExt;

    #[derive(Deserialize)]
    struct ClientFile {
        #[serde(default)]
        oidc: RawSettings,
    }

    let path = std::path::Path::new("/etc/sigil/client.toml");
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RawSettings::default());
        }
        Err(_) => return Err(AuthError::Config("client policy file is unreadable".into())),
    };
    if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(AuthError::Config(
            "client policy file must be a root-owned, non-writable regular file".into(),
        ));
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|_| AuthError::Config("client policy file is unreadable".into()))?;
    toml::from_str::<ClientFile>(&contents)
        .map(|file| file.oidc)
        .map_err(|_| AuthError::Config("client policy file is invalid".into()))
}

#[cfg(not(any(windows, unix)))]
fn read_policy() -> Result<RawSettings> {
    Ok(RawSettings::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(issuer: Option<&str>, client_id: Option<&str>) -> RawSettings {
        RawSettings {
            issuer: issuer.map(str::to_owned),
            client_id: client_id.map(str::to_owned),
            ca_file: None,
        }
    }

    #[test]
    fn settings_require_an_https_issuer_and_both_values() {
        assert_eq!(settings_from_raw(raw(None, None)).unwrap(), None);
        assert!(settings_from_raw(raw(Some("https://idp.example/app/"), None)).is_err());
        assert!(settings_from_raw(raw(Some("http://idp.example/app/"), Some("sigil"))).is_err());
        assert!(settings_from_raw(raw(Some("https://idp.example/app/"), Some(" "))).is_err());
        let settings = settings_from_raw(raw(Some("https://idp.example/app/"), Some("sigil")))
            .unwrap()
            .unwrap();
        assert_eq!(settings.client_id, "sigil");
    }
}
