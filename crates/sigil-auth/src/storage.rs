use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use zeroize::Zeroizing;

use crate::{AuthError, Result, config::OidcSettings};

/// Stores the refresh record for one issuer and client. Implementations must keep values private to the
/// current user or machine; the value is a refresh token.
pub trait TokenStore: Send + Sync {
    fn load(&self, target: &str) -> Result<Option<Zeroizing<String>>>;
    fn save(&self, target: &str, value: &str) -> Result<()>;
    fn delete(&self, target: &str) -> Result<()>;
}

/// Credential Manager target name for an issuer/client pair.
pub fn target_name(settings: &OidcSettings) -> String {
    format!("Sigil:oidc:{}|{}", settings.issuer, settings.client_id)
}

/// In-process store used by tests and by platforms without a persistent store yet.
#[derive(Default)]
pub struct MemoryStore {
    values: Mutex<HashMap<String, Zeroizing<String>>>,
}

impl TokenStore for MemoryStore {
    fn load(&self, target: &str) -> Result<Option<Zeroizing<String>>> {
        let values = self
            .values
            .lock()
            .map_err(|_| AuthError::Storage("token store lock is poisoned".into()))?;
        Ok(values.get(target).cloned())
    }

    fn save(&self, target: &str, value: &str) -> Result<()> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| AuthError::Storage("token store lock is poisoned".into()))?;
        values.insert(target.to_owned(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn delete(&self, target: &str) -> Result<()> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| AuthError::Storage("token store lock is poisoned".into()))?;
        values.remove(target);
        Ok(())
    }
}

/// The store used by the CLI and GUI on this platform.
pub fn platform_store() -> Arc<dyn TokenStore> {
    #[cfg(windows)]
    {
        Arc::new(CredentialManagerStore)
    }
    #[cfg(not(windows))]
    {
        Arc::new(MemoryStore::default())
    }
}

/// Windows Credential Manager (generic credential, local-machine persistence).
#[cfg(windows)]
pub struct CredentialManagerStore;

#[cfg(windows)]
fn wide_target(target: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(target)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
impl TokenStore for CredentialManagerStore {
    fn load(&self, target: &str) -> Result<Option<Zeroizing<String>>> {
        use std::ptr::null_mut;
        use windows_sys::Win32::{
            Foundation::{ERROR_NOT_FOUND, GetLastError},
            Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW},
        };

        let target = wide_target(target);
        let mut credential: *mut CREDENTIALW = null_mut();
        // SAFETY: target is NUL-terminated and credential is a valid output pointer.
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
            // SAFETY: GetLastError reads the error from the immediately preceding call.
            let error = unsafe { GetLastError() };
            return if error == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(AuthError::Storage(format!(
                    "Credential Manager read failed ({error})"
                )))
            };
        }
        // SAFETY: CredReadW succeeded, so credential points to a valid record freed exactly once below.
        let value = unsafe {
            let record = &*credential;
            let blob = std::slice::from_raw_parts(
                record.CredentialBlob,
                record.CredentialBlobSize as usize,
            );
            let value = std::str::from_utf8(blob)
                .map(|text| Zeroizing::new(text.to_owned()))
                .map_err(|_| AuthError::Storage("stored sign-in record is not UTF-8".into()));
            CredFree(credential.cast());
            value
        };
        value.map(Some)
    }

    fn save(&self, target: &str, value: &str) -> Result<()> {
        use windows_sys::Win32::Security::Credentials::{
            CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
        };

        let mut target = wide_target(target);
        let blob = value.as_bytes();
        // SAFETY: CREDENTIALW is a plain C struct; every field we use is set below and the rest are zero.
        let mut credential: CREDENTIALW = unsafe { std::mem::zeroed() };
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = target.as_mut_ptr();
        credential.CredentialBlobSize = blob.len() as u32;
        credential.CredentialBlob = blob.as_ptr().cast_mut();
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        // SAFETY: credential and the buffers it references (target, blob) outlive the call.
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(AuthError::Storage("Credential Manager write failed".into()));
        }
        Ok(())
    }

    fn delete(&self, target: &str) -> Result<()> {
        use windows_sys::Win32::{
            Foundation::{ERROR_NOT_FOUND, GetLastError},
            Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW},
        };

        let target = wide_target(target);
        // SAFETY: target is NUL-terminated and lives for the call.
        if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            // SAFETY: GetLastError reads the error from the immediately preceding call.
            let error = unsafe { GetLastError() };
            if error != ERROR_NOT_FOUND {
                return Err(AuthError::Storage(format!(
                    "Credential Manager delete failed ({error})"
                )));
            }
        }
        Ok(())
    }
}
