use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    mem::{offset_of, size_of},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr::{null_mut, slice_from_raw_parts},
};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_INVALID_OWNER, GetLastError, HLOCAL,
        LocalFree,
    },
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, GetFileAttributesW,
        GetFileInformationByHandle, INVALID_FILE_ATTRIBUTES,
    },
    System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    },
};

const PROTECTED_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const WRITE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: This allocation was returned by a Windows LocalAlloc-based API.
        unsafe { LocalFree(self.0 as HLOCAL) };
    }
}

pub(super) fn ensure_protected_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => validate_existing_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_protected_directory(path)?;
            validate_existing_directory(path)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "refusing to trust Sigil directory {} because it could not be inspected; delete the directory and let sigil-agent recreate it, or apply SDDL {PROTECTED_SDDL} as an administrator",
                path.display()
            )
        }),
    }
}

fn create_protected_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot create protected directory {} without a parent",
                path.display()
            )
        })?;
    if !parent.is_dir() {
        bail!(
            "cannot create protected directory {} because its parent {} does not exist",
            path.display(),
            parent.display()
        );
    }
    let descriptor = descriptor_from_sddl(PROTECTED_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide = path_wide(path);
    // SAFETY: The descriptor and SECURITY_ATTRIBUTES remain valid for the synchronous call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        // SAFETY: GetLastError has no pointer arguments and reads the calling thread's last error.
        let error = unsafe { GetLastError() };
        if error == ERROR_ALREADY_EXISTS {
            return Ok(());
        }
        if error == ERROR_INVALID_OWNER || error == ERROR_ACCESS_DENIED {
            bail!(
                "sigil-agent must run elevated (Run as administrator) or as the installed SigilAgent service to create {}; for mock development use `sigil-agent run --mock --dev-insecure-config`",
                path.display()
            );
        }
        return Err(std::io::Error::from_raw_os_error(error as i32)).with_context(|| {
            format!(
                "could not create protected directory {}; create it as an administrator with SDDL {PROTECTED_SDDL}",
                path.display()
            )
        });
    }
    Ok(())
}

fn validate_existing_directory(path: &Path) -> Result<()> {
    let wide = path_wide(path);
    // SAFETY: `wide` is NUL-terminated and lives across the call.
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(unsafe_directory(
            path,
            &format!(
                "Windows could not inspect the directory: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(unsafe_directory(path, "it is a reparse point"));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(unsafe_directory(path, "it is not a directory"));
    }
    let descriptor = security_descriptor_for_path(path)?;
    // SAFETY: The descriptor was returned by GetNamedSecurityInfoW and is owned by its guard.
    let trusted = unsafe { evaluate_security_descriptor(descriptor.0) };
    if !trusted {
        return Err(unsafe_directory(
            path,
            "its owner or DACL grants an untrusted principal write or security-control rights",
        ));
    }
    Ok(())
}

fn unsafe_directory(path: &Path, reason: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "refusing unsafe Sigil directory {}: {reason}. Delete the directory and let sigil-agent recreate it, or apply SDDL {PROTECTED_SDDL} as an administrator",
        path.display()
    )
}

fn security_descriptor_for_path(path: &Path) -> Result<LocalAllocation> {
    let wide = path_wide(path);
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `wide` is NUL-terminated and descriptor is a writable output pointer.
    let error = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32))
            .with_context(|| {
                format!(
                    "refusing to trust {} because its owner/DACL could not be read; delete the directory and let sigil-agent recreate it, or apply SDDL {PROTECTED_SDDL} as an administrator",
                    path.display()
                )
            });
    }
    Ok(LocalAllocation(descriptor.cast::<c_void>()))
}

fn descriptor_from_sddl(sddl: &str) -> Result<LocalAllocation> {
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: SDDL is NUL-terminated and descriptor is a writable output pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("invalid security descriptor SDDL");
    }
    Ok(LocalAllocation(descriptor.cast::<c_void>()))
}

unsafe fn evaluate_security_descriptor(descriptor: PSECURITY_DESCRIPTOR) -> bool {
    let mut owner: PSID = null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: descriptor is a valid security descriptor held by its caller.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0 {
        return false;
    }
    // SAFETY: owner is the SID pointer returned from the valid descriptor.
    let Some(owner_sid) = (unsafe { sid_string(owner) }) else {
        return false;
    };
    if owner_sid != "S-1-5-18" && owner_sid != "S-1-5-32-544" {
        return false;
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: descriptor is valid and all output pointers are writable.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return false;
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is owned by descriptor and information is a writable output buffer.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return false;
    }
    for index in 0..information.AceCount {
        let mut ace_pointer: *mut c_void = null_mut();
        // SAFETY: index is bounded by the ACE count from GetAclInformation.
        if unsafe { GetAce(dacl, index, &mut ace_pointer) } == 0 || ace_pointer.is_null() {
            return false;
        }
        // SAFETY: GetAce returned an ACE pointer inside the valid DACL.
        let header = unsafe { &*ace_pointer.cast::<ACE_HEADER>() };
        match header.AceType as u32 {
            ACCESS_ALLOWED_ACE_TYPE => {
                // SAFETY: The header identifies this as an ACCESS_ALLOWED_ACE.
                let ace = unsafe { &*ace_pointer.cast::<ACCESS_ALLOWED_ACE>() };
                let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
                // SAFETY: SidStart begins the SID payload of a basic allowed ACE.
                let sid = unsafe { ace_pointer.cast::<u8>().add(sid_offset).cast::<c_void>() };
                // SAFETY: sid points into the ACE returned by GetAce.
                let Some(sid) = (unsafe { sid_string(sid) }) else {
                    return false;
                };
                let trusted_principal =
                    sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == TRUSTED_INSTALLER_SID;
                if ace.Mask & WRITE_RIGHTS != 0 && !trusted_principal {
                    return false;
                }
            }
            ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_COMPOUND_ACE_TYPE => return false,
            _ => {}
        }
    }
    true
}

unsafe fn sid_string(sid: PSID) -> Option<String> {
    let mut text = null_mut();
    // SAFETY: sid points to a SID contained in a valid security descriptor or token.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return None;
    }
    let text = LocalAllocation(text.cast::<c_void>());
    let mut length = 0usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 string.
    unsafe {
        while *text.0.cast::<u16>().add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: The slice covers initialized UTF-16 code units before the terminator.
    let slice = unsafe { &*slice_from_raw_parts(text.0.cast::<u16>(), length) };
    Some(String::from_utf16_lossy(slice))
}

pub(super) fn open_service_log(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .create(true)
        .append(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .with_context(|| format!("could not open service log {}", path.display()))?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file is open and information is a writable output buffer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not inspect service log {}", path.display()));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!(
            "refusing service log {} because it is a reparse point",
            path.display()
        );
    }
    if information.nNumberOfLinks > 1 {
        bail!(
            "refusing service log {} because it has {} hard links",
            path.display(),
            information.nNumberOfLinks
        );
    }
    Ok(file)
}

fn path_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{descriptor_from_sddl, evaluate_security_descriptor};

    fn accepted(sddl: &str) -> bool {
        let descriptor = descriptor_from_sddl(sddl).expect("valid SDDL");
        // SAFETY: descriptor was built in memory by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { evaluate_security_descriptor(descriptor.0) }
    }

    #[test]
    fn ace_evaluator_accepts_only_trusted_write_grants() {
        let baseline = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)";
        assert!(accepted(baseline));
        for extra in [
            "(A;;FW;;;BU)",
            "(A;;GA;;;WD)",
            "(A;;WD;;;AU)",
            "(A;OICIIO;GA;;;CO)",
        ] {
            assert!(!accepted(&format!("{baseline}{extra}")), "accepted {extra}");
        }
        assert!(!accepted("O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)"));
    }

    #[test]
    fn rejects_fresh_user_owned_temp_directory() {
        let path = std::env::temp_dir().join(format!(
            "sigil-unprotected-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        assert!(super::ensure_protected_dir(&path).is_err());
        std::fs::remove_dir(path).unwrap();
    }
}
