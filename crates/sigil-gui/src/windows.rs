#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
pub fn restart_as_administrator() -> std::result::Result<(), String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_CANCELLED, GetLastError},
        UI::{
            Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    };

    let executable =
        std::env::current_exe().map_err(|error| format!("could not locate Sigil: {error}"))?;
    let file = wide_string(executable.as_os_str());
    let verb = wide_string(std::ffi::OsStr::new("runas"));
    let mut arguments = Vec::new();
    for argument in std::env::args_os().skip(1) {
        if !arguments.is_empty() {
            arguments.push(u16::from(b' '));
        }
        arguments.extend(quote_windows_argument(&argument));
    }
    arguments.push(0);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: arguments.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..SHELLEXECUTEINFOW::default()
    };
    // SAFETY: All strings are NUL-terminated and info is a writable initialized structure.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        // SAFETY: GetLastError retrieves the error from the immediately preceding call.
        let error = unsafe { GetLastError() };
        if error == ERROR_CANCELLED {
            return Err("Administrator elevation was cancelled.".into());
        }
        return Err(format!(
            "Could not restart Sigil as administrator (Windows error {error})."
        ));
    }
    if !info.hProcess.is_null() {
        // SAFETY: ShellExecuteExW returned this owned process handle.
        unsafe { CloseHandle(info.hProcess) };
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn restart_as_administrator() -> std::result::Result<(), String> {
    Err("Administrator relaunch is only available on Windows.".into())
}

#[cfg(windows)]
pub fn open_signin_options() -> std::result::Result<(), String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

    let verb = wide_string(std::ffi::OsStr::new("open"));
    let target = wide_string(std::ffi::OsStr::new("ms-settings:signinoptions"));
    // SAFETY: verb and target are NUL-terminated; optional parameters and directory are null.
    let result = unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as usize <= 32 {
        Err("Could not open Windows sign-in settings.".into())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn open_signin_options() -> std::result::Result<(), String> {
    Err("Windows sign-in settings are only available on Windows.".into())
}

#[cfg(windows)]
pub fn copy_to_clipboard(value: &str) -> std::result::Result<(), String> {
    use std::{mem::size_of, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{GlobalFree, HWND},
        System::{
            DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData},
            Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
            Ole::CF_UNICODETEXT,
        },
    };

    struct ClipboardGuard;

    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            // SAFETY: This guard is created only after OpenClipboard succeeds.
            unsafe { CloseClipboard() };
        }
    }

    // SAFETY: A null owner selects the current task's clipboard window.
    if unsafe { OpenClipboard(null_mut::<core::ffi::c_void>() as HWND) } == 0 {
        return Err("Windows clipboard is unavailable.".into());
    }
    let _clipboard = ClipboardGuard;
    // SAFETY: The current process owns the open clipboard.
    if unsafe { EmptyClipboard() } == 0 {
        return Err("Could not clear the Windows clipboard.".into());
    }
    let mut wide = value
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let size = wide.len() * size_of::<u16>();
    // SAFETY: GlobalAlloc requests movable clipboard-compatible storage.
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, size) };
    if memory.is_null() {
        return Err("Could not allocate clipboard storage.".into());
    }
    // SAFETY: memory is a newly allocated movable global-memory handle.
    let destination = unsafe { GlobalLock(memory) }.cast::<u16>();
    if destination.is_null() {
        // SAFETY: memory remains owned by this function until SetClipboardData succeeds.
        unsafe { GlobalFree(memory) };
        return Err("Could not lock clipboard storage.".into());
    }
    // SAFETY: destination points to a writable region of at least size bytes.
    unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), destination, wide.len()) };
    // SAFETY: memory was successfully locked immediately above.
    unsafe { GlobalUnlock(memory) };
    // Avoid retaining the extra UTF-16 copy after transfer.
    wide.fill(0);
    // SAFETY: memory contains a NUL-terminated CF_UNICODETEXT string; successful transfer assigns ownership to Windows.
    if unsafe { SetClipboardData(CF_UNICODETEXT.into(), memory) }.is_null() {
        // SAFETY: ownership was not transferred because SetClipboardData failed.
        unsafe { GlobalFree(memory) };
        return Err("Could not copy the management key.".into());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn copy_to_clipboard(_value: &str) -> std::result::Result<(), String> {
    Err("Clipboard access is only available on Windows.".into())
}

#[cfg(windows)]
fn wide_string(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn quote_windows_argument(value: &std::ffi::OsStr) -> Vec<u16> {
    let value = value.encode_wide().collect::<Vec<_>>();
    if !value.is_empty() && !value.iter().any(|unit| matches!(*unit, 0x20 | 0x09 | 0x22)) {
        return value;
    }
    let mut quoted = vec![0x22];
    let mut backslashes = 0usize;
    for unit in value {
        if unit == 0x5c {
            backslashes += 1;
        } else if unit == 0x22 {
            quoted.extend(std::iter::repeat_n(0x5c, backslashes * 2 + 1));
            quoted.push(unit);
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n(0x5c, backslashes));
            quoted.push(unit);
            backslashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n(0x5c, backslashes * 2));
    quoted.push(0x22);
    quoted
}
