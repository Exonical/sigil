use std::{
    ffi::c_void,
    io,
    mem::{size_of, size_of_val},
    ptr::{null_mut, slice_from_raw_parts},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
    Security::Authorization::ConvertSidToStringSidW,
    Security::{
        GetTokenInformation, RevertToSelf, TOKEN_QUERY, TOKEN_USER, TokenSessionId, TokenUser,
    },
    System::{
        Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient},
        RemoteDesktop::WTSGetActiveConsoleSessionId,
        Threading::{GetCurrentThread, OpenThreadToken},
    },
};

use super::CallerIdentity;

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: This handle was returned by OpenThreadToken and is owned here.
        unsafe { CloseHandle(self.0) };
    }
}

struct SidString(windows_sys::core::PWSTR);

impl Drop for SidString {
    fn drop(&mut self) {
        // SAFETY: ConvertSidToStringSidW allocates this pointer with LocalAlloc.
        unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
    }
}

struct RevertGuard(bool);

impl RevertGuard {
    fn revert(&mut self) -> io::Result<()> {
        // SAFETY: The current thread was impersonating the connected named-pipe client.
        if unsafe { RevertToSelf() } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.0 = false;
        Ok(())
    }
}

impl Drop for RevertGuard {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: Best-effort cleanup for the impersonation established by this function.
            unsafe { RevertToSelf() };
        }
    }
}

pub(crate) fn identify_named_pipe_client(pipe: HANDLE) -> io::Result<CallerIdentity> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a connected NamedPipeServer handle and `pid` is writable.
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The call impersonates the client connected to the supplied server pipe.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut revert = RevertGuard(true);
    let mut token: HANDLE = null_mut();
    // SAFETY: We are impersonating the pipe client; token receives an owned query handle.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _token = TokenHandle(token);

    let mut needed = 0u32;
    // SAFETY: A null buffer with zero size is the documented size-query call.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut user_buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: The aligned buffer is large enough according to the first size query.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            user_buffer.as_mut_ptr().cast::<c_void>(),
            (user_buffer.len() * size_of::<usize>()) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation filled the buffer with a TOKEN_USER structure.
    let token_user = unsafe { &*user_buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text: windows_sys::core::PWSTR = null_mut();
    // SAFETY: The SID pointer comes from the valid TOKEN_USER returned above.
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_text = SidString(sid_text);
    let mut sid_len = 0usize;
    // SAFETY: The returned SID string is NUL-terminated and owned by SidString.
    unsafe {
        while *sid_text.0.add(sid_len) != 0 {
            sid_len += 1;
        }
    }
    // SAFETY: The slice spans the initialized UTF-16 chars before the terminating NUL.
    let sid = unsafe { &*slice_from_raw_parts(sid_text.0, sid_len) };
    let os_user = String::from_utf16_lossy(sid);

    let mut session_id = 0u32;
    let mut returned = 0u32;
    // SAFETY: The output pointers refer to initialized writable buffers of the stated sizes.
    if unsafe {
        GetTokenInformation(
            token,
            TokenSessionId,
            (&mut session_id as *mut u32).cast::<c_void>(),
            size_of_val(&session_id) as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    revert.revert()?;
    Ok(CallerIdentity {
        os_user,
        session_id: Some(session_id),
        pid,
    })
}

pub(crate) fn active_console_session() -> u32 {
    // SAFETY: WTSGetActiveConsoleSessionId takes no pointers and has no preconditions.
    unsafe { WTSGetActiveConsoleSessionId() }
}
