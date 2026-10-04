use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    ptr::{null_mut, slice_from_raw_parts},
};

use tokio::net::windows::named_pipe::NamedPipeClient;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree},
    Security::Authorization::ConvertSidToStringSidW,
    Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT, SYNCHRONIZE,
    },
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{
            GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use super::{debug_bypass, trust_server};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: OpenProcess and OpenProcessToken return owned handles held only here.
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalString(windows_sys::core::PWSTR);

impl Drop for LocalString {
    fn drop(&mut self) {
        // SAFETY: ConvertSidToStringSidW allocates this pointer with LocalAlloc.
        unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
    }
}

pub(crate) fn open_named_pipe(endpoint: &str) -> io::Result<NamedPipeClient> {
    let name: Vec<u16> = std::ffi::OsStr::new(endpoint)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let access = FILE_READ_DATA
        | FILE_WRITE_DATA
        | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES
        | SYNCHRONIZE;
    // SAFETY: The pipe name is NUL-terminated; the remaining pointers are null by contract.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            0,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: This is a fresh, owned handle to an opened named pipe created with FILE_FLAG_OVERLAPPED.
    // Ownership transfers to Tokio's NamedPipeClient here.
    unsafe { NamedPipeClient::from_raw_handle(handle) }
}

pub(crate) fn named_pipe_server_is_trusted(pipe: &NamedPipeClient) -> bool {
    let bypass = debug_bypass();
    let mut server_pid = 0u32;
    // SAFETY: The pipe is connected and server_pid is a valid writable output pointer.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server_pid) } == 0 {
        return trust_server(0, current_process_id(), false, false, bypass);
    }
    let own_pid = current_process_id();
    if server_pid == own_pid {
        return trust_server(server_pid, own_pid, false, false, bypass);
    }

    let process = unsafe {
        // SAFETY: The PID came from GetNamedPipeServerProcessId; no handle is inherited.
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid)
    };
    if process.is_null() {
        return trust_server(server_pid, own_pid, false, false, bypass);
    }
    let _process = OwnedHandle(process);
    let mut token = null_mut();
    // SAFETY: process is a valid query handle and token is a writable output pointer.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return trust_server(server_pid, own_pid, false, false, bypass);
    }
    let _token = OwnedHandle(token);

    let is_local_system = token_user_sid(token).is_some_and(|sid| sid == "S-1-5-18");
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: elevation and returned are valid writable buffers of the supplied sizes.
    let is_elevated = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        ) != 0
            && elevation.TokenIsElevated != 0
    };
    trust_server(server_pid, own_pid, is_local_system, is_elevated, bypass)
}

fn token_user_sid(token: HANDLE) -> Option<String> {
    let mut needed = 0u32;
    // SAFETY: A null buffer and zero length request the required TokenUser buffer size.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: The aligned buffer is at least the size returned by the previous query.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            (buffer.len() * size_of::<usize>()) as u32,
            &mut needed,
        )
    } == 0
    {
        return None;
    }
    // SAFETY: GetTokenInformation filled the buffer with a TOKEN_USER structure.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = null_mut();
    // SAFETY: user.Sid points into the valid TokenUser buffer.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
        return None;
    }
    let sid = LocalString(sid);
    let mut length = 0usize;
    // SAFETY: sid is NUL-terminated storage allocated by ConvertSidToStringSidW.
    unsafe {
        while *sid.0.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: The slice covers initialized UTF-16 code units before the NUL terminator.
    let sid = unsafe { &*slice_from_raw_parts(sid.0, length) };
    Some(String::from_utf16_lossy(sid))
}

fn current_process_id() -> u32 {
    // SAFETY: GetCurrentProcessId has no pointer arguments or preconditions.
    unsafe { GetCurrentProcessId() }
}
