use std::{
    ffi::c_void,
    io,
    mem::{align_of, size_of},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    ptr::{null, null_mut, slice_from_raw_parts},
};

use tokio::net::windows::named_pipe::NamedPipeClient;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
        LocalFree,
    },
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
        Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
            QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
            SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
            SERVICE_STATUS_PROCESS,
        },
        Threading::{
            GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use super::{debug_bypass, trust_server};

// Keep in sync with SERVICE_NAME in crates/sigil-agent/src/main.rs::windows_service.
const SIGIL_AGENT_SERVICE_NAME: &str = "SigilAgent";

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: OpenProcess and OpenProcessToken return owned handles held only here.
        unsafe { CloseHandle(self.0) };
    }
}

struct OwnedServiceHandle(SC_HANDLE);

impl Drop for OwnedServiceHandle {
    fn drop(&mut self) {
        // SAFETY: OpenSCManagerW and OpenServiceW return owned SCM handles closed exactly once.
        unsafe { CloseServiceHandle(self.0) };
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
        return trust_server(0, current_process_id(), false, false, false, bypass);
    }
    let own_pid = current_process_id();
    if server_pid == own_pid {
        return trust_server(server_pid, own_pid, false, false, false, bypass);
    }
    let is_trusted_service = is_running_local_system_agent(server_pid);

    let process = unsafe {
        // SAFETY: The PID came from GetNamedPipeServerProcessId; no handle is inherited.
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid)
    };
    if process.is_null() {
        return trust_server(
            server_pid,
            own_pid,
            false,
            false,
            is_trusted_service,
            bypass,
        );
    }
    let _process = OwnedHandle(process);
    let mut token = null_mut();
    // SAFETY: process is a valid query handle and token is a writable output pointer.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return trust_server(
            server_pid,
            own_pid,
            false,
            false,
            is_trusted_service,
            bypass,
        );
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
    trust_server(
        server_pid,
        own_pid,
        is_local_system,
        is_elevated,
        is_trusted_service,
        bypass,
    )
}

fn is_running_local_system_agent(server_pid: u32) -> bool {
    let service_name = std::ffi::OsStr::new(SIGIL_AGENT_SERVICE_NAME)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: null machine/database names select the local computer and active database.
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return false;
    }
    let _manager = OwnedServiceHandle(manager);
    // SAFETY: manager is an open SCM handle and service_name is NUL-terminated.
    let service = unsafe {
        OpenServiceW(
            manager,
            service_name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        )
    };
    if service.is_null() {
        return false;
    }
    let _service = OwnedServiceHandle(service);

    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut status_bytes = 0u32;
    // SAFETY: service is an open query handle and status/status_bytes are writable outputs.
    if unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut status_bytes,
        )
    } == 0
        || status.dwCurrentState != SERVICE_RUNNING
        || status.dwProcessId != server_pid
    {
        return false;
    }

    let mut needed = 0u32;
    // SAFETY: service is an open query handle; null and zero request the required buffer size.
    if unsafe { QueryServiceConfigW(service, null_mut(), 0, &mut needed) } != 0 {
        return false;
    }
    // SAFETY: This reads the error from the immediately preceding QueryServiceConfigW call.
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || needed < size_of::<QUERY_SERVICE_CONFIGW>() as u32
    {
        return false;
    }

    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let mut bytes_returned = 0u32;
    // SAFETY: buffer is aligned and at least the size requested by QueryServiceConfigW.
    if unsafe {
        QueryServiceConfigW(
            service,
            buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>(),
            (buffer.len() * size_of::<usize>()) as u32,
            &mut bytes_returned,
        )
    } == 0
    {
        return false;
    }
    // SAFETY: A successful QueryServiceConfigW initialized the structure at the start of buffer.
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    is_local_system_start_name(config.lpServiceStartName, &buffer)
}

fn is_local_system_start_name(name: windows_sys::core::PWSTR, buffer: &[usize]) -> bool {
    if name.is_null() {
        return true;
    }
    let buffer_start = buffer.as_ptr() as usize;
    let Some(buffer_end) =
        buffer_start.checked_add(buffer.len().saturating_mul(size_of::<usize>()))
    else {
        return false;
    };
    let name_address = name as usize;
    if name_address < buffer_start
        || name_address >= buffer_end
        || !(name_address - buffer_start).is_multiple_of(align_of::<u16>())
    {
        return false;
    }
    let available_units = (buffer_end - name_address) / size_of::<u16>();
    // SAFETY: The pointer lies within the successful query buffer and the slice length is bounded by it.
    let name_units = unsafe { std::slice::from_raw_parts(name, available_units) };
    let Some(name_length) = name_units.iter().position(|unit| *unit == 0) else {
        return false;
    };
    name_length == 0
        || String::from_utf16(&name_units[..name_length])
            .is_ok_and(|account| account.eq_ignore_ascii_case("LocalSystem"))
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
