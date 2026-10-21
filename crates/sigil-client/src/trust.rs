use std::io;

pub(crate) fn untrusted_io_error(endpoint: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("the process serving {endpoint} is not the Sigil agent"),
    )
}

fn trust_server(
    server_pid: u32,
    own_pid: u32,
    is_local_system: bool,
    is_elevated: bool,
    is_trusted_service: bool,
    debug_bypass: bool,
) -> bool {
    debug_bypass || server_pid == own_pid || is_trusted_service || is_local_system || is_elevated
}

fn debug_bypass() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SIGIL_AGENT_TRUST_UNPRIVILEGED").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        eprintln!(
            "WARNING: SIGIL_AGENT_TRUST_UNPRIVILEGED=1 disables agent process authentication; use only for local development."
        );
        return true;
    }

    false
}

#[cfg(windows)]
#[path = "trust_windows.rs"]
mod platform;

#[cfg(unix)]
#[path = "trust_unix.rs"]
mod platform;

#[cfg(unix)]
pub(crate) use platform::unix_server_is_trusted;
#[cfg(windows)]
pub(crate) use platform::{named_pipe_server_is_trusted, open_named_pipe};

#[cfg(test)]
mod tests {
    use super::trust_server;

    #[test]
    fn trusts_only_service_local_system_elevated_self_or_debug_bypass_servers() {
        assert!(trust_server(7, 8, false, false, true, false));
        assert!(trust_server(7, 8, true, false, false, false));
        assert!(trust_server(7, 8, false, true, false, false));
        assert!(trust_server(8, 8, false, false, false, false));
        assert!(trust_server(7, 8, false, false, false, true));
        assert!(!trust_server(7, 8, false, false, false, false));
    }
}
