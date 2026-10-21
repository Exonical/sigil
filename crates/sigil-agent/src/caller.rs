use sigil_core::CredentialError;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallerIdentity {
    pub os_user: String,
    pub session_id: Option<u32>,
    pub pid: u32,
}

impl CallerIdentity {
    pub fn rejected() -> Self {
        Self::default()
    }

    pub fn is_valid(&self) -> bool {
        !self.os_user.is_empty() && self.pid != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CallerPolicy {
    pub require_console_session: bool,
}

impl CallerPolicy {
    pub const fn production() -> Self {
        Self {
            require_console_session: true,
        }
    }
}

pub fn authorize(identity: &CallerIdentity, policy: CallerPolicy) -> Result<(), CredentialError> {
    if !identity.is_valid() {
        return Err(CredentialError::CallerRejected(
            "could not identify the local IPC client".into(),
        ));
    }
    #[cfg(windows)]
    if policy.require_console_session {
        let active = windows::active_console_session();
        if identity.session_id != Some(active) {
            return Err(CredentialError::CallerRejected(
                "client is not in the active console session".into(),
            ));
        }
    }
    #[cfg(unix)]
    if policy.require_console_session {
        // Linux console-session membership is not implemented yet. Keep the
        // peer UID/PID from SO_PEERCRED and do not synthesize a session ID.
        tracing::debug!(caller_uid = %identity.os_user, "console-session validation is unavailable on Unix");
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) use unix::identify_unix_client;
#[cfg(windows)]
pub(crate) use windows::identify_named_pipe_client;
