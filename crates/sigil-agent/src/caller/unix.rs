use std::io;

use super::CallerIdentity;

pub(crate) fn identify_unix_client(stream: &tokio::net::UnixStream) -> io::Result<CallerIdentity> {
    let credentials = stream.peer_cred()?;
    let pid = credentials
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .unwrap_or_default();
    Ok(CallerIdentity {
        os_user: credentials.uid().to_string(),
        session_id: None,
        pid,
    })
}
