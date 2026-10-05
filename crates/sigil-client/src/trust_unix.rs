use tokio::net::UnixStream;

use super::{debug_bypass, trust_server};

pub(crate) fn unix_server_is_trusted(stream: &UnixStream) -> bool {
    let bypass = debug_bypass();
    let Ok(credentials) = stream.peer_cred() else {
        return trust_server(0, std::process::id(), false, false, false, bypass);
    };
    let server_pid = credentials
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .unwrap_or_default();
    trust_server(
        server_pid,
        std::process::id(),
        credentials.uid() == 0,
        false,
        false,
        bypass,
    )
}
