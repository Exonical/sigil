#[cfg(not(any(windows, unix)))]
use std::io;

use tokio::sync::oneshot;

use crate::{caller::CallerPolicy, server::AgentService};

type ServeResult<T> = anyhow::Result<T>;

pub async fn serve(
    service: AgentService,
    endpoint: String,
    policy: CallerPolicy,
    ready: Option<oneshot::Sender<()>>,
    shutdown: oneshot::Receiver<()>,
) -> ServeResult<()> {
    serve_inner(service, endpoint, policy, ready, shutdown).await
}

#[cfg(feature = "test-support")]
pub async fn serve_for_test(
    service: AgentService,
    endpoint: String,
    ready: oneshot::Sender<()>,
    shutdown: oneshot::Receiver<()>,
) -> ServeResult<()> {
    serve_inner(
        service,
        endpoint,
        CallerPolicy {
            require_console_session: false,
        },
        Some(ready),
        shutdown,
    )
    .await
}

async fn serve_inner(
    service: AgentService,
    endpoint: String,
    policy: CallerPolicy,
    ready: Option<oneshot::Sender<()>>,
    shutdown: oneshot::Receiver<()>,
) -> ServeResult<()> {
    #[cfg(windows)]
    return windows::serve(service, endpoint, policy, ready, shutdown).await;
    #[cfg(unix)]
    return unix::serve(service, endpoint, policy, ready, shutdown).await;
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (service, endpoint, policy, ready, shutdown);
        Err(io::Error::new(io::ErrorKind::Unsupported, "local IPC is unsupported").into())
    }
}

/// Runs the spawned tonic server until it exits or `stop` completes. A stop drains the server for
/// up to two seconds and then returns the stop's own error, if any, ahead of the server's result.
#[cfg(any(windows, unix))]
async fn run_until_stopped(
    mut server: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    graceful_stop: oneshot::Sender<()>,
    stop: impl std::future::Future<Output = ServeResult<()>>,
) -> ServeResult<()> {
    let stopped = tokio::select! {
        result = &mut server => {
            result??;
            return Ok(());
        }
        stopped = stop => stopped,
    };
    let _ = graceful_stop.send(());
    let drained = match tokio::time::timeout(std::time::Duration::from_secs(2), &mut server).await {
        Ok(result) => result?.map_err(anyhow::Error::from),
        Err(_) => {
            server.abort();
            let _ = server.await;
            tracing::warn!("forcing IPC streams closed during agent shutdown");
            Ok(())
        }
    };
    stopped?;
    drained
}

#[cfg(all(test, any(windows, unix)))]
mod run_until_stopped_tests {
    use std::future;

    use tokio::sync::oneshot;

    use super::run_until_stopped;

    #[tokio::test]
    async fn returns_when_the_server_exits_without_a_stop() {
        let (graceful_stop, _graceful_receiver) = oneshot::channel();
        let server = tokio::spawn(async { Ok(()) });

        run_until_stopped(server, graceful_stop, future::pending())
            .await
            .expect("server exit");
    }

    #[tokio::test]
    async fn requested_stop_drains_the_server() {
        let (graceful_stop, graceful_receiver) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let _ = graceful_receiver.await;
            Ok(())
        });

        run_until_stopped(server, graceful_stop, async { Ok(()) })
            .await
            .expect("graceful stop");
    }

    #[tokio::test]
    async fn failed_stop_drains_the_server_and_returns_the_error() {
        let (graceful_stop, graceful_receiver) = oneshot::channel::<()>();
        let (drained_sender, drained) = oneshot::channel();
        let server = tokio::spawn(async move {
            let _ = graceful_receiver.await;
            let _ = drained_sender.send(());
            Ok(())
        });

        let error = run_until_stopped(server, graceful_stop, async {
            Err(anyhow::anyhow!(
                "could not create pending named pipe instance"
            ))
        })
        .await
        .expect_err("accept failure");

        assert_eq!(
            error.to_string(),
            "could not create pending named pipe instance"
        );
        drained.await.expect("server was asked to stop");
    }
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::{OsStr, c_void},
        io,
        mem::size_of,
        os::windows::io::AsRawHandle,
        pin::Pin,
        ptr::null_mut,
        sync::Arc,
        task::{Context, Poll},
    };

    use anyhow::Context as _;
    use sigil_proto::v1::agent_server::AgentServer;
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::windows::named_pipe::{NamedPipeServer, ServerOptions},
        sync::{mpsc, oneshot},
    };
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::{transport::Server, transport::server::Connected};
    use windows_sys::Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
    };

    // IU gets the exact data/attribute/control/sync mask; 0x4 maps to FILE_CREATE_PIPE_INSTANCE
    // for named pipes and is deliberately excluded. OW allows the pipe owner to create instances.
    const AGENT_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x00120183;;;IU)";

    use crate::{
        caller::{self, CallerIdentity, CallerPolicy},
        ipc::{ServeResult, run_until_stopped},
        server::AgentService,
    };

    struct PipeSecurity(usize);

    impl PipeSecurity {
        fn new() -> io::Result<Self> {
            let sddl: Vec<u16> = AGENT_PIPE_SDDL
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: SDDL is NUL-terminated and descriptor points to a writable output slot.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(descriptor as usize))
        }

        fn pointer(&self) -> PSECURITY_DESCRIPTOR {
            self.0 as PSECURITY_DESCRIPTOR
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            // SAFETY: The descriptor was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }

    struct PipeConnection {
        pipe: NamedPipeServer,
        caller: CallerIdentity,
    }

    impl Connected for PipeConnection {
        type ConnectInfo = CallerIdentity;

        fn connect_info(&self) -> Self::ConnectInfo {
            self.caller.clone()
        }
    }

    impl AsyncRead for PipeConnection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for PipeConnection {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.pipe).poll_write(context, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.pipe).poll_shutdown(context)
        }
    }

    fn create_pipe(
        endpoint: &str,
        security: &PipeSecurity,
        first: bool,
    ) -> io::Result<NamedPipeServer> {
        let mut options = ServerOptions::new();
        options
            .reject_remote_clients(true)
            .first_pipe_instance(first);
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.pointer(),
            bInheritHandle: 0,
        };
        // SAFETY: SECURITY_ATTRIBUTES and its descriptor remain valid for the CreateNamedPipe call.
        unsafe {
            options.create_with_security_attributes_raw(
                OsStr::new(endpoint),
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
    }

    pub(super) async fn serve(
        service: AgentService,
        endpoint: String,
        policy: CallerPolicy,
        ready: Option<oneshot::Sender<()>>,
        shutdown: oneshot::Receiver<()>,
    ) -> ServeResult<()> {
        let security = Arc::new(PipeSecurity::new()?);
        let first = create_pipe(&endpoint, &security, true)?;
        let spare = create_pipe(&endpoint, &security, false)?;
        let (sender, receiver) = mpsc::channel::<io::Result<PipeConnection>>(8);
        let mut accept = tokio::spawn(accept_connections(
            first,
            spare,
            endpoint,
            security,
            sender.clone(),
        ));
        let accept_abort = accept.abort_handle();
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        let (graceful_stop, graceful_receiver) = oneshot::channel();
        let server = tokio::spawn(
            Server::builder()
                .add_service(AgentServer::new(service.with_policy(policy)))
                .serve_with_incoming_shutdown(ReceiverStream::new(receiver), async move {
                    let _ = graceful_receiver.await;
                }),
        );
        let stop = async move {
            tokio::select! {
                _ = shutdown => Ok(()),
                accepted = &mut accept => accepted?,
            }
        };
        // Holding `sender` keeps the incoming stream open, so a failed accept task stops the
        // server through `stop` and reports its error instead of ending the stream cleanly.
        let result = run_until_stopped(server, graceful_stop, stop).await;
        accept_abort.abort();
        drop(sender);
        result
    }

    /// Accepts clients until the server drops its receiver. A failed `connect()` is passed to the
    /// server as an `Err` item and replaced by a fresh pipe instance, like a failed Unix `accept()`;
    /// failing to create a pipe instance is fatal and ends the task with that error.
    async fn accept_connections(
        mut pending: NamedPipeServer,
        mut spare: NamedPipeServer,
        endpoint: String,
        security: Arc<PipeSecurity>,
        sender: mpsc::Sender<io::Result<PipeConnection>>,
    ) -> ServeResult<()> {
        loop {
            let accepted = match pending.connect().await {
                Ok(()) => {
                    let caller = caller::identify_named_pipe_client(pending.as_raw_handle())
                        .unwrap_or_else(|error| {
                            tracing::debug!(%error, "could not identify named pipe caller");
                            CallerIdentity::rejected()
                        });
                    Ok(PipeConnection {
                        pipe: pending,
                        caller,
                    })
                }
                Err(error) => {
                    tracing::warn!(%error, "named pipe accept failed");
                    Err(error)
                }
            };
            let next = create_pipe(&endpoint, &security, false)
                .context("could not create pending named pipe instance")?;
            if sender.send(accepted).await.is_err() {
                return Ok(());
            }
            pending = spare;
            spare = next;
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            ffi::c_void,
            mem::{offset_of, size_of},
            ptr::{null_mut, slice_from_raw_parts},
        };

        use windows_sys::Win32::{
            Foundation::{GENERIC_ALL, GENERIC_WRITE, HLOCAL, LocalFree},
            Security::Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            Security::{
                ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
                GetAce, GetAclInformation, GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR, PSID,
            },
            System::SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        };

        use super::AGENT_PIPE_SDDL;

        struct Descriptor(PSECURITY_DESCRIPTOR);

        impl Drop for Descriptor {
            fn drop(&mut self) {
                // SAFETY: The descriptor was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
                unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
            }
        }

        struct SidString(windows_sys::core::PWSTR);

        impl Drop for SidString {
            fn drop(&mut self) {
                // SAFETY: ConvertSidToStringSidW allocates this pointer with LocalAlloc.
                unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
            }
        }

        fn ace_entries() -> Vec<(String, u32)> {
            let sddl: Vec<u16> = AGENT_PIPE_SDDL
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: SDDL is NUL-terminated and descriptor points to writable output storage.
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        SDDL_REVISION_1,
                        &mut descriptor,
                        null_mut(),
                    )
                },
                0
            );
            let descriptor = Descriptor(descriptor);
            let mut dacl_present = 0;
            let mut dacl_defaulted = 0;
            let mut dacl: *mut ACL = null_mut();
            // SAFETY: descriptor is valid and the output pointers are writable.
            assert_ne!(
                unsafe {
                    GetSecurityDescriptorDacl(
                        descriptor.0,
                        &mut dacl_present,
                        &mut dacl,
                        &mut dacl_defaulted,
                    )
                },
                0
            );
            assert_ne!(dacl_present, 0);
            assert!(!dacl.is_null());
            let mut information = ACL_SIZE_INFORMATION::default();
            // SAFETY: dacl belongs to the valid descriptor and information is writable.
            assert_ne!(
                unsafe {
                    GetAclInformation(
                        dacl,
                        (&mut information as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                        size_of::<ACL_SIZE_INFORMATION>() as u32,
                        AclSizeInformation,
                    )
                },
                0
            );
            let mut entries = Vec::with_capacity(information.AceCount as usize);
            for index in 0..information.AceCount {
                let mut ace_pointer: *mut c_void = null_mut();
                // SAFETY: index is bounded by the ACE count returned by GetAclInformation.
                assert_ne!(unsafe { GetAce(dacl, index, &mut ace_pointer) }, 0);
                assert!(!ace_pointer.is_null());
                // SAFETY: GetAce returned a valid ACE pointer inside dacl.
                let header = unsafe { &*ace_pointer.cast::<ACE_HEADER>() };
                assert_eq!(header.AceType as u32, ACCESS_ALLOWED_ACE_TYPE);
                // SAFETY: The ACE header identifies this as an ACCESS_ALLOWED_ACE.
                let ace = unsafe { &*ace_pointer.cast::<ACCESS_ALLOWED_ACE>() };
                let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
                // SAFETY: SidStart is the SID payload of this basic allowed ACE.
                let sid = unsafe { ace_pointer.cast::<u8>().add(sid_offset).cast::<c_void>() };
                // SAFETY: sid points to the SID payload of the valid ACE.
                let sid = unsafe { sid_string(sid) }.expect("valid SID");
                entries.push((sid, ace.Mask));
            }
            entries
        }

        unsafe fn sid_string(sid: PSID) -> Option<String> {
            let mut text = null_mut();
            // SAFETY: sid points into an ACE owned by the descriptor.
            if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
                return None;
            }
            let text = SidString(text);
            let mut length = 0usize;
            // SAFETY: text is NUL-terminated UTF-16 storage returned by ConvertSidToStringSidW.
            unsafe {
                while *text.0.add(length) != 0 {
                    length += 1;
                }
            }
            // SAFETY: The slice spans initialized code units up to the terminator.
            let text = unsafe { &*slice_from_raw_parts(text.0, length) };
            Some(String::from_utf16_lossy(text))
        }

        #[test]
        fn pipe_dacl_excludes_client_instance_creation_rights() {
            let entries = ace_entries();
            let interactive = entries.iter().find(|(sid, _)| sid == "S-1-5-4").unwrap();
            assert_eq!(interactive.1, 0x0012_0183);
            assert_eq!(interactive.1 & 0xF000_0000, 0);
            assert!(entries.iter().any(|(sid, _)| sid == "S-1-3-4"));
            for (sid, mask) in &entries {
                if !["S-1-5-18", "S-1-5-32-544", "S-1-3-4"].contains(&sid.as_str()) {
                    assert_eq!(mask & (0x4 | GENERIC_WRITE | GENERIC_ALL), 0, "SID {sid}");
                }
            }
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::{
        io,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        pin::Pin,
        task::{Context, Poll},
    };

    use futures_util::stream;
    use sigil_proto::v1::agent_server::AgentServer;
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::{UnixListener, UnixStream},
        sync::oneshot,
    };
    use tonic::{transport::Server, transport::server::Connected};

    use crate::{
        caller::{self, CallerIdentity, CallerPolicy},
        ipc::{ServeResult, run_until_stopped},
        server::AgentService,
    };

    struct UnixConnection {
        stream: UnixStream,
        caller: CallerIdentity,
    }

    impl Connected for UnixConnection {
        type ConnectInfo = CallerIdentity;

        fn connect_info(&self) -> Self::ConnectInfo {
            self.caller.clone()
        }
    }

    impl AsyncRead for UnixConnection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for UnixConnection {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(context, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(context)
        }
    }

    struct SocketPath(PathBuf);

    impl Drop for SocketPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn bind_socket(path: &Path) -> io::Result<UnixListener> {
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
        }
        let listener = UnixListener::bind(path)?;
        // SAFETY: geteuid has no pointer arguments and is safe to call in this process.
        if unsafe { libc::geteuid() } == 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        }
        Ok(listener)
    }

    pub(super) async fn serve(
        service: AgentService,
        endpoint: String,
        policy: CallerPolicy,
        ready: Option<oneshot::Sender<()>>,
        shutdown: oneshot::Receiver<()>,
    ) -> ServeResult<()> {
        let path = PathBuf::from(&endpoint);
        let listener = bind_socket(&path)?;
        let _socket_path = SocketPath(path);
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        let incoming = stream::unfold(listener, |listener| async move {
            let accepted = listener.accept().await.map(|(stream, _)| {
                let caller = caller::identify_unix_client(&stream).unwrap_or_else(|error| {
                    tracing::debug!(%error, "could not identify Unix socket caller");
                    CallerIdentity::rejected()
                });
                UnixConnection { stream, caller }
            });
            Some((accepted, listener))
        });
        let (graceful_stop, graceful_receiver) = oneshot::channel();
        let server = tokio::spawn(
            Server::builder()
                .add_service(AgentServer::new(service.with_policy(policy)))
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = graceful_receiver.await;
                }),
        );
        run_until_stopped(server, graceful_stop, async move {
            let _ = shutdown.await;
            Ok(())
        })
        .await
    }
}
