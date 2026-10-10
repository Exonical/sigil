#[cfg(unix)]
use std::{fs, path::Path};

#[cfg(unix)]
use serde::Deserialize;
use sigil_app::CredentialService;
use sigil_client::{AgentClient, DEFAULT_ENDPOINT};
use sigil_core::{CredentialError, DeviceDiscovery, DeviceManagement, PivManagement};
use sigil_platform::NativeDiscovery;
use thiserror::Error;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Registry::{HKEY, RegCloseKey},
};

#[cfg(windows)]
struct TokenHandle(HANDLE);

#[cfg(windows)]
impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: OpenProcessToken returned this owned handle, which is closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

#[cfg(windows)]
struct RegistryKey(HKEY);

#[cfg(windows)]
impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: RegOpenKeyExW returned this owned key handle, which is closed exactly once.
        unsafe { RegCloseKey(self.0) };
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionMode {
    Agent { endpoint: String },
    Direct { elevated: bool },
}

#[derive(Clone)]
pub struct ConnectedService {
    pub credentials: CredentialService,
    pub mode: ConnectionMode,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionPreference {
    Agent { endpoint: String },
    Direct,
    Default { endpoint: String },
    Mock,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AgentAttempt {
    NotAttempted,
    Connected,
    Failed(CredentialError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionSelection {
    pub mode: ConnectionMode,
    pub warning: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConnectError {
    #[error("direct mode is disabled by machine policy")]
    DirectModeDisabled,
    #[error("the Sigil agent is required by machine policy but is not running")]
    AgentRequired,
    #[error("choose either an agent endpoint or direct mode, not both")]
    ConflictingModes,
    #[error(transparent)]
    Agent(#[from] CredentialError),
}

pub trait MachinePolicyReader {
    fn require_agent(&self) -> bool;
}

pub struct SystemMachinePolicy;

impl MachinePolicyReader for SystemMachinePolicy {
    fn require_agent(&self) -> bool {
        read_require_agent()
    }
}

pub fn select_connection(
    preference: ConnectionPreference,
    require_agent: bool,
    elevated: bool,
    attempt: AgentAttempt,
) -> Result<ConnectionSelection, ConnectError> {
    match preference {
        ConnectionPreference::Direct | ConnectionPreference::Mock => {
            if require_agent {
                Err(ConnectError::DirectModeDisabled)
            } else {
                Ok(ConnectionSelection {
                    mode: ConnectionMode::Direct { elevated },
                    warning: None,
                })
            }
        }
        ConnectionPreference::Agent { endpoint } => match attempt {
            AgentAttempt::Connected => Ok(ConnectionSelection {
                mode: ConnectionMode::Agent { endpoint },
                warning: None,
            }),
            AgentAttempt::Failed(error) => Err(ConnectError::Agent(error)),
            AgentAttempt::NotAttempted => Err(ConnectError::Agent(
                CredentialError::AgentUnavailable("agent was not attempted".into()),
            )),
        },
        ConnectionPreference::Default { endpoint } => match attempt {
            AgentAttempt::Connected => Ok(ConnectionSelection {
                mode: ConnectionMode::Agent { endpoint },
                warning: None,
            }),
            AgentAttempt::Failed(CredentialError::AgentUnavailable(_)) if require_agent => {
                Err(ConnectError::AgentRequired)
            }
            AgentAttempt::Failed(CredentialError::AgentUnavailable(_)) => Ok(ConnectionSelection {
                mode: ConnectionMode::Direct { elevated },
                warning: None,
            }),
            AgentAttempt::Failed(error @ CredentialError::AgentUntrusted(_)) if require_agent => {
                Err(ConnectError::Agent(error))
            }
            AgentAttempt::Failed(CredentialError::AgentUntrusted(_)) => Ok(ConnectionSelection {
                mode: ConnectionMode::Direct { elevated },
                warning: Some(format!(
                    "The Sigil agent at {endpoint} is untrusted; using direct mode."
                )),
            }),
            AgentAttempt::Failed(error) => Err(ConnectError::Agent(error)),
            AgentAttempt::NotAttempted => Err(ConnectError::Agent(
                CredentialError::AgentUnavailable("agent was not attempted".into()),
            )),
        },
    }
}

#[derive(Default)]
pub struct ConnectOptions {
    pub agent: Option<String>,
    pub direct: bool,
    #[cfg(debug_assertions)]
    pub direct_mock: bool,
}

pub fn connect(options: ConnectOptions) -> Result<ConnectedService, ConnectError> {
    connect_with_policy(options, &SystemMachinePolicy)
}

pub fn connect_with_policy(
    options: ConnectOptions,
    policy: &dyn MachinePolicyReader,
) -> Result<ConnectedService, ConnectError> {
    let require_agent = policy.require_agent();
    let elevated = current_user_is_elevated();
    let environment_endpoint = std::env::var("SIGIL_AGENT_ENDPOINT").ok();
    if options.direct && (options.agent.is_some() || environment_endpoint.is_some()) {
        return Err(ConnectError::ConflictingModes);
    }

    #[cfg(debug_assertions)]
    if options.direct_mock {
        if options.agent.is_some() || environment_endpoint.is_some() {
            return Err(ConnectError::ConflictingModes);
        }
        let selection = select_connection(
            ConnectionPreference::Mock,
            require_agent,
            elevated,
            AgentAttempt::NotAttempted,
        )?;
        return Ok(ConnectedService {
            credentials: mock_service(),
            mode: selection.mode,
            warning: selection.warning,
        });
    }

    let endpoint = options.agent.or(environment_endpoint);
    let preference = if let Some(endpoint) = endpoint {
        ConnectionPreference::Agent {
            endpoint: endpoint.clone(),
        }
    } else if options.direct {
        ConnectionPreference::Direct
    } else {
        ConnectionPreference::Default {
            endpoint: DEFAULT_ENDPOINT.to_owned(),
        }
    };

    let endpoint = match &preference {
        ConnectionPreference::Agent { endpoint } | ConnectionPreference::Default { endpoint } => {
            Some(endpoint.clone())
        }
        ConnectionPreference::Direct | ConnectionPreference::Mock => None,
    };
    let mut agent = None;
    let attempt = match endpoint.as_deref() {
        Some(endpoint) => match AgentClient::connect(Some(endpoint)) {
            Ok(client) => {
                agent = Some(client);
                AgentAttempt::Connected
            }
            Err(error) => AgentAttempt::Failed(error),
        },
        None => AgentAttempt::NotAttempted,
    };
    let selection = select_connection(preference, require_agent, elevated, attempt)?;
    let credentials = match &selection.mode {
        ConnectionMode::Agent { .. } => {
            let client = std::sync::Arc::new(agent.expect("selected connected agent"));
            let discovery: std::sync::Arc<dyn DeviceDiscovery> = client.clone();
            let piv_management: std::sync::Arc<dyn PivManagement> = client.clone();
            let device_management: std::sync::Arc<dyn DeviceManagement> = client;
            CredentialService::new_with_device_management(
                discovery,
                piv_management,
                device_management,
            )
        }
        ConnectionMode::Direct { .. } => native_service(),
    };
    Ok(ConnectedService {
        credentials,
        mode: selection.mode,
        warning: selection.warning,
    })
}

fn native_service() -> CredentialService {
    let native = std::sync::Arc::new(NativeDiscovery);
    let discovery: std::sync::Arc<dyn DeviceDiscovery> = native.clone();
    let piv_management: std::sync::Arc<dyn PivManagement> = native.clone();
    let device_management: std::sync::Arc<dyn DeviceManagement> = native;
    CredentialService::new_with_device_management(discovery, piv_management, device_management)
}

#[cfg(debug_assertions)]
fn mock_service() -> CredentialService {
    let mock = std::sync::Arc::new(sigil_mock::MockDiscovery::with_example_fips());
    let discovery: std::sync::Arc<dyn DeviceDiscovery> = mock.clone();
    let piv_management: std::sync::Arc<dyn PivManagement> = mock.clone();
    let device_management: std::sync::Arc<dyn DeviceManagement> = mock;
    CredentialService::new_with_device_management(discovery, piv_management, device_management)
}

#[cfg(windows)]
fn current_user_is_elevated() -> bool {
    use std::{mem::size_of, ptr::null_mut};
    use windows_sys::Win32::{
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle and token is a writable output pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let token = TokenHandle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: token is an owned query handle and the output pointers reference writable buffers.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        ) != 0
            && elevation.TokenIsElevated != 0
    }
}

#[cfg(unix)]
fn current_user_is_elevated() -> bool {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(any(windows, unix)))]
fn current_user_is_elevated() -> bool {
    false
}

#[cfg(unix)]
fn read_require_agent() -> bool {
    use std::os::unix::fs::MetadataExt;

    let path = Path::new("/etc/sigil/client.toml");
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return true;
    }
    read_policy(path)
}

#[cfg(windows)]
fn read_require_agent() -> bool {
    use std::{mem::size_of, os::windows::ffi::OsStrExt, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND},
        System::Registry::{
            HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, RRF_RT_REG_DWORD, RegGetValueW, RegOpenKeyExW,
        },
    };

    let key: Vec<u16> = std::ffi::OsStr::new(r"SOFTWARE\Policies\Sigil")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value_name: Vec<u16> = std::ffi::OsStr::new("RequireAgent")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut policy_key: HKEY = null_mut();
    // SAFETY: key is NUL-terminated and policy_key is a valid writable output pointer.
    let open_result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut policy_key,
        )
    };
    if open_result == ERROR_FILE_NOT_FOUND || open_result == ERROR_PATH_NOT_FOUND {
        return false;
    }
    if open_result != 0 {
        return true;
    }
    let policy_key = RegistryKey(policy_key);
    let mut value = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: policy_key is an open key; value_name is NUL-terminated and value/size are writable.
    let result = unsafe {
        RegGetValueW(
            policy_key.0,
            std::ptr::null(),
            value_name.as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    if result == 0 { value != 0 } else { true }
}

#[cfg(not(any(windows, unix)))]
fn read_require_agent() -> bool {
    true
}

#[cfg(unix)]
#[derive(Deserialize)]
struct ClientPolicy {
    #[serde(default)]
    require_agent: bool,
}

#[cfg(unix)]
fn read_policy(path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(path) else {
        return true;
    };
    toml::from_str::<ClientPolicy>(&contents)
        .map(|policy| policy.require_agent)
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedPolicy(bool);

    impl MachinePolicyReader for FixedPolicy {
        fn require_agent(&self) -> bool {
            self.0
        }
    }

    fn select(
        preference: ConnectionPreference,
        require_agent: bool,
        attempt: AgentAttempt,
    ) -> Result<ConnectionSelection, ConnectError> {
        select_connection(preference, require_agent, false, attempt)
    }

    #[test]
    fn forced_agent_never_falls_back() {
        assert!(matches!(
            select(
                ConnectionPreference::Agent {
                    endpoint: "pipe:test".into()
                },
                false,
                AgentAttempt::Failed(CredentialError::AgentUnavailable("offline".into()))
            ),
            Err(ConnectError::Agent(CredentialError::AgentUnavailable(_)))
        ));
    }

    #[test]
    fn direct_mode_and_machine_policy_are_enforced() {
        assert_eq!(
            select(
                ConnectionPreference::Direct,
                false,
                AgentAttempt::NotAttempted
            )
            .unwrap()
            .mode,
            ConnectionMode::Direct { elevated: false }
        );
        assert_eq!(
            select(
                ConnectionPreference::Direct,
                true,
                AgentAttempt::NotAttempted
            ),
            Err(ConnectError::DirectModeDisabled)
        );
    }

    #[test]
    fn default_mode_falls_back_only_for_unavailable_or_untrusted_agents() {
        let endpoint = "pipe:test";
        assert_eq!(
            select(
                ConnectionPreference::Default {
                    endpoint: endpoint.into()
                },
                false,
                AgentAttempt::Failed(CredentialError::AgentUnavailable("offline".into()))
            )
            .unwrap()
            .mode,
            ConnectionMode::Direct { elevated: false }
        );
        let untrusted = select(
            ConnectionPreference::Default {
                endpoint: endpoint.into(),
            },
            false,
            AgentAttempt::Failed(CredentialError::AgentUntrusted(endpoint.into())),
        )
        .unwrap();
        assert_eq!(untrusted.mode, ConnectionMode::Direct { elevated: false });
        assert!(untrusted.warning.unwrap().contains(endpoint));
        assert_eq!(
            select(
                ConnectionPreference::Default {
                    endpoint: endpoint.into()
                },
                true,
                AgentAttempt::Failed(CredentialError::AgentUnavailable("offline".into()))
            ),
            Err(ConnectError::AgentRequired)
        );
    }

    #[test]
    fn default_mode_does_not_fallback_on_protocol_or_trust_failures_under_policy() {
        let endpoint = "pipe:test";
        assert!(matches!(
            select(
                ConnectionPreference::Default {
                    endpoint: endpoint.into()
                },
                false,
                AgentAttempt::Failed(CredentialError::ProtocolMismatch {
                    agent: 2,
                    client: 1
                })
            ),
            Err(ConnectError::Agent(
                CredentialError::ProtocolMismatch { .. }
            ))
        ));
        assert!(matches!(
            select(
                ConnectionPreference::Default {
                    endpoint: endpoint.into()
                },
                true,
                AgentAttempt::Failed(CredentialError::AgentUntrusted(endpoint.into()))
            ),
            Err(ConnectError::Agent(CredentialError::AgentUntrusted(_)))
        ));
    }

    #[test]
    fn connect_uses_the_injected_machine_policy_reader() {
        let options = ConnectOptions {
            agent: None,
            direct: true,
            #[cfg(debug_assertions)]
            direct_mock: false,
        };
        assert_eq!(
            connect_with_policy(options, &FixedPolicy(true)).map(|_| ()),
            Err(ConnectError::DirectModeDisabled)
        );
    }
}
