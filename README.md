# Sigil

Sigil is a local credential manager for YubiKeys and other hardware credentials. The privileged `sigil-agent` is the only process that accesses hardware; the CLI (`cms`) and Dioxus GUI are unprivileged clients over local IPC. Read-only inventory, FIDO inspection, and PIV inspection are available to the active console user. Backend grants apply only to PIV operations enforced with system-held management keys or PUKs. FIDO fingerprint enroll/remove uses the user's FIDO PIN and is audit-logged without a backend grant.

## Run it

Install the current stable Rust toolchain. On Windows 11, install the MSVC C++ build tools and WebView2 runtime for the Dioxus desktop app. On Linux, install the Dioxus desktop WebKitGTK development dependencies (see the [Dioxus desktop guide](https://dioxuslabs.com/learn/0.7/guides/platforms/desktop/)).

For an unprivileged, hardware-free development session, set the debug-only trust bypass in both the agent and client shells. The mock runner also uses `--dev-insecure-config` to skip production path checks; never use either option with real hardware.

```powershell
$env:SIGIL_AGENT_TRUST_UNPRIVILEGED='1'
cargo run -p sigil-agent -- run --mock --dev-insecure-config
cargo run -p sigil-cli -- device list
cargo run -p sigil-cli -- device list --json
cargo run -p sigil-gui
```

On Unix shells, prefix the agent and client commands with `SIGIL_AGENT_TRUST_UNPRIVILEGED=1`. For hardware-free development, run the mock agent in one terminal and use the CLI or GUI in another.

```sh
SIGIL_AGENT_TRUST_UNPRIVILEGED=1 cargo run -p sigil-agent -- run --mock --dev-insecure-config
SIGIL_AGENT_TRUST_UNPRIVILEGED=1 cargo run -p sigil-cli -- device list
SIGIL_AGENT_TRUST_UNPRIVILEGED=1 cargo run -p sigil-gui
```

Clients also accept `--agent <endpoint>`; `SIGIL_AGENT_ENDPOINT` overrides the platform default. On Windows, install or remove the LocalSystem `SigilAgent` service with `cargo run -p sigil-agent -- install` / `uninstall` from an elevated terminal. For foreground real-hardware development, run `sigil-agent run` elevated; the clients themselves do not need elevation. PIN prompts remain in the CLI, do not echo, and never put PINs in shell history. User-mode FIDO on Windows will use the Windows WebAuthn API in a later milestone. On Linux, systemd can launch `sigil-agent run`; the local socket is `/run/sigil/agent.sock`. Linux caller identity currently contains peer UID/PID only; console-session validation is not implemented, and the native hardware backend remains unavailable (mock mode only).

The agent refuses unprotected configuration, grant-key, and service-log directories rather than repairing them. On Windows, have an administrator remove an unsafe `%ProgramData%\Sigil` directory and let the service recreate it, or apply the protected SDDL reported by the error. Service installation also checks the executable directory; `--allow-unprotected-path` is a debug-only, explicitly dangerous development override.

```powershell
cargo run -p sigil-cli -- fido info '<device-id>' --json
cargo run -p sigil-cli -- fido credentials list '<device-id>' --json
cargo run -p sigil-cli -- fido fingerprints list '<device-id>' --json
cargo run -p sigil-cli -- fido fingerprints enroll '<device-id>' --json
cargo run -p sigil-cli -- fido fingerprints remove '<device-id>' '<fingerprint-id>' --yes
```

PIV inspection displays PIN/PUK retry metadata, key policy and algorithm metadata when available, and certificate summaries. Certificates can be shown or exported as PEM/DER; export paths are created exclusively and are never overwritten. PIN change, CSR signing, attestation reads, and a confirmed PIV reset do not require a grant. PUK change/unblock, management-key changes, key generation/deletion, and certificate import/deletion require a backend grant.

```powershell
cargo run -p sigil-cli -- piv info mock-yubikey-12345678 --json
cargo run -p sigil-cli -- piv slots mock-yubikey-12345678 --json
cargo run -p sigil-cli -- piv certificate show mock-yubikey-12345678 9a
cargo run -p sigil-cli -- piv certificate export mock-yubikey-12345678 9a
cargo run -p sigil-cli -- piv info '<smart-card-device-id>'
cargo run -p sigil-cli -- piv slots '<smart-card-device-id>'
cargo run -p sigil-cli -- piv certificate export '<smart-card-device-id>' 9a --format der --output .\authentication.der
```

PIV mutation commands prompt securely for PINs, PUKs, and management keys; secrets are never accepted as arguments. New PINs and PUKs must be confirmed twice. Use `--current-default` only when the current management key is the published factory key. Reset requires typing the printed serial and a second `y` confirmation.

```powershell
cargo run -p sigil-cli -- piv pin change '<device-id>'
cargo run -p sigil-cli -- piv pin unblock '<device-id>'
cargo run -p sigil-cli -- piv puk change '<device-id>'
cargo run -p sigil-cli -- piv management-key change '<device-id>' --current-default --algorithm aes256
cargo run -p sigil-cli -- piv key generate '<device-id>' --slot 9a --algorithm p256 --pin-policy once --touch-policy never --current-default
cargo run -p sigil-cli -- piv key delete '<device-id>' --slot 9a --current-default
cargo run -p sigil-cli -- piv attest '<device-id>' --slot 9a --output .\attestation
cargo run -p sigil-cli -- piv csr '<device-id>' --slot 9a --subject 'CN=Example' --output .\request.csr
cargo run -p sigil-cli -- piv certificate import '<device-id>' --slot 9a --file .\certificate.der --current-default
cargo run -p sigil-cli -- piv certificate delete '<device-id>' --slot 9a --current-default
cargo run -p sigil-cli -- piv reset '<device-id>'
```

The management-key-change RPC generates a new key with the agent OS random source and returns it once in hex as a test-only escrow placeholder. The CLI prints a warning to stderr; store the displayed value securely. A later escrow milestone will remove the one-time return.

Mock certificates are self-signed public test fixtures and do not contain private keys. Native PIV commands require a discovered smart-card reader and an enabled PIV application; PIV inspection works over both USB CCID and NFC. A FIDO-only key is not a smart-card device.

Read-only hardware discovery/inspection tests are gated by `SIGIL_HARDWARE_TESTS=1`. Physical-token mutation tests additionally require `SIGIL_HARDWARE_MUTATION_SERIAL=<serial>`, validate factory defaults before the first change, and reset PIV to factory defaults before finishing. Run the two mutation test binaries sequentially, not in parallel:

```powershell
$env:SIGIL_HARDWARE_TESTS='1'
$env:SIGIL_HARDWARE_MUTATION_SERIAL='39192733'
cargo test -p sigil-platform --test hardware_piv_mutation -- --nocapture
cargo test -p sigil-agent --features dev-grants --test hardware_piv_agent -- --nocapture
```

These mutation tests never require touch; key generation uses touch policy `never`. Read-only RPCs are allowed for the active console user without backend sign-in and are audit-logged locally. Only discoverable credentials can be listed. Fingerprint enrollment shows capture progress and needs repeated touches of the same finger; deleting a fingerprint requires confirmation. Enroll/list/remove uses the user's FIDO PIN, remains user-configurable, and is audit-logged without a backend grant. PINs are not saved or logged. Bio operations require validation with a physical Bio key before operational use.

The CLI and GUI always connect to `sigil-agent`; they have no in-process mock or native hardware backend. The client authenticates the local process serving the pipe/socket before sending RPCs. Select a returned opaque ID with `cms device info <id>`; `--json` is available for device commands. For real Windows hardware, run the foreground agent elevated or install the LocalSystem service with `sigil-agent install`; the install command refuses binaries in user-writable directories unless the debug-only development override is explicitly supplied. On Linux, the agent currently supports mock hardware only; native discovery is not implemented. The CLI binary is named `cms`.

The Windows backend enumerates every smart-card reader through WinSCard/PC/SC. YubiKey-named readers are treated as USB CCID; on other readers, including ACS, Identiv, and HID Omnikey NFC readers, Sigil probes the read-only Yubico management applet and lists a device only when that applet responds. Non-YubiKey cards, including generic PIV cards, are ignored. NFC management metadata reports NFC-specific enabled and supported applications separately from USB capabilities. PIV inspection uses the same reader-scoped device ID and works over NFC. FIDO-only Yubico USB product IDs are enumerated through HID; HID presence alone does not establish CTAP2 support, so application and firmware fields remain unknown. Smart-card insertion/removal uses reader notifications; HID-only discovery refreshes every five seconds. Multiple readers and keys keep separate opaque device IDs. Hardware-generated attributes require validation on physical devices before relying on them operationally.

If the Windows Smart Card service (`SCardSvr`) is stopped, the agent logs that PC/SC discovery is unavailable and can still discover HID devices; the watcher retries the service. Start it with `Start-Service SCardSvr` in an elevated PowerShell when testing CCID or NFC. The LocalSystem service can perform supported raw FIDO HID operations without elevating the client; a foreground agent needs to be launched elevated for HID access. The current native FIDO provider still opens HID IDs only, so FIDO-over-NFC RPCs are not implemented yet. Older keys may not provide serial or management data over FIDO. A FIDO-only key does not require the smart-card service.

NFC discovery and PIV-over-NFC have not been validated on hardware because no NFC reader is available on the development machine. The native PC/SC path probes other readers with only the read-only Yubico management SELECT/READ commands and ignores cards that do not provide Yubico management data.

## Architecture

| Crate | Responsibility |
| --- | --- |
| `sigil-core` | Vendor-neutral device types, discovery/events, FIDO/PIV inspection traits, typed errors |
| `sigil-app` | Shared typed service used inside the agent and client applications |
| `sigil-proto` | Protobuf RPC/grant messages, domain conversions, and structured error statuses |
| `sigil-agent` | The only hardware process; caller identity, audit logging, local IPC, and grant verification |
| `sigil-client` | Synchronous discovery/FIDO/PIV traits implemented over the local agent IPC channel |
| `sigil-platform` | Windows PC/SC and HID hardware access, used only by `sigil-agent`; Linux native backend remains unimplemented |
| `sigil-yubikey` | YubiKey management, PIV metadata, and vendor-specific PIV mutation provider, used only by the agent |
| `sigil-piv` | Vendor-neutral PIV APDUs, management-key authentication, CSR helpers, BER-TLV, certificate parsing and encoding |
| `sigil-mock` | Hardware-free backend hosted inside `sigil-agent run --mock` |
| `sigil-cli` | `cms` commands and JSON rendering over `sigil-client` |
| `sigil-gui` | Dioxus desktop client over `sigil-client` |

Only `sigil-agent` links the hardware providers. The CLI and GUI are unprivileged local-IPC clients; `DeviceId` remains opaque and serial numbers are never treated as unique selection keys. Read-only calls are available to the active console user without backend sign-in and every call is audit-logged. FIDO fingerprint enroll/remove is controlled by the user's FIDO PIN and does not require a grant. PIV operations requiring a system-held management key or PUK use a single-use backend-signed protobuf grant (ECDSA P-256 over the exact transmitted grant bytes). The optional `dev-grants` signer is for debug development only and is rejected in release builds. M4 PIV mutations verify the grant against the token serial read inside the same card transaction that performs the mutation.

PIV mutation, PIN/PUK changes, key generation, and CSR creation remain future milestones. No raw APDU interface is exposed to the client applications or remote protocols.

## Backend (M7a)

The Go backend provides an mTLS gRPC gateway for agents, validates OIDC access tokens, inventories tokens, records an append-only hash-chained audit trail, and signs policy-approved PIV grants. It does not include the portal/BFF or agent login/client yet, and it has no development authentication bypass.

Start the local PostgreSQL 17 service from the repository root:

```sh
podman compose -f deploy/dev/compose.yaml up -d
```

Provision the backend TLS server/client certificates and configure a real OIDC issuer (Authentik first, Keycloak second) in a private copy of `deploy/dev/sigil-server.example.toml`. From `backend/`, generate protobuf code and run the tests:

```sh
go generate ./...
go test ./...
```

Generate the P-256 grant signing key, apply migrations, register a station certificate, and start the service:

```sh
go run ./cmd/sigil-server keygen --out ../deploy/dev/keys/grant-private.pem --public-out ../deploy/dev/keys/grant-public.pem
go run ./cmd/sigil-server migrate --config ../deploy/dev/sigil-server.example.toml
go run ./cmd/sigil-server station add --config ../deploy/dev/sigil-server.example.toml --id station-1 --name "Provisioning station" --mode station --cert ../deploy/dev/certs/station.pem
go run ./cmd/sigil-server serve --config ../deploy/dev/sigil-server.example.toml
```

Keep the signing key and server TLS private key readable only by the backend service account. `keygen` writes private keys with mode 0600 on Unix and prints only the public-key path.

## Next milestones

M4a adds local PIV mutations and grant verification at the agent boundary. Linux native PIV remains unsupported; Linux later adds pcsc-lite behind the same discovery interface. The PC/SC event watcher uses its own context so blocking notifications do not block scans.

## Quality gates

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The default automated test suite is hardware-free; opt-in hardware tests require the gates documented above. Linux without WebKitGTK development libraries can use `cargo test --workspace --exclude sigil-gui` and the equivalent `cargo clippy` command. Windows CI compiles both entry points but cannot prove behavior with real hardware.
