# Sigil

Sigil is a local credential manager for YubiKeys and, later, other hardware credentials. The Windows discovery backend is read-only. PIV management and enrollment are later milestones.

## Run it

Install the current stable Rust toolchain. On Windows 11, install the MSVC C++ build tools and WebView2 runtime for the Dioxus desktop app. On Linux, install the Dioxus desktop WebKitGTK development dependencies (see the [Dioxus desktop guide](https://dioxuslabs.com/learn/0.7/guides/platforms/desktop/)).

```sh
cargo run -p sigil-cli -- device list
cargo run -p sigil-cli -- device list --json
cargo run -p sigil-gui
```

Copy an opaque HID ID from `device list`; quote it in PowerShell. On Windows, run an elevated PowerShell for FIDO inspection. The passkey list command prompts for a PIN without echoing it or putting it in shell history.

```powershell
cargo run -p sigil-cli -- fido info '<device-id>' --json
cargo run -p sigil-cli -- fido credentials list '<device-id>' --json
```

The GUI can open a second, elevated instance on request when Windows restricts FIDO HID access. Only discoverable credentials can be listed. Sigil does not save PINs or enumerate non-discoverable credentials.

On Windows, these commands use native discovery. Select a returned opaque ID with `cms device info <id>`; `--json` is available for both device commands. For hardware-free development use `cargo run -p sigil-cli -- --backend mock device list --json` and `cargo run -p sigil-gui -- --mock`. On Linux, the mock remains the default until the native backend is implemented; `--backend native` reports an explicit error. The CLI binary is named `cms`.

The Windows backend enumerates YubiKey smart-card readers through WinSCard/PC/SC, then reads the Yubico management applet for serial, firmware, form factor, and supported versus enabled USB applications. It separately enumerates FIDO-only Yubico USB product IDs through HID. FIDO-only HID presence alone does not establish CTAP2 support, so its application and firmware fields remain unknown. The retail model is also left generic when it cannot be verified. Smart-card insertion/removal uses reader notifications; HID-only discovery refreshes every five seconds. Multiple readers and keys keep separate opaque device IDs. Reader-name matching can miss nonstandard reader names. Hardware-generated attributes require validation on physical devices before relying on them operationally.

If the Windows Smart Card service (`SCardSvr`) is stopped, the CLI warns on stderr and HID discovery can still list FIDO-capable YubiKeys, including models with a CCID interface. A present Yubico HID interface path supplies a fallback when Windows denies access to its FIDO descriptor; this proves USB presence alone. When direct HID access is available, Sigil uses CTAPHID INIT and Yubico's read-only management command to obtain firmware, serial, form factor, and application capabilities. On Windows a normal session may detect the FIDO key but lack permission to open it, so metadata remains unknown; run the CLI elevated to test direct access. Older keys may not provide serial or management data over FIDO even with access. Smart-card metadata is unavailable until the service starts. An empty list while the service is stopped does not rule out a CCID-only key. The watcher retries the service every five seconds. Check `Get-Service SCardSvr` in PowerShell; if a connected CCID key is still missing, run `Start-Service SCardSvr` in an elevated PowerShell and repeat `cargo run -p sigil-cli -- device list --json`. Windows may stop the service when no smart-card reader is attached; a FIDO-only key does not require it.

## Architecture

| Crate | Responsibility |
| --- | --- |
| `sigil-core` | Vendor-neutral device types, discovery/events, optional PIV and FIDO traits, typed errors |
| `sigil-app` | Shared inventory and explicit device selection used by both entry points |
| `sigil-mock` | Hardware-free inventory and connection/update/removal events |
| `sigil-platform` | Windows PC/SC and HID discovery; Linux native implementation remains a placeholder |
| `sigil-yubikey` | Read-only management response parser and provider skeleton |
| `sigil-cli` | Clap commands and JSON rendering |
| `sigil-gui` | Dioxus desktop presentation calling the same service |

`DeviceId` is opaque and scoped to its discovery backend. Serial numbers can be absent and are not used as a unique selection key. A consumer subscribes to events before reading a snapshot and reconciles later events by ID; the mock backend exercises this contract. No general-purpose APDU service is exposed.

PIV operations, authorization, secure secret handling, PIN/PUK workflows, key generation, CSR, and the centralized Go service are future milestones. The `PivDevice` and `FidoDevice` traits currently advertise only availability; typed operational interfaces will be added alongside implementation and tests rather than exposing an unsafe generic command API.

## Next: PIV inspection and hardware validation

Validate Windows discovery with zero, one, and multiple physical devices, including a FIDO-only Security Key and a YubiKey 5 with CCID enabled. Record behavior when the smart-card service is stopped, a token is removed mid-scan, and another application holds the card exclusively. PIV inspection will add typed slots and certificate parsing, without exposing a general-purpose APDU API. Linux later adds pcsc-lite and HID behind the same discovery interface. The PC/SC event watcher uses its own context so blocking notifications do not block scans.

## Quality gates

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

No automated test requires a physical YubiKey. Linux without WebKitGTK development libraries can use `cargo test --workspace --exclude sigil-gui` and the equivalent `cargo clippy` command. Windows CI compiles both entry points but cannot prove behavior with real hardware.
