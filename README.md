# Sigil

Sigil is a local credential manager for YubiKeys and, later, other hardware credentials. Windows discovery, FIDO inspection, and PIV inspection are read-only; explicit fingerprint enrollment and deletion are available for supported Bio keys. PIV mutation and enrollment are later milestones.

## Run it

Install the current stable Rust toolchain. On Windows 11, install the MSVC C++ build tools and WebView2 runtime for the Dioxus desktop app. On Linux, install the Dioxus desktop WebKitGTK development dependencies (see the [Dioxus desktop guide](https://dioxuslabs.com/learn/0.7/guides/platforms/desktop/)).

```sh
cargo run -p sigil-cli -- device list
cargo run -p sigil-cli -- device list --json
cargo run -p sigil-gui
```

Copy an opaque device ID from `device list`; quote it in PowerShell. On Windows, FIDO operations over USB HID or NFC/PC/SC currently require an elevated PowerShell. User-mode FIDO will use the Windows WebAuthn API in a later milestone. PIN prompts do not echo or put the PIN in shell history.

```powershell
cargo run -p sigil-cli -- fido info '<device-id>' --json
cargo run -p sigil-cli -- fido credentials list '<device-id>' --json
cargo run -p sigil-cli -- fido fingerprints list '<device-id>' --json
cargo run -p sigil-cli -- fido fingerprints enroll '<device-id>' --json
cargo run -p sigil-cli -- fido fingerprints remove '<device-id>' '<fingerprint-id>' --yes
```

PIV inspection is read-only. It displays PIN/PUK retry metadata, key policy and algorithm metadata when available, and certificate summaries. Certificates can be shown or exported as PEM/DER; export paths are created exclusively and are never overwritten.

```powershell
cargo run -p sigil-cli -- --backend mock piv info mock-yubikey-12345678 --json
cargo run -p sigil-cli -- --backend mock piv slots mock-yubikey-12345678 --json
cargo run -p sigil-cli -- --backend mock piv certificate show mock-yubikey-12345678 9a
cargo run -p sigil-cli -- --backend mock piv certificate export mock-yubikey-12345678 9a
cargo run -p sigil-cli -- piv info '<smart-card-device-id>'
cargo run -p sigil-cli -- piv slots '<smart-card-device-id>'
cargo run -p sigil-cli -- piv certificate export '<smart-card-device-id>' 9a --format der --output .\authentication.der
```

Mock certificates are self-signed public test fixtures and do not contain private keys. Native PIV commands require a discovered `windows-pcsc:` device with an enabled PIV application. A FIDO-only key is not a smart-card device. No real PIV hardware was available for validation on the development machine (the attached YubiKey is FIDO-only and Windows `SCardSvr` is stopped); all regular tests are hardware-free. The native read-only hardware test is skipped unless `SIGIL_HARDWARE_TESTS=1` is set.

Run the gated hardware test with `$env:SIGIL_HARDWARE_TESTS='1'; cargo test -p sigil-platform --test hardware_piv`; without the environment variable it returns without touching hardware. The GUI can open a second, elevated instance on request when Windows restricts FIDO HID access. Only discoverable credentials can be listed. Fingerprint enrollment shows capture progress and needs repeated touches of the same finger; deleting a fingerprint requires a second confirmation and a fresh PIN entry. Fingerprint deletion is permanent. Sigil does not save PINs or enumerate non-discoverable credentials. The Bio operations compile for Windows but require validation with a physical Bio key before operational use.

On Windows, these commands use native discovery. Select a returned opaque ID with `cms device info <id>`; `--json` is available for both device commands. For hardware-free development use `cargo run -p sigil-cli -- --backend mock device list --json` and `cargo run -p sigil-gui -- --mock`. On Linux, the mock remains the default until the native backend is implemented; `--backend native` reports an explicit error. The CLI binary is named `cms`.

The Windows backend enumerates every smart-card reader through WinSCard/PC/SC. YubiKey-named readers are treated as USB CCID; on other readers, including ACS, Identiv, and HID Omnikey NFC readers, Sigil probes the read-only Yubico management applet and lists a device only when that applet responds. Non-YubiKey cards, including generic PIV cards, are ignored. NFC management metadata reports NFC-specific enabled and supported applications separately from USB capabilities. PIV inspection uses the same reader-scoped device ID and works over NFC. FIDO-only Yubico USB product IDs are enumerated through HID; HID presence alone does not establish CTAP2 support, so application and firmware fields remain unknown. Smart-card insertion/removal uses reader notifications; HID-only discovery refreshes every five seconds. Multiple readers and keys keep separate opaque device IDs. Hardware-generated attributes require validation on physical devices before relying on them operationally.

If the Windows Smart Card service (`SCardSvr`) is stopped, the CLI warns on stderr and HID discovery can still list FIDO-capable YubiKeys, including models with a CCID interface. A present Yubico HID interface path supplies a fallback when Windows denies access to its FIDO descriptor; this proves USB presence alone. When direct HID access is available, Sigil uses CTAPHID INIT and Yubico's read-only management command to obtain firmware, serial, form factor, and application capabilities. On Windows a normal session may detect the FIDO key but lack permission to open it, so metadata remains unknown; run the CLI elevated to test direct access. Older keys may not provide serial or management data over FIDO even with access. Smart-card metadata is unavailable until the service starts. An empty list while the service is stopped does not rule out a CCID-only key. The watcher retries the service every five seconds. Check `Get-Service SCardSvr` in PowerShell; if a connected CCID key is still missing, run `Start-Service SCardSvr` in an elevated PowerShell and repeat `cargo run -p sigil-cli -- device list --json`. Windows may stop the service when no smart-card reader is attached; a FIDO-only key does not require it.

NFC discovery and PIV-over-NFC have not been validated on hardware because no NFC reader is available on the development machine. The native PC/SC path probes other readers with only the read-only Yubico management SELECT/READ commands and ignores cards that do not provide Yubico management data.

## Architecture

| Crate | Responsibility |
| --- | --- |
| `sigil-core` | Vendor-neutral device types, discovery/events, optional PIV and FIDO traits, typed errors |
| `sigil-app` | Shared inventory and explicit device selection used by both entry points |
| `sigil-mock` | Hardware-free inventory and connection/update/removal events |
| `sigil-platform` | Windows PC/SC and HID discovery; Linux native implementation remains a placeholder |
| `sigil-yubikey` | Read-only YubiKey management and PIV metadata provider |
| `sigil-piv` | Vendor-neutral read-only PIV APDU flow, BER-TLV, certificate parsing and encoding |
| `sigil-cli` | Clap commands and JSON rendering |
| `sigil-gui` | Dioxus desktop presentation calling the same service |

`DeviceId` is opaque and scoped to its discovery backend. Serial numbers can be absent and are not used as a unique selection key. A consumer subscribes to events before reading a snapshot and reconciles later events by ID; the mock backend exercises this contract. No general-purpose APDU service is exposed.

PIV mutation, authorization, secure secret handling, PIN/PUK changes, key generation, CSR creation, and the centralized Go service are future milestones. The `PivDevice` and `FidoDevice` traits retain capability-level availability checks; discovery backends additionally implement typed read-only inspection through their respective inspection traits. No general-purpose APDU service is exposed.

## Next: Milestone 4 — PIV mutation

The next milestone adds carefully authorized PIV mutation workflows, including PIN/PUK management, key generation, and CSR creation. These operations must keep PINs out of command-line arguments and logs, and must remain separate from the provider-internal APDU transport. Validate all mutating hardware behavior on dedicated test devices before operational use. Linux later adds pcsc-lite and HID behind the same discovery interface. The PC/SC event watcher uses its own context so blocking notifications do not block scans.

## Quality gates

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

No automated test requires a physical YubiKey. Linux without WebKitGTK development libraries can use `cargo test --workspace --exclude sigil-gui` and the equivalent `cargo clippy` command. Windows CI compiles both entry points but cannot prove behavior with real hardware.
