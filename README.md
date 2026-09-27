# Sigil

Sigil is a proposed local credential manager for YubiKeys and, later, other hardware credentials. **Milestone 1 is a hardware-free prototype.** Its sample serial, firmware, transports, and application list are simulated. It does not inspect or change a real token.

## Try the prototype

Install the current stable Rust toolchain. On Windows 11, install the MSVC C++ build tools and WebView2 runtime for the Dioxus desktop app. On Linux, install the Dioxus desktop WebKitGTK development dependencies (see the [Dioxus desktop guide](https://dioxuslabs.com/learn/0.7/guides/platforms/desktop/)).

```sh
cargo run -p sigil-cli -- device list
cargo run -p sigil-cli -- device list --json
cargo run -p sigil-cli -- device info mock-yubikey-12345678
cargo run -p sigil-gui
```

The CLI binary is named `cms`. `--backend mock` is the default **for this prototype only**. `--backend native` fails explicitly until native discovery is implemented. The GUI shows a prominent simulated-hardware label. Neither path performs hardware operations.

## Architecture

| Crate | Responsibility |
| --- | --- |
| `sigil-core` | Vendor-neutral device types, discovery/events, optional PIV and FIDO traits, typed errors |
| `sigil-app` | Shared inventory and explicit device selection used by both entry points |
| `sigil-mock` | Hardware-free inventory and connection/update/removal events |
| `sigil-platform` | OS boundary; Windows and Linux native implementations are placeholders |
| `sigil-yubikey` | Provider skeleton for YubiKey-specific protocol operations |
| `sigil-cli` | Clap commands and JSON rendering |
| `sigil-gui` | Dioxus desktop presentation calling the same service |

`DeviceId` is opaque and scoped to its discovery backend. Serial numbers can be absent and are not used as a unique selection key. A consumer subscribes to events before reading a snapshot and reconciles later events by ID; the mock backend exercises this contract. No general-purpose APDU service is exposed.

PIV operations, authorization, secure secret handling, PIN/PUK workflows, key generation, CSR, and the centralized Go service are future milestones. The `PivDevice` and `FidoDevice` traits currently advertise only availability; typed operational interfaces will be added alongside implementation and tests rather than exposing an unsafe generic command API.

## Milestone 2: Windows discovery

Replace `NativeDiscovery` on Windows with an adapter that enumerates Windows smart-card readers through WinSCard/PC/SC and correlates the YubiKey USB interfaces needed for model, serial, firmware, and capabilities. Keep the native adapter behind `DeviceDiscovery`; the CLI and GUI continue to consume `CredentialService`. Give each connected token a stable, per-session opaque ID and support multiple readers/tokens. Subscribe to reader and device changes, reconcile against fresh snapshots, and surface removal during an operation. Do not infer PIV support solely from a reader name or infer FIDO2 support from a PIV connection. Explicitly distinguish unknown attributes from verified capabilities. Test on Windows 11 x64 with zero, one, and multiple keys; use gated hardware tests alongside mock tests.

For PIV, the maintained `pcsc` crate wraps WinSCard on Windows and pcsc-lite/pcscd on Linux. The `hidapi` crate offers cross-platform HID access; CTAP-level options include `ctap-hid-fido2`, which should be reviewed for security and maintenance before adoption. Linux later adds udev/hidraw and PC/SC integration behind the same interface. Avoid holding a single PC/SC context in a blocking event call while also using it for APDU operations.

## Quality gates

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

No test requires a physical YubiKey. The GUI requires a graphical desktop session to launch; compilation and non-GUI tests can run headlessly when desktop development libraries are installed.
