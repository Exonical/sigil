# Repository guidance

## Quality gates

Run these commands from the workspace root before handing off changes:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

From the repository root, `gofmt -l $(find backend -type f -name '*.go')` must print nothing. From `backend/`, run:

```sh
go generate ./...
go vet ./...
go tool staticcheck ./...
go test ./...
```

After `go generate ./...`, run `git diff --exit-code` from the repository root to ensure generated code is up to date.

The Windows PC/SC hardware test is read-only and returns without hardware access unless `SIGIL_HARDWARE_TESTS=1` is set. Regular tests must remain hardware-free.

To build the Windows x64 MSI with the pinned user-local .NET SDK and repo-local WiX tool, run from the workspace root:

```powershell
$env:CARGO_TARGET_DIR='target\sidekick'
.\installer\windows\build.ps1
```

Validate it without installing it using `dotnet wix msi validate target\installer\Sigil-<version>-x64.msi`.

## Conventions

- Keep `sigil-core` vendor-neutral and expose typed domain APIs through `sigil-app`.
- Do not expose raw APDU transport beyond provider crates. Never add an arbitrary APDU endpoint to the app, CLI, GUI, or a remote protocol.
- Never pass PINs or PUKs as CLI arguments. Prompt securely when authorization is introduced, and never persist or log secrets.
- Keep PIV inspection read-only. Tests that change a physical token require `SIGIL_HARDWARE_TESTS=1` and `SIGIL_HARDWARE_MUTATION_SERIAL=<serial>`, must restore factory defaults with a PIV reset, and must never use touch-required policies.
- Prefer focused changes, follow the existing Rust style, and add hardware-free tests for protocol parsing and service behavior.
- Hardware is accessed by `sigil-agent` or, in direct mode, in-process by the CLI/GUI as the current user. Operations that use system-held secrets (escrowed or randomized PUK/management key, configuration lock codes, backend grants) run only in `sigil-agent`. The CLI/GUI prefer a running, trusted agent; machine policy `RequireAgent` (`HKLM\SOFTWARE\Policies\Sigil` or `/etc/sigil/client.toml`) disables direct mode.
- Every read-only RPC is audit-logged. Never log PINs, PUKs, signed grants, or raw APDUs.
- Backend grants are required only when the agent itself uses a system-held secret. Operations where the caller supplies the PIN, PUK, or management key are user-configurable and audit-only. The `dev-grants` feature must never be enabled in release builds.
- Escrow-backed agent operations that use a system-held secret must verify the grant against the token serial read inside the same card transaction that performs the mutation.

## Product decisions

- Target experience: PIV enrollment in about 10 seconds (FIDO2 adds 5-10 seconds), several certificates per token in one pass, over USB or NFC, with any number of connected keys.
- Default to ECC (P-256/P-384) key generation; on-device RSA generation is too slow for the enrollment target. Keys are always generated on the token.
- CSRs must carry PIV attestation (slot F9 chain to the Yubico PIV root, bundled offline). The agent installs only certificates that chain to the configured CA.
- PIN and touch policy come from the credential profile. PIV policies are fixed at key generation; changing them means regenerating the key and reissuing.
- Users set their own PIN locally during enrollment. The PUK and management key are randomized by the system.
- PIN recovery is per profile: `reenroll` (reset PIV and reissue) or `puk_escrow` (random PUK held by the secrets provider and released only for an approved unblock).
- Management key storage is per profile: `pin_protected` (on the card behind the user's PIN) or `escrowed` (secrets provider).
- The agent runs in two modes: station mode (help-desk provisioning workstation, station mTLS identity, full operations) and user mode (end-user machine, IdP login, limited to the user's own token: PIN change and recovery as the profile allows).
- Windows blocks raw CTAP access for non-admin processes over both USB-HID and NFC/PC/SC (the FIDO applet SELECT is denied). Station mode may run elevated; user-mode FIDO on Windows must use the Windows WebAuthn API. PIV over PC/SC (USB or NFC) does not need admin; neither do OATH (CCID) or YubiKey OTP slot configuration (keyboard HID), matching Yubico Authenticator, where only WebAuthn/passkey changes require elevation.
- YubiKey 5 FIPS firmware 5.7 requires an 8-character PIN and PUK, a non-default AES management key, and PIN complexity before key generation is approved; PIN policy `never`, RSA-1024, 3DES, and X25519 are unavailable. PIV reset returns the applet to unapproved mode. FIPS PIV over NFC requires SCP03/SCP11, which is not implemented.
- Because a local user can reach PIV, OATH, and OTP directly without the agent, the agent cannot be the only control for those applets on user machines. PIV enforcement relies on secrets the user never holds (randomized PUK and management key) plus backend checks (attestation, CA binding, inventory/serial reconciliation). A user can always change their own PIN or reset PIV after blocking PIN and PUK; the backend must detect that (missing or unattested certificates) rather than assume it is impossible.
- FIDO2 enrollment IdPs, in priority order: Authentik, Keycloak. Whether each supports API import of credentials or needs browser registration is still unverified.
- Backend grants are required only when the agent itself uses a system-held secret. Operations where the caller supplies a PIN, PUK, or management key are user-configurable and audit-only. Everything the user can already do with stock tools remains user-configurable and only audit-logged, including PIV PIN change, OATH accounts and password, YubiKey OTP slots 1/2, and FIDO PIN change. Windows Settings also lets non-admin users change the FIDO PIN and reset a security key.
- OATH accounts and YubiKey OTP slots 1/2 are in scope after the Go backend (M7), as user-configurable features.
- Backend: Go 1.27 server and web portal (inventory, revocation by "delete key", lost keys by token nickname).

## Development environment

- Local Authentik setup is documented in `dev/README.md`; it uses the pinned 2026.8.3 release, PostgreSQL, and no Redis.
- Keep all generated Authentik, backend signing, escrow, and certificate material under ignored `dev/.secrets/`. Never log or paste these values.
- `installer/dev/new-station-cert.ps1` requires elevation and uses the machine's `LocalMachine\My` store. Do not run it from an automated development handoff; ask the operator to approve and run it.
- All `dev/` Podman commands must explicitly use the rootless `podman-machine-default` connection; leave the machine default `podman-machine-default-root` unchanged. Use `localhost` for published ports and database URLs, not `127.0.0.1` or the Podman VM IP; rootful published ports are affected by [Podman issue #29377](https://github.com/containers/podman/issues/29377).
