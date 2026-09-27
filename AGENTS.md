# Repository guidance

## Quality gates

Run these commands from the workspace root before handing off changes:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The Windows PC/SC hardware test is read-only and returns without hardware access unless `SIGIL_HARDWARE_TESTS=1` is set. Regular tests must remain hardware-free.

## Conventions

- Keep `sigil-core` vendor-neutral and expose typed domain APIs through `sigil-app`.
- Do not expose raw APDU transport beyond provider crates. Never add an arbitrary APDU endpoint to the app, CLI, GUI, or a remote protocol.
- Never pass PINs or PUKs as CLI arguments. Prompt securely when authorization is introduced, and never persist or log secrets.
- Keep PIV inspection read-only. Gate hardware-specific tests with `SIGIL_HARDWARE_TESTS=1` and never make tests mutate a physical token.
- Prefer focused changes, follow the existing Rust style, and add hardware-free tests for protocol parsing and service behavior.

## Product decisions

- Target experience: PIV enrollment in about 10 seconds (FIDO2 adds 5-10 seconds), several certificates per token in one pass, over USB or NFC, with any number of connected keys.
- Default to ECC (P-256/P-384) key generation; on-device RSA generation is too slow for the enrollment target. Keys are always generated on the token.
- CSRs must carry PIV attestation (slot F9 chain to the Yubico PIV root, bundled offline). The agent installs only certificates that chain to the configured CA.
- PIN and touch policy come from the credential profile. PIV policies are fixed at key generation; changing them means regenerating the key and reissuing.
- Users set their own PIN locally during enrollment. The PUK and management key are randomized by the system.
- PIN recovery is per profile: `reenroll` (reset PIV and reissue) or `puk_escrow` (random PUK held by the secrets provider and released only for an approved unblock).
- Management key storage is per profile: `pin_protected` (on the card behind the user's PIN) or `escrowed` (secrets provider).
- The agent runs in two modes: station mode (help-desk provisioning workstation, station mTLS identity, full operations) and user mode (end-user machine, IdP login, limited to the user's own token: PIN change and recovery as the profile allows).
- Windows blocks raw CTAP access for non-admin processes over both USB-HID and NFC/PC/SC (the FIDO applet SELECT is denied). Station mode may run elevated; user-mode FIDO on Windows must use the Windows WebAuthn API. PIV over PC/SC (USB or NFC) does not need admin.
- FIDO2 enrollment IdPs, in priority order: Authentik, Keycloak. Whether each supports API import of credentials or needs browser registration is still unverified.
- Backend: Go 1.27 server and web portal (inventory, revocation by "delete key", lost keys by token nickname).
