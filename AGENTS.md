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
