# Local backend and Authentik

1. From the repository root, run `.\dev\authentik\up.ps1`. It uses the explicit rootless Podman connection `podman-machine-default`, starts `sigil-test-pg` plus the pinned Authentik server, worker and private PostgreSQL container, and creates local secrets under `dev\.secrets\`. It generates a self-signed P-256 HTTPS certificate for `localhost`, `127.0.0.1` and `::1` under `dev\.secrets\authentik-tls\sigil-localhost\`, mounts it read-only into the server and worker, imports it, and assigns it to the default brand. The served certificate is exported to `dev\.secrets\authentik-ca.pem`. Redis is not required by Authentik 2026.8.3; the dependency was removed in 2025.10.
2. Run `.\dev\authentik\test-token.ps1` to use the confidential `sigil-dev-test` client and `admin1` app password, exchange the machine token for the `sigil` audience, and print only the final token's `iss`, `aud` and `groups` claims. The token signature and all credentials remain local.
3. From an elevated PowerShell session, run `.\installer\dev\new-station-cert.ps1`. It reuses a valid `Sigil dev station` certificate in `LocalMachine\My` or creates a non-exportable client-auth certificate for the machine FQDN. Sigil does not issue or manage enterprise computer certificates.
4. Run `.\dev\backend\setup.ps1`. It generates the local backend TLS identity, grant signing key and escrow KEK under `dev\.secrets\backend\`, writes `backend.toml` and migrates the database at `postgres://postgres:sigil-test@localhost:55432/postgres?sslmode=disable`. If the station certificate is missing, it stops there and prints the elevated certificate-script instruction; after that script succeeds, rerun setup to register the machine FQDN as a station.
5. Start the gateway with `Push-Location backend; go run ./cmd/sigil-server serve --config ..\dev\.secrets\backend\backend.toml; Pop-Location`.
6. Run `.\dev\agent\setup.ps1`. From an elevated PowerShell session it applies the protected Sigil ACL to `dev\.secrets\agent\agent.toml` and places copies of the public backend CA and grant-verification key beside it. A non-elevated run writes the config for the mock-only `--dev-insecure-config` smoke test; rerun it elevated before using the config without that flag. The agent uses the hostname-derived lowercase station ID and the non-exportable certificate in `LocalMachine\My`.
7. Build and perform the read-only mTLS check from an elevated PowerShell session:

   ```powershell
   $env:CARGO_TARGET_DIR='target\sidekick'
   cargo build -p sigil-agent
   .\target\sidekick\debug\sigil-agent.exe backend check --config dev\.secrets\agent\agent.toml
   ```

8. To run the station agent in an elevated console without `--dev-insecure-config`, use a separate development pipe endpoint:

   ```powershell
   .\target\sidekick\debug\sigil-agent.exe --config dev\.secrets\agent\agent.toml run --endpoint '\\.\pipe\sigil-agent-dev'
   ```

   With `[backend]` configured, the agent reports its current token inventory on startup, device changes and a 15-minute interval, and forwards its durable audit outbox in the background.
   For a non-elevated, hardware-free smoke test only, use `run --mock --dev-insecure-config --endpoint '\\.\pipe\sigil-agent-mock'`. Never combine `--dev-insecure-config` with real hardware or service mode.

`dev\.secrets\` is ignored by Git. Keep it local and do not paste its contents into issues or logs. The Authentik containers are persistent; `.\dev\authentik\down.ps1` stops them but preserves their volumes.

All `dev/` Podman commands explicitly use the rootless `podman-machine-default` connection. The machine's default connection remains `podman-machine-default-root`. Use `localhost` (which reaches the rootless published port over `::1`); do not use `127.0.0.1` or the Podman VM IP. This avoids the rootful published-port limitation tracked in Podman issue [#29377](https://github.com/containers/podman/issues/29377).
