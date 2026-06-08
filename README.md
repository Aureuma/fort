# fort

`fort` is the SI policy/authentication API for SI Vault operations.

See also:
- `docs/GUIDING_PRINCIPLES.md`

## Components
- `fortd`: HTTP API server
- `fort`: CLI client
- `fort-agent`: refreshes short-lived access tokens from a refresh-token file

## Architecture
Fort is intentionally thin.

Fort does:
- bearer-token authentication
- policy authorization at `repo/env/op`
- secret operation routing to SI Vault-backed data in `safe` (`.env.<env>` files)

Fort does not:
- store secret key/value material in Fort state
- expose bootstrap/admin bypass keys

## Guiding Principles
- Fort is an authz/authn wrapper over SI Vault, not a second vault.
- All secret reads/writes resolve against SI Vault-backed `safe` `.env` material.
- Workloads authenticate with short-lived access tokens and rotating refresh sessions.
- Refresh and signing secrets are file-backed and strict-permissioned (`0600`), never env-injected secret values.
- SI Vault ciphertext files (`safe/<repo>/.env.<env>`) must be regular files with `0600` (or stricter).
- SI Vault keyring material is file-backed JSON state (`~/.si/vault/si-vault-keyring.json` by default), not OS keychain storage.
- Provisioning is explicit and authenticated; there is no hidden bootstrap bypass path.

## Auth & Session Security
- Access tokens are short-lived JWT bearer tokens.
- Refresh sessions use opaque rotating refresh tokens.
- Opening a refresh session for an agent revokes any prior active refresh session for that same agent.
- Reuse of a rotated refresh token is treated as compromise; Fort revokes that refresh session.
- For `fort-breakglass-admin`, token issuance revokes any prior active break-glass tokens and refresh sessions.
- Agent credential rotation invalidates prior auth artifacts:
  - existing access tokens are rejected via `credential_version`
  - existing refresh sessions are revoked
- JWT claims are validated strictly (`iss`, `sub`, `aud`, `jti`, `iat`, `nbf`, `exp`).

## Build
```bash
cargo build --release --bin fort --bin fortd --bin fort-agent --bin fort-seed
```

Container builds are Rust-only and lock to `Cargo.lock`.
The runtime image ships:
- `fortd`
- `fort`
- `fort-agent`

The runtime image intentionally does not ship `fort-seed`; provisioning shortcuts remain test-only.

## Run locally
```bash
mkdir -p .artifacts/local
printf '%s' 'replace-with-at-least-32-char-signing-key' > .artifacts/local/fort-jwt-signing.key
chmod 600 .artifacts/local/fort-jwt-signing.key
cat > .artifacts/local/fortd.toml <<EOF
addr = "127.0.0.1:8088"
state_path = "$PWD/.artifacts/local/fort-state.json"
jwt_signing_key_file = "$PWD/.artifacts/local/fort-jwt-signing.key"
safe_root = "/home/shawn/Development/safe"
vault_keyring_file = "$HOME/.si/vault/si-vault-keyring.json"
token_ttl = "15m"
refresh_session_ttl = "30d"
run_ttl = "60s"
secret_ttl = "120s"
EOF

./.artifacts/cargo-target/release/fortd --config-file .artifacts/local/fortd.toml
```

## CLI
```bash
fort -h
fort doctor
fort version
fort auth issue|login|whoami|list|revoke
fort auth session open|refresh|close
fort get
fort set
fort list
fort batch-get
fort run
fort agent create|get|list|set-status|rotate|remove
fort agent policy get|set|add|remove|check
```

CLI host resolution order:
1. `--host`
2. `FORT_HOST`
3. `~/.si/fort/settings.toml` `[fort].host` (or `~/.si/settings.toml` `[fort].host`)

`fort run` performs `open -> materialize -> close` session flow.

CLI token sources:
1. `--token-file`
2. `FORT_TOKEN_PATH`
3. `FORT_BOOTSTRAP_TOKEN_FILE`

Use `FORT_TOKEN_PATH` only for managed runtime environments. SI-managed Codex runtime auth is owned by `si codex spawn` / `si codex shell`, which pass explicit token files to native `fort`.

Deprecated token-value env vars are disallowed:
- `FORT_TOKEN`
- `FORT_REFRESH_TOKEN`

For SI runtime workers, prefer the `si fort ...` wrapper path:
- SI reads the managed Codex profile session under `CODEX_HOME/fort/`
- SI refreshes as needed
- SI keeps auth file-based (no bearer token argv flow)

When invoking `fort` flags through the SI wrapper, pass native `fort` flags after `--`:

```bash
si fort -- --host https://fort.aureuma.ai doctor
```

## Refresh Token Handling (File-Only)
- Do not pass refresh tokens via environment variables.
- Use file-backed refresh token flow:
  - `fort auth session open --agent <id> --refresh-token-out <path>`
  - `fort auth session refresh --refresh-token-file <path> [--refresh-token-out <path>]`
  - `fort-agent --refresh-token-file <path> --token-path <path>`
- Codex profile refresh tokens must be refreshed in place:
  - `~/.si/codex/profiles/<profile>/fort/refresh.token` for `primary`
  - `~/.si/codex/profiles/<profile>/workers/<slot>/fort/refresh.token` for non-primary slots
- Refresh token files must be regular files with `0600` (or stricter) permissions.
- `fort-agent` enforces regular-file checks and strict permission checks on refresh-token files.

## Deploy with Viva
```bash
viva deploy --file deploy/viva.api-local.prod.yaml
viva deploy --file deploy/viva.api.prod.yaml
```

Public domain config is in `deploy/viva.api.prod.yaml`.
Both deploy manifests require Fort config to reference mounted file-backed secrets and storage paths.
The runtime contract stays file-backed in containerized deploys:
- `jwt_signing_key_file` must point to a mounted `0600` regular file
- `vault_keyring_file` must point to a mounted `0600` regular file
- `safe_root` must point to the mounted `safe` directory

`fortd` now fails at startup when the mounted safe root or SI Vault keyring path is missing or invalid, instead of deferring that failure until first secret access.

## Test
```bash
cargo test
cargo test fort_e2e_roundtrip_preserves_vault_ciphertext_contract -- --nocapture
./scripts/smoke-container.sh
./scripts/e2e-si-vault.sh
```

Integration coverage includes:
- Rust e2e coverage for `fortd` + `fort` + `fort-agent`
- Fort↔Vault parity checks against ciphertext in `safe`
- container smoke validation through the Docker image
