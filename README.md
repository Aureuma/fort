# fort

`fort` is the policy/authentication API for Vault operations.

See also:
- `docs/GUIDING_PRINCIPLES.md`
- `CHANGELOG.md` and `docs/RELEASING.md` for versioning and the release process

## Components
- `fortd`: HTTP API server
- `fort`: CLI client
- `fort-agent`: refreshes short-lived access tokens from a refresh-token file

## Install
```bash
brew tap aureuma/fort
brew install aureuma/fort/fort
fort version
fort doctor
```

Portable archives (`fort_<version>_{linux,darwin}_{amd64,arm64}.tar.gz` plus
`checksums.txt`) are attached to each GitHub Release. Start with
`fort auth github login`, then use `get`, `set`, `list`, and `run`.
Every command documents itself: `fort --help`, `fort <command> --help`.

## Architecture
Fort is intentionally thin.

Fort does:
- bearer-token authentication
- policy authorization at `repo/env/op`
- secret operation routing to Vault-backed data in `safe` (`.env.<env>` files)

Fort does not:
- store secret key/value material in Fort state
- expose bootstrap/admin bypass keys

## Guiding Principles
- Fort is an authz/authn wrapper over Vault, not a second vault.
- All secret reads/writes resolve against Vault-backed `safe` `.env` material.
- Workloads authenticate with short-lived access tokens and rotating refresh sessions.
- Refresh and signing secrets are file-backed and strict-permissioned (`0600`), never env-injected secret values.
- Vault ciphertext files (`safe/<repo>/.env.<env>`) must be regular files with `0600` (or stricter).
- Vault keyring material is file-backed JSON state (`~/.vault/keyring.json` by default), not OS keychain storage.
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
safe_root = "<path-to-safe-checkout>"
vault_keyring_file = "$HOME/.vault/keyring.json"
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
fort auth github login|logout|enroll|unenroll|list
fort get
fort set
fort list
fort batch-get
fort scope ensure
fort run
fort rotate npm
fort agent create|get|list|set-status|rotate|remove
fort agent policy get|set|add|remove|check
```

Use `fort set --value-file <0600-path>` for credentials and other secret values.
The legacy `--value` form remains available for non-sensitive fixtures, but it places
the value in the process argument list and must not be used for real secrets.

An administrator can create an exact repository/environment encryption scope with
`fort scope ensure --repo <repo> --env <env>`. The operation reuses Fort's established
single canonical keypair, is idempotent and audited, and never returns key material.

CLI host resolution order:
1. `--host`
2. `FORT_HOST`
3. `~/.fort/settings.toml` `[fort].host` (`FORT_SETTINGS_FILE` overrides the path)

`fort run` performs `open -> materialize -> close` session flow.

### npm Token Rotation

`fort rotate npm` rotates an npm access token stored in Fort-managed Safe material.
The command reads the current publish token, npm management token, and optionally npm password through Fort,
creates a new npm granular token through the npm registry API, writes the new token back through
Fort, and optionally revokes the old npm token after the Fort write succeeds.

Example:

```bash
fort rotate npm \
  --repo svelta-blog \
  --env prod \
  --token-key NPM_TOKEN \
  --management-token-key NPM_MANAGEMENT_TOKEN \
  --password-key NPM_PASSWORD \
  --otp-file /run/user/1000/npm-otp \
  --name svelta-blog-prod-publish-$(date +%Y%m%d) \
  --package @aureuma/svelta-blog \
  --packages-permission read-write \
  --expires-days 90 \
  --bypass-2fa \
  --github-actions-repo Aureuma/svelta-blog \
  --github-secret-name NPM_TOKEN \
  --github-token-repo orbit \
  --github-token-env prod \
  --github-token-key GH_PAT_AUREUMA \
  --revoke-old
```

Notes:
- `--otp-file` must point to a `0600` file containing the current npm OTP.
- `--password-key` is optional; include it when the management token flow requires it. If omitted, Fort attempts passwordless token creation for providers that allow it.
- `--management-token-key` should be a token capable of npm token management; it defaults to `--token-key` only for accounts where the stored token can create/revoke tokens.
- Use explicit `--package` or `--scope` values for least privilege. `--all-packages` is accepted only when broad access is intentional.
- Read-write npm tokens are capped at 90 days.
- JSON output redacts token values; the full new token is written only through Fort.
- `--github-actions-repo` updates a repository Actions secret with the new npm token after the Fort write succeeds. Fort fetches the repository public key, encrypts the new token with GitHub-compatible sealed-box encryption, and sends only the encrypted value to GitHub.
- Old npm token revocation runs after every configured sink succeeds, including GitHub Actions secret updates.
- `--dry-run` validates the requested npm token shape and configured sinks without reading secret values, contacting npm, updating Fort, or updating GitHub.

CLI token sources:
1. `--token-file`
2. `FORT_TOKEN_PATH`
3. `FORT_BOOTSTRAP_TOKEN_FILE`
4. managed session at `$FORT_SESSION_DIR/access.token` (default `~/.fort/session/access.token`, last resort)

Use `FORT_TOKEN_PATH` only for managed runtime environments where the
orchestrator passes explicit token files to `fort`.

Deprecated token-value env vars are disallowed:
- `FORT_TOKEN`
- `FORT_REFRESH_TOKEN`

For managed runtimes: when no explicit token source is configured and
`$FORT_SESSION_DIR/refresh.token` exists, `fort` refreshes the managed session
as needed. A missing or near-expiry access token is bootstrapped from the
refresh token, the new access token is written to
`$FORT_SESSION_DIR/access.token`, and the refresh token is rotated in place.
Explicit token sources always win and never trigger a managed refresh. Auth
stays file-based (no bearer token argv flow), so plain commands work directly:

```bash
fort --host https://fort.aureuma.ai doctor
```

## GitHub PAT Login (Remote Machines)

Remote machines authenticate with a GitHub fine-grained PAT. Fort verifies the
PAT live against the GitHub API (`GET /user`) and maps it to a Fort agent via
an HMAC-SHA256 fingerprint keyed by a server-side pepper. The server never
stores, logs, or echoes the PAT itself — only the fingerprint is persisted.

```bash
# one-time per machine (admin enrolls the machine's PAT fingerprint)
fort --host https://fort.aureuma.ai --token-file admin.token \
  agent create --id vps-vanguarda --type workload
fort --host https://fort.aureuma.ai --token-file admin.token \
  agent policy set --id vps-vanguarda --bind '*:*:*'
fort --host https://fort.aureuma.ai --token-file admin.token \
  auth github enroll --agent vps-vanguarda --pat-file machine.pat

# on the machine: log in (writes the managed session, no flags needed after)
fort --host https://fort.aureuma.ai auth github login
fort --host https://fort.aureuma.ai get --repo safe --env prod --key NPM_TOKEN
fort --host https://fort.aureuma.ai auth github logout
```

Without `--pat-file` (needs fort 1.0.7+), login reuses the stored PAT at
`~/.fort/github.pat` when present, otherwise it prompts for the PAT with
hidden input and stores it there as a `0600` file after a successful login.
Delete that file to enter a different PAT. `--pat-file` still bypasses the
prompt and the stored PAT, and is never itself stored.

Rules:

- `--pat-file` must point to a `0600` file. PATs are never accepted via argv or
  environment variables.
- The CLI refuses to send a PAT over plaintext HTTP except to loopback hosts
  (isolated integration tests). Production login is HTTPS-only.
- Server config needs `github_pepper_file` (a `0600` file with 32+ characters);
  without it the github endpoints return `503`. `github_api_base` defaults to
  `https://api.github.com` and only needs overriding in tests.
- Login attempts are throttled per source IP and audited (fingerprint prefix
  only, never the PAT).

## Refresh Token Handling (File-Only)
- Do not pass refresh tokens via environment variables.
- Use file-backed refresh token flow:
  - `fort auth session open --agent <id> --refresh-token-out <path>`
  - `fort auth session refresh --refresh-token-file <path> [--refresh-token-out <path>]`
  - `fort-agent --refresh-token-file <path> --token-path <path>`
- Managed refresh tokens live at `$FORT_SESSION_DIR/refresh.token` (default `~/.fort/session/refresh.token`) and must be refreshed in place.
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

`fortd` now fails at startup when the mounted safe root or Vault keyring path is missing or invalid, instead of deferring that failure until first secret access.

## Test
```bash
cargo test
cargo test fort_e2e_roundtrip_preserves_vault_ciphertext_contract -- --nocapture
./scripts/smoke-container.sh
./scripts/e2e-vault.sh
```

Integration coverage includes:
- Rust e2e coverage for `fortd` + `fort` + `fort-agent`
- Fort↔Vault parity checks against ciphertext in `safe`
- container smoke validation through the Docker image
