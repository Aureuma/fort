# fort

`fort` is the SI policy/authentication API for SI Vault operations.

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

## Auth & Session Security
- Access tokens are short-lived JWT bearer tokens.
- Refresh sessions use opaque rotating refresh tokens.
- Reuse of a rotated refresh token is treated as compromise; Fort revokes that refresh session.
- Agent credential rotation invalidates prior auth artifacts:
  - existing access tokens are rejected via `credential_version`
  - existing refresh sessions are revoked
- JWT claims are validated strictly (`iss`, `sub`, `aud`, `jti`, `iat`, `nbf`, `exp`).

## Build
```bash
go build -o .dist/fort ./cmd/fort
go build -o .dist/fortd ./cmd/fortd
go build -o .dist/fort-agent ./cmd/fort-agent
```

## Run locally
```bash
export FORT_ADDR=127.0.0.1:8088
export FORT_STATE_PATH=$PWD/fort-state.json
printf '%s' 'replace-with-at-least-32-char-signing-key' > /tmp/fort-jwt-signing.key
chmod 600 /tmp/fort-jwt-signing.key
export FORT_JWT_SIGNING_KEY_FILE=/tmp/fort-jwt-signing.key
export FORT_SAFE_ROOT=/home/shawn/Development/safe
export FORT_VAULT_KEYRING_FILE=$HOME/.si/vault/si-vault-keyring.json

./.dist/fortd
```

## CLI
```bash
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

`fort run` performs `open -> materialize -> close` session flow.

## Refresh Token Handling (File-Only)
- Do not pass refresh tokens via environment variables.
- Use file-backed refresh token flow:
  - `fort auth session open --agent <id> --refresh-token-out <path>`
  - `fort auth session refresh --refresh-token-file <path> [--refresh-token-out <path>]`
  - `fort-agent --refresh-token-file <path> --token-path <path>`
- Refresh token files must be regular files with `0600` (or stricter) permissions.

## Deploy with Viva
```bash
viva deploy --file deploy/service.yaml
viva deploy --file deploy/service.public.yaml
```

Public domain config is in `deploy/service.public.yaml`.
Both deploy manifests require `FORT_JWT_SIGNING_KEY_FILE` mounted from the host.

## Test
```bash
go test ./...
./scripts/smoke-container.sh
./scripts/e2e-si-vault.sh
```
