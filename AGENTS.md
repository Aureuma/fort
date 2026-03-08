# Fort Mission Contract

## Purpose
Fort is the policy and authentication API boundary for SI Vault operations.

Fort stays intentionally thin:
- authenticate agent requests with bearer access tokens
- authorize by policy bindings (`repo/env/op`)
- route secret operations to SI Vault-backed material in `safe`

## Hard Boundaries
Fort must not:
- persist secret key/value material in Fort state
- expose unauthenticated setup/bootstrap bypass paths
- hold long-lived secret plaintext in process memory outside request scope
- couple SI Vault secret flows to Sun

Fort state is limited to:
- agents
- policies
- token and refresh-session records
- audit events

## Security Principles
- Every sensitive endpoint is bearer-token authenticated.
- Admin operations require wildcard admin policy (`*:*:*`) on the calling agent.
- Workload access is policy-scoped by `repo`, `env`, and operation.
- Access tokens are short-lived JWTs with strict claim validation (`iss/sub/aud/jti/iat/nbf/exp`).
- Refresh sessions use rotating opaque refresh tokens with reuse detection and compromise revocation.
- Only one active refresh session is allowed per agent; opening a new one revokes prior active sessions.
- `fort-breakglass-admin` must have a single active break-glass auth state; reissue revokes prior active tokens/sessions.
- Agent credential rotation invalidates prior access tokens and refresh sessions.
- Refresh tokens and JWT signing keys are file-backed secrets only (`0600`), never env-injected secret values.
- SI Vault ciphertext files (`safe/<repo>/.env.<env>`) must be regular files with `0600` (or stricter).

## Provisioning and Bootstrap
- There is no production seeding/bootstrap shortcut.
- Operational provisioning is explicit and authenticated:
  - create/enable agent
  - apply policy bindings
  - open refresh session for workload runtime
- Test fixtures may initialize isolated local state for integration tests only.

## Data Plane Contract
- `get/set/list/batch-get/run` operate against SI Vault ciphertext in `safe` (`encrypted:si-vault:`).
- Fort does not maintain an independent secret store.
- Per `repo/env` cryptographic material is resolved from the configured SI Vault keyring.
- Keyring scope entries must resolve to one canonical SI Vault keypair across all scopes (anti-sprawl invariant).
- The SI Vault keyring in this architecture is a file-backed JSON state (`~/.si/vault/si-vault-keyring.json` by default), not an OS keychain primitive.

## Deployment Contract
- Fort is publicly routed through Viva.
- Public HTTPS endpoint is environment-specific and must be configured in infra plus `~/.si/fort/settings.toml` `[fort].host`.
- Runtime mounts must include:
  - `FORT_STATE_PATH`
  - `FORT_SAFE_ROOT`
  - `FORT_VAULT_KEYRING_FILE`
  - `FORT_JWT_SIGNING_KEY_FILE`
  - workload refresh-token file paths used by `fort-agent`

## Regression Policy
Treat the following as regressions:
- auth bypass or hidden bootstrap path
- Fort-owned secret persistence
- env-injected refresh/JWT signing secrets
- Sun coupling in SI Vault/Fort secret flow
