# Fort Mission Contract
See `SKILL.md` for the operator-facing CLI guide (login, get/set, admin flows).
This file is the contributor contract: mission boundaries and invariants.
## Purpose
Fort is the policy and authentication API boundary for Vault operations.
Fort stays intentionally thin:
- authenticate agent requests with bearer access tokens
- authorize by policy bindings (`repo/env/op`)
- route secret operations to Vault-backed material in `safe`
## Hard Boundaries
Fort must not:
- persist secret key/value material in Fort state
- expose unauthenticated setup/bootstrap bypass paths
- hold long-lived secret plaintext in process memory outside request scope
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
- Remote machines authenticate with GitHub fine-grained PATs, verified live against the GitHub API and mapped to agents by HMAC-SHA256 fingerprints. PAT values are never persisted, logged, or echoed.
- Refresh sessions use rotating opaque refresh tokens with reuse detection and compromise revocation.
- Only one active refresh session is allowed per agent; opening a new one revokes prior active sessions.
- `fort-breakglass-admin` must have a single active break-glass auth state; reissue revokes prior active tokens/sessions.
- Agent credential rotation invalidates prior access tokens and refresh sessions.
- Refresh tokens and JWT signing keys are file-backed secrets only (`0600`), never env-injected secret values.
- Vault ciphertext files (`safe/<repo>/.env.<env>`) must be regular files with `0600` (or stricter).
## Secret Access Discipline
- Fort may call Vault-backed code internally as its implementation detail, but agents working on the repo should not jump around Fort for real secret access.
- Direct Vault usage is limited to explicit Fort maintenance, isolated tests, or code paths whose purpose is implementing the Fort-to-Vault data plane.
- Keep `docs/GUIDING_PRINCIPLES.md` in mind for secret-related work, especially public HTTPS runtime access, file-backed tokens, scoped policy enforcement, and Fort remaining the auth boundary over Vault-backed `safe` data.
## Provisioning and Bootstrap
- There is no production seeding/bootstrap shortcut.
- Operational provisioning is explicit and authenticated:
  - create/enable agent
  - apply policy bindings
  - open refresh session for workload runtime
- Test fixtures may initialize isolated local state for integration tests only.
## Data Plane Contract
- `get/set/list/batch-get/run` operate against Vault ciphertext in `safe` (`encrypted:vault:`).
- Fort does not maintain an independent secret store.
- Per `repo/env` cryptographic material is resolved from the configured Vault keyring.
- Keyring scope entries must resolve to one canonical Vault keypair across all scopes (anti-sprawl invariant).
- The Vault keyring in this architecture is a file-backed JSON state (`~/.vault/keyring.json` by default), not an OS keychain primitive.
## Deployment Contract
- Fort is publicly routed through Viva.
- Public HTTPS endpoint is environment-specific and must be configured in infra plus `~/.fort/settings.toml` `[fort].host`.
- Runtime mounts must include:
  - `FORT_STATE_PATH`
  - `FORT_SAFE_ROOT`
  - `FORT_VAULT_KEYRING_FILE`
  - `FORT_JWT_SIGNING_KEY_FILE`
  - `FORT_GITHUB_PEPPER_FILE` (PAT fingerprint pepper, `0600`)
  - workload refresh-token file paths used by `fort-agent`
- Auth file contract (native `fort` only; there is no wrapper CLI):
  - bootstrap/admin auth file: `FORT_BOOTSTRAP_TOKEN_FILE`
  - runtime session files: managed `$FORT_SESSION_DIR/access.token` and `$FORT_SESSION_DIR/refresh.token` (default `~/.fort/session/`), refreshed in place by native `fort`
## Regression Policy
Treat the following as regressions:
- auth bypass or hidden bootstrap path
- Fort-owned secret persistence
- env-injected refresh/JWT signing secrets
## Version Source Of Truth
- The canonical hard-coded version source is the root `Cargo.toml` under `[package].version`.
- Docs, release automation, packaging metadata, and examples must reference that version instead of introducing another independently maintained repo version.
