# Fort Mission Contract

## Purpose
Fort is the policy and authentication API boundary for SI Vault operations.

Fort must stay a thin layer:
- authenticate agent requests using bearer tokens
- authorize requests with agent policy (repo/env/op bindings)
- forward secret operations to SI Vault-backed storage (`safe` repo `.env` files)

## Hard Boundaries
Fort must not:
- keep secret key/value material in its own state database
- expose bootstrap/admin bypass keys or unauthenticated setup paths
- store long-lived secret values in memory outside request scope

Fort state is limited to:
- agents
- policies
- token/session records
- audit events

## Security Model
- Every sensitive endpoint is bearer-token authenticated.
- Admin operations require an agent whose policy grants wildcard admin capability (`*:*:*`).
- Workload access is policy-scoped by `repo`, `env`, and operation (`get`, `set`, `list`, `batch-get`, `run`).
- Session refresh uses rotating refresh tokens only; no alternate bypass path.
- Refresh-token reuse detection is mandatory: reuse revokes the session as compromised.
- Access-token validation must enforce JWT registered claims and issuer/audience/subject consistency.
- Agent credential rotation must invalidate previous credentials and sessions.
- Refresh tokens and signing keys must be file-backed secrets, never env-injected secret values.

## Data Plane Contract
- Secret `get/set/list/batch-get/run` operations operate on SI Vault material in the `safe` repository.
- SI Vault ciphertext format (`encrypted:si-vault:`) is preserved.
- Per `repo/env` key material is sourced from the configured vault keyring file.

## Deployment Contract
- Fort is deployed as a public API service through Viva routing.
- Runtime must mount:
  - Fort state directory (`FORT_STATE_PATH`)
  - safe repo root (`FORT_SAFE_ROOT`)
  - SI Vault keyring (`FORT_VAULT_KEYRING_FILE`)
  - JWT signing key file (`FORT_JWT_SIGNING_KEY_FILE`)
  - refresh token file(s) for workload-side `fort-agent` runtime

## Change Discipline
Any change that introduces:
- bootstrap bypass auth,
- Fort-owned secret persistence,
- env-injected refresh/JWT signing secrets,
- or Sun coupling in Vault flows,
must be treated as a regression.
