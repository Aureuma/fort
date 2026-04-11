# Fort Guiding Principles

## Mission
Fort is the policy/authentication boundary for SI Vault secret operations.

Fort is not a secret database. It must remain a thin API wrapper over SI Vault-backed `safe` data.

## Core Invariants
- Fort never persists secret plaintext key/value material.
- Fort never exposes unauthenticated bootstrap or bypass paths.
- Secret operations are policy-scoped by `repo/env/op`.

## Authentication Model
- Workloads use short-lived JWT access tokens.
- Refresh uses rotating opaque refresh tokens.
- Only one active refresh session is allowed per agent at a time.
- Refresh-token reuse is compromise and revokes session state.
- `fort-breakglass-admin` token re-issuance revokes prior active break-glass tokens and refresh sessions.
- Agent credential rotation invalidates old tokens and refresh sessions.

## Secret Handling Model
- Refresh tokens and signing keys are file-backed secrets.
- Required file mode is `0600` (or stricter).
- SI Vault ciphertext files (`safe/<repo>/.env.<env>`) are required to be regular files with `0600` (or stricter).
- SI Vault keyring entries must converge on one canonical keypair across all `repo/env` scopes.
- SI Vault keyring material is file-backed JSON state (default `~/.si/vault/si-vault-keyring.json`), not OS keychain storage.
- Refresh tokens are not passed via environment variables.
- Secret scope reads fail fast when `.env.<env>` or keyring scope material is missing.

## What Was Hardened
- Documented and enforced file-only refresh-token handling.
- Added/kept integration coverage for:
  - Fort container smoke flow
  - SI↔Fort↔Vault end-to-end flow
  - manual SI Vault decrypt parity checks

## Non-Goals
- Fort-owned secret persistence
- alternate auth backdoors
- shadow vault formats or private secret stores outside SI Vault

## Unified Contract

### Scope Boundaries
- SI Vault owns local `.env` encryption/decryption format and key material lifecycle.
- Fort owns remote authentication/authorization and policy enforcement.

### Secret Data Plane
- Source of truth for secrets: `safe/<repo>/.env.<env>`.
- Ciphertext format: `encrypted:si-vault:...` (legacy `encrypted:` accepted for compatibility).
- Fort `get/set/list/batch-get/run` resolves directly against SI Vault-backed `safe` files.

### Key Material Model
- SI Vault key material registry: `~/.si/vault/si-vault-keyring.json` (or `SI_VAULT_KEYRING_FILE`).
- This keyring is file-backed JSON state, not OS keychain storage.
- One canonical keypair is enforced across all `repo/env` keyring scopes.
- `backup_private_keys` sprawl is disallowed.

### Runtime Access Model
- Runtime workers access secrets through `si fort ...`.
- Direct local `si vault` secret commands are blocked in SI runtime workers.
- Host/admin operations may use `si vault` for local maintenance workflows.
- SI wrapper bootstrap/admin auth resolves from `FORT_BOOTSTRAP_TOKEN_FILE`.
- SI runtime sessions resolve from file paths `FORT_TOKEN_PATH` and `FORT_REFRESH_TOKEN_PATH`.

### Token & Session Security
- Access tokens are short-lived JWT bearer tokens.
- Refresh sessions use rotating opaque refresh tokens with reuse detection.
- Normal operator refresh sessions are bounded and default to 30 days unless explicitly shortened for a workload.
- Single active refresh session per agent.
- Refresh and signing secrets are file-backed only (`0600`), not env-injected secret values.
- For `si fort` wrapper calls, native `fort` flags should be passed after `--`.

### File/Permission Invariants
- `safe/<repo>/.env.<env>`: regular file, `0600` or stricter.
- `~/.si/vault/si-vault-keyring.json`: `0600`.
- `~/.si/vault/keys/age.key` (if file backend): `0600`.
- Fort refresh token and signing key files: `0600`.

### Deployment Invariants
- Hosted Fort endpoint is configured in `~/.si/fort/settings.toml` (`[fort].host` / `runtime_host`).
- Production and operator-facing Fort access must resolve through the public HTTPS endpoint, for example `https://fort.aureuma.ai`.
- Loopback addresses, local container IPs, and ad-hoc private hostnames are not valid steady-state runtime endpoints for Fort-backed workflows.
- Localhost and private-address exposure are permitted only for development, isolated integration tests, or break/fix debugging that is explicitly temporary.
- Fort deploy path is via Viva manifests and public routing, not ad-hoc local-only exposure.

### Regression Definition
- auth bypass or hidden bootstrap path
- Fort-owned secret persistence
- env-injected refresh/JWT signing secrets
- SI Vault keypair sprawl across scopes
