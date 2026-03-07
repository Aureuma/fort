# Fort Guiding Principles

## Mission
Fort is the policy/authentication boundary for SI Vault secret operations.

Fort is not a secret database. It must remain a thin API wrapper over SI Vault-backed `safe` data.

## Core Invariants
- Fort never persists secret plaintext key/value material.
- Fort never exposes unauthenticated bootstrap or bypass paths.
- Secret operations are policy-scoped by `repo/env/op`.
- Sun is not in the SI Vault/Fort secret path.

## Authentication Model
- Workloads use short-lived JWT access tokens.
- Refresh uses rotating opaque refresh tokens.
- Refresh-token reuse is compromise and revokes session state.
- Agent credential rotation invalidates old tokens and refresh sessions.

## Secret Handling Model
- Refresh tokens and signing keys are file-backed secrets.
- Required file mode is `0600` (or stricter).
- Refresh tokens are not passed via environment variables.
- Secret scope reads fail fast when `.env.<env>` or keyring scope material is missing.

## What Was Hardened
- Documented and enforced file-only refresh-token handling.
- Added/kept integration coverage for:
  - Fort container smoke flow
  - SI↔Fort↔Vault end-to-end flow
  - manual SI Vault decrypt parity checks
- Removed/blocked architecture drift in docs toward Sun-coupled vault flow.

## Non-Goals
- Fort-owned secret persistence
- alternate auth backdoors
- shadow vault formats or private secret stores outside SI Vault
