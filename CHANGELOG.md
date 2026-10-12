# Changelog

All notable changes to this project will be documented in this file.

## Changelog Guidelines

- Follow Semantic Versioning (SemVer) and keep entries newest-first.
- Use these sections when applicable: Added, Changed, Fixed, Removed, Security.
- Write short, user-facing bullets in past tense.
- Dates use UTC in YYYY-MM-DD.
- Every commit bumps PATCH in the same commit; only `vX.Y.0` minor tags are
  published as GitHub Releases (see `docs/RELEASING.md`).

## [Unreleased]

### Added

- Added README install instructions (Homebrew tap plus release archives)
  and pointers to the changelog and release process.
- Added weekly Dependabot updates for Cargo and GitHub Actions.
- Added the patch-per-commit versioning and release rules to the
  contributor contract (`AGENTS.md`).

### Fixed

- Fixed a stale hard-coded checkout path in the README local-run example.

## [v1.1.0] - 2026-10-12

### Added

- Added an e2e regression test proving the old npm token is left alone when a
  GitHub Actions sink fails during `fort rotate npm`.
- Added the npm token rotation operator runbook to `SKILL.md`.
- Added human-readable `--help` text to every `fort`, `fortd`,
  `fort-agent`, `fort-breakglass`, and `fort-seed` command and flag, plus a
  help-coverage regression test.
- Added the dev-only `fort-release` Rust helper: release version gate,
  local asset build/verify, host and Homebrew smokes, and tap formula
  rendering (byte-identical to the shell renderer it replaces).
- Added an install-smoke CI workflow (format, clippy, tests, host smokes on
  Linux and macOS, Homebrew render smoke) and a `fmt --check` gate in CI.

### Changed

- Changed the release pipeline to render the tap formula with
  `fort-release` (with tap-token fallback) and to verify with a real
  macOS tap install after publish.

### Fixed

- Fixed the managed-refresh-rotation e2e test to isolate `FORT_SESSION_DIR`
  and `FORT_*` env so it no longer depends on the developer's live
  access-token expiry.
- Fixed `fort-release` asset, verify, and smoke version flags to tolerate a
  `v` prefix.

## [v1.0.8] - 2026-10-11

Reconstructed from git history up to tag `v1.0.8`; earlier per-release notes
were not kept, so only this consolidated entry exists for the 1.0 line.

### Added

- Added GitHub fine-grained PAT login with peppered HMAC fingerprints,
  interactive prompt, and stored-PAT reuse (`auth github login`).
- Added native managed-session refresh with single active session per agent,
  rotating opaque refresh tokens, and reuse-compromise revocation.
- Added audited secret scope provisioning (`scope ensure`) and
  policy-scoped secret operations (`get`, `set`, `list`, `batch-get`, `run`).
- Added `fort rotate npm` for granular npm token rotation with Fort-backed
  inputs, optional GitHub Actions secret sync, sink-first revoke ordering,
  and redacted output.
- Added `fort-agent` container refresh loop and single-image deploy
  artifacts with a container smoke flow.
- Added the operator `SKILL.md` guide and the contributor contract
  (`AGENTS.md`, `docs/GUIDING_PRINCIPLES.md`).

### Changed

- Changed the secret data plane to the standalone `vault` format
  (`encrypted:vault:`), rejecting legacy ciphertext labels instead of
  silently reading them.
- Changed refresh tokens and JWT signing keys to file-backed (`0600`) only;
  environment-injected secret values are rejected.
- Hardened JWT claim validation (`iss`/`sub`/`aud`/`jti`/`iat`/`nbf`/`exp`)
  and tied tokens to agent credential versions with rotation revocation.
- Hardened SIGPIPE behavior across CLI output paths and release archive
  verification.

### Fixed

- Fixed the plaintext fallthrough so unrecognized `encrypted:*` values are
  hard errors instead of silently served ciphertext.
- Fixed the release archive verification to avoid SIGPIPE failures.
- Fixed the container build guard to the fort namespace with pepper wired
  into the smoke test.
