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

## [v1.7.0] - 2026-11-25

### Added

- Extended the Gemini issuer to per-project minter bindings: extra
  `[gemini_minters."<gcp-project>"]` bindings (or `FORT_GEMINI_MINTERS`
  JSON) map each GCP project to its own minter safe scope, and every
  `fort keys <issue|rotate|revoke|list|validate> gemini` command accepts
  `--project`. Requests resolve the project from the explicit flag,
  otherwise from `gcp-<store-repo>` when bound, otherwise the existing
  single-project default, which keeps working unchanged.

### Changed

- Pointed the container Gemini issuer configuration at the terrabillion
  estate (`gcp-terrabillion`), so the baked `fortd.toml` carries the live
  minter scope holding the existing API keys.

### Fixed

- Fixed host resolution ignoring `[fort].host` in `settings.toml`: the
  settings file is now parsed with TOML document semantics, so
  `fort doctor` (and every command) resolves its host with no
  `--host`/`FORT_HOST` override (#38).

## [v1.6.1] - 2026-11-24

### Fixed

- Fixed Gemini `list_keys` silently dropping keys beyond the first page;
  it now follows `nextPageToken` (`pageSize=100`) until exhausted.

## [v1.6.0] - 2026-11-24

### Added

- Added Gemini (Google AI Studio) API key lifecycle to the unified
  `fort keys` family: `issue`, `list`, `rotate`, `revoke`, and
  `validate` for the `gemini` provider, backed by a vault-stored
  minter credential with `FORT_GEMINI_*` env and `fortd.toml` configuration.
- Returned Gemini key material once at issuance with audit logging;
  the 7-day rotation guidance is advisory and not platform-enforced.
- Rejected caller-supplied TTLs on Gemini issuance and surfaced
  unconfigured-service (503) plus orphan-key remediation errors from
  the new `POST /v1/gemini/keys/*` server endpoints.
- Added `--version`/`-V` flags to the `fort` and `fortd` binaries and
  `version` subcommands to `fortd` and `fort-release` (#25, #27).

### Removed

- Removed all GitHub Actions workflows (CI, install smoke, release assets);
  `scripts/local-gates.sh` (plus `make gates`) is now the enforced local
  gate for checks, tests, smokes, and release-asset builds.

### Fixed

- Fixed `fort-release` host-smoke and asset builds preferring a stale
  `target/` binary over the configured `.artifacts/cargo-target` output.
- Printed the full error chain from top-level CLI mains instead of
  only the outermost message (#26).
- Used repo-relative viva build paths in deploy tooling (#24).

### Changed

- Renamed the container R2 issuer key reference from
  `VIVA_CLOUDFLARE_R2_ISSUER_TOKEN` to
  `TOFU_CLOUDFLARE_R2_ISSUER_TOKEN` to match the Fort rename.
- Documented that the `CF_R2_TOKEN_MANAGER` bootstrap credential must
  stay a user token (Cloudflare forbids token-management groups on
  account tokens) and can only be changed from the dashboard.
- Bumped `jsonwebtoken` from 10.4.0 to 12.0.0 and `toml` from 0.8.23
  to 1.2.1+spec-1.1.0 as prudent dependency hygiene; no API or
  behavior impact expected (#22, #23).

## [v1.5.0] - 2026-11-18

### Added

- Added the unified `fort keys <verb> <provider>` command family for
  provider credential lifecycle: `issue`, `create`, `rotate`,
  `revoke`, `list`, and `audit`, starting with the `r2` provider
  (`npm` rotation moved under `keys rotate` too). The old `fort r2`
  and `fort rotate` spellings remain as deprecated aliases.

## [v1.4.0] - 2026-11-16

### Added

- Added Fort-managed R2 temporary-credential issuance (`fort r2 issue`)
  backed by a long-lived issuer token in the safe. Callers get
  short-lived, bucket-scoped S3 credentials (7-day TTL cap) without ever
  seeing the issuer token.

### Changed

- Raised the default refresh session lifetime from 30 days to 90 days.

## [1.3.0] - 2026-11-02

## [v1.2.0] - 2026-10-19

### Added

- Added README install instructions (Homebrew tap plus release archives)
  and pointers to the changelog and release process.
- Added weekly Dependabot updates for Cargo and GitHub Actions.
- Added the patch-per-commit versioning and release rules to the
  contributor contract (`AGENTS.md`).

### Fixed

- Fixed a stale hard-coded checkout path in the README local-run example.
- Fixed the Homebrew formula installing only `fort`: brew installs now ship
  `fort`, `fortd`, and `fort-agent` from the release archives, and release
  verification asserts all three binaries.
- Fixed `auth github login`, `auth github logout`, and `auth session
  refresh` failing with `refresh managed session` when the managed session
  on disk was already dead; these commands no longer require a live session
  first.
- Fixed concurrent `fort` processes revoking the managed session: refreshes
  are now serialized with a session lockfile, so simultaneous refreshes no
  longer look like token-reuse compromise to the server.

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
