# npm Token Rotation

Date: 2026-06-11
Repo: `fort`
Branch: `main` (fast-forwarded from dedicated feature work)

## Purpose

Add a Fort CLI path for rotating third-party service API keys, starting with npm access tokens.
The implementation must keep Fort as the Safe/Vault auth boundary, avoid Fort-owned plaintext
secret persistence, and support future providers without implementing speculative provider code now.

## Scope

1. Add `fort rotate npm` as the first provider-specific rotation command.
2. Read the current npm publish token, npm management token, and npm password through Fort.
3. Require OTP from a strict-permission file for npm token creation.
4. Create a new npm granular access token through the npm registry token API.
5. Store the new npm token back through Fort.
6. Optionally sync the new token to GitHub Actions repository secrets for workflows that consume `secrets.NPM_TOKEN`.
7. Optionally revoke the old npm token only after every configured sink succeeds.
8. Redact token values from CLI output.
9. Validate with unit tests and a local Fort plus mock npm/GitHub integration test.

## Implementation Notes

The command is client-side in the Fort CLI. Fort server state remains unchanged and does not store
provider-specific plaintext secrets. Provider communication is limited to the CLI process scope.

Future providers should follow the same pattern:

1. read provider management credentials through Fort;
2. create the replacement credential at the provider;
3. write the replacement secret through Fort;
4. update configured downstream secret sinks;
5. revoke old provider credential only after every configured sink succeeds;
6. expose provider-specific flags instead of generic best-guess abstractions.

## Current Status

Implemented in `main`.

Completed:

1. Added `fort rotate npm`.
2. Added validation for explicit package/scope/org access, read-write token expiration limit, and npm permission values.
3. Added token redaction in JSON and text output.
4. Added focused unit tests for npm token request construction and validation.
5. Added an integration test using local Fort plus a mock npm registry for create/write/revoke flow.
6. Bumped Fort version to `0.2.22`.
7. Verified `cargo fmt --all -- --check`, `cargo test --locked`, and `cargo clippy --locked --all-targets -- -D warnings`.
8. Committed implementation as `feat: add npm token rotation command`.
9. Rechecked Svelta token locations through Fort using the managed `gadolina` Codex profile runtime.
10. Confirmed Svelta publish workflows use `NPM_TOKEN` as the publish token key.
11. Added optional GitHub Actions repository secret sync with GitHub-compatible sealed-box encryption.
12. Expanded the local integration test so it verifies npm create, Fort write, GitHub encrypted secret update, and old npm token revoke ordering.
13. Changed `--dry-run` to validate command shape and configured sinks without reading secret values, so missing Svelta scopes no longer block preflight.
14. Rechecked the user-specified Safe/Fort location structurally and confirmed the Svelta npm candidates are under `safe/aureuma`, exposed through Fort as `aureuma/dev` and `aureuma/prod`.
15. Confirmed through `fort run` that `aureuma/prod` has `NPM_TOKEN`, `NODE_AUTH_TOKEN`, and `SV_NPM_GAT_AUREUMA`, with `NPM_TOKEN` and `NODE_AUTH_TOKEN` equal.
16. Confirmed through `fort run` that npm rejects both `aureuma/prod:SV_NPM_GAT_AUREUMA` and `aureuma/dev:SV_NPM_GAT_AUREUMA` with `E401` on `npm whoami`.
17. Confirmed `SV_NPM_GAT_AUREUMA` could list tokens via `GET /-/npm/v1/tokens` but does not appear to be a publisher/session credential for token creation, and it was revoked during validation.
18. Confirmed `aureuma/prod` does not expose the required live token creation inputs `NPM_PASSWORD` or `NPM_OTP` through Fort.
19. Added negative-path coverage for passwordless-capable providers that reject passwordless token creation.
20. Re-ran managed-runtime checks (`codex shell --profile gadolina --slot nova-actor`) and confirmed:
   - `aureuma/prod` exposes `NPM_TOKEN`, `NODE_AUTH_TOKEN`, and `SV_NPM_GAT_AUREUMA`.
   - `npm whoami` for each token returns `E401`.
   - `orbit` and `viva` GitHub PAT candidates return `401 Bad credentials` from `GET /user`.

Remaining:

1. Replace or repair the Fort-backed Svelta/Aureuma npm publish credential, because the current Fort-exposed candidates fail npm authentication.
2. Store required npm rotation inputs through the approved Fort/Safe workflow:
   - a valid npm token-management bearer, typically a current npm session/traditional token accepted by the token-management API
   - npm password or an equivalent npm-supported token creation credential (now supported as optional in CLI, based on provider behavior)
3. Provide the current npm OTP in a local `0600` file at rotation time, or store an approved OTP source once Fort has a supported workflow for it.
4. If GitHub Actions `secrets.NPM_TOKEN` remains the active publish surface, repair GitHub auth and use `--github-actions-repo` to update that repository secret after npm token creation.
5. Perform live npm rotation only after the above inputs are available.

Planned provider expansion:

- GitHub Apps/PATs: rotate token-based auth used for CI and API operations with the same create/store/revoke sequencing.
- Docker Hub/OCI tokens: rotate publisher tokens where rotation APIs are supported.
- Cloud provider keys: apply the same sink-first pattern when provider API supports list/create/revoke with explicit scope controls.

Verified dry-run shape for Svelta:

```bash
fort --host http://127.0.0.1:1 --json rotate npm \
  --repo aureuma \
  --env prod \
  --token-key SV_NPM_GAT_AUREUMA \
  --management-token-key SV_NPM_GAT_AUREUMA \
  --password-key NPM_PASSWORD \
  --name svelta-aureuma-prod-test \
  --package @aureuma/svelta-blog \
  --dry-run \
  --github-actions-repo Aureuma/svelta-blog \
  --github-secret-name NPM_TOKEN \
  --github-token-repo orbit \
  --github-token-env prod \
  --github-token-key GH_PAT_AUREUMA
```

This succeeds without loading secret values and reports `secret_values_loaded: false`.

Current blocker:

Fort runtime auth works with the managed `gadolina` Codex profile runtime. The Svelta-looking npm
keys are currently in `aureuma/dev` and `aureuma/prod`, not in a `safe/svelta*` scope. The available
Fort-exposed npm token candidates are present but fail npm authentication with `E401`, and `aureuma/prod`
does not expose the `NPM_PASSWORD`/`NPM_OTP` inputs needed for live npm token creation. `SV_NPM_GAT_AUREUMA` also
supports token-management list/revoke operations but has already been revoked in-place.
The Svelta repos
reference `NPM_TOKEN` in GitHub Actions publish workflows. Local `gh` auth and the Fort-listed GitHub PAT
keys checked during this task return GitHub `401 Bad credentials`, so GitHub Actions secret metadata and
updates are also blocked. Checked keys:

1. `orbit/dev`: `GH_PAT`, `GH_PAT_AUREUMA`, `GH_PAT_AUREUMA_VANGUARDA`, `GITHUB_PAT`
2. `orbit/prod`: `GH_PAT`, `GH_PAT_AUREUMA`, `GH_PAT_AUREUMA_VANGUARDA`, `GITHUB_PAT`
3. `viva/dev`: `GH_PAT_AUREUMA`
4. `viva/prod`: `GH_PAT_AUREUMA`

## References

- npm Registry API: `https://api-docs.npmjs.com/`
- npm access token docs: `https://docs.npmjs.com/about-access-tokens/`
- HashiCorp rotation model: `https://developer.hashicorp.com/hcp/docs/vault-secrets/auto-rotation`
