# Releasing and Changelog Guide

This document is the single source for Fort release policy and the release
checklist. It follows Semantic Versioning and keeps a human-focused changelog.
It is adapted from the SI runbook (`si/docs/RELEASING.md`) for Fort's
single-crate layout and GitHub + Homebrew-only distribution.

## Versioning Rules

- Use the SemVer shape `MAJOR.MINOR.PATCH`, but apply it operationally in
  this repo.
- Keep one hard-coded Fort version source of truth: root `Cargo.toml` under
  `[package].version`.
- Treat every other Fort version surface as derived data from that root
  version, not as an independently maintained version.
- Every commit must bump PATCH in the same commit.
- A published release bumps MINOR, resets PATCH to `0`, and uses a release
  tag of `vX.Y.0`.
- Only minor release versions are tagged and published to GitHub Releases or
  external distribution channels.
- Use the `v` prefix consistently for release tags and GitHub Releases. The
  canonical release/tag form is `vX.Y.0`; bare forms such as `1.1.0` are
  non-canonical and must not be introduced.
- Patch versions such as `vX.Y.1` remain commit-scoped working versions only.
  They are not release tags and must not have GitHub Release entries.
- There must be exactly one canonical GitHub Release per minor release tag.
  Do not leave duplicate release entries for both a bare tag and a
  `v`-prefixed tag on the same version line.
- MAJOR changes remain exceptional and must be called out explicitly when
  they happen.
- Grandfather note: tag `v1.0.8` (and its GitHub Release) predates this
  policy and is the only published patch tag. No further patch tags will be
  published.

## Changelog Format (Predefined)

Use this structure for each release entry:

```
## [vX.Y.0] - YYYY-MM-DD
### Added
- ...
### Changed
- ...
### Fixed
- ...
### Removed
- ...
### Security
- ...
```

Guidelines:

- Newest first.
- Use only the sections that apply.
- Short, user-facing bullets in past tense.
- Dates are UTC in YYYY-MM-DD.

## Release Process (Best-Practice Sequence)

This sequence follows typical maintainer workflows: verify state, prepare
release notes, update versions, tag, push, then publish a GitHub Release.

### 0) Pre-flight checks (clean repo, sync tags)

```
git status -sb
git fetch --tags origin
git switch main
git pull --ff-only
```

- Ensure CI is green on `main`.
- Ensure you can push tags and create GitHub releases.
- Ensure the working tree is clean and the branch is up to date.
- Make sure you have all remote tags locally before picking the next version.
- Inspect existing release/tag state before cutting a new release:

```
gh release list --repo Aureuma/fort
git tag -l
```

- Confirm there are no stray patch-version releases (other than the
  grandfathered `v1.0.8`), no bare-tag releases such as `1.1.0`, and no
  duplicate release entries for the same minor line.

### 1) Determine the next version + release name

- Decide the next release version `vX.Y.0`.
- Choose a short suggested name for the release title.
- Title format for GitHub Release: `vX.Y.0 - Suggested Name`.
- Do not cut release tags or release titles in bare form such as
  `1.1.0 - Suggested Name`.

### 2) Draft the changelog entry (authoritative notes)

1. Move the `Unreleased` section in `CHANGELOG.md` to a new `vX.Y.0` entry
   with today's UTC date, leaving a fresh empty `Unreleased` section.
2. Summarize user-facing changes in 2–6 bullets per section.
3. Keep language past tense and user-focused.
4. Cover the full set of patch-bump commits since the previous minor release.

### 3) Bump version strings in code

Update release version metadata:

- root `Cargo.toml` `version = "X.Y.0"`
- `Cargo.lock` follows that same version update in the same commit
  (`cargo update -p fort` must touch only the fort entry).

Do not invent or hand-maintain separate Fort versions in packaging templates
or docs. Those must derive from the root version.

### 4) Verify and commit the release prep

```
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo run --quiet --locked --bin fort-release -- self validate-version --tag vX.Y.0
cargo run --quiet --locked --bin fort-release -- installer smoke-host
cargo run --quiet --locked --bin fort-release -- self assets --out-dir .artifacts/release-preflight
cargo run --quiet --locked --bin fort-release -- self verify --version vX.Y.0 --out-dir .artifacts/release-preflight
git add CHANGELOG.md Cargo.toml Cargo.lock
git commit -m "release: vX.Y.0"
```

- Keep release prep changes in a dedicated commit.
- The release-assets preflight confirms archive packaging before publishing
  a GitHub Release.
- `fort-release self assets` reads the canonical version from root
  `Cargo.toml` when `--version` is omitted.
- Include the Homebrew smoke lane (`installer smoke-homebrew`) so the tap
  formula still installs the release binary.

### 5) Create an annotated tag for the release commit

```
git tag -a vX.Y.0 -m "vX.Y.0"
```

- Annotated tags are recommended for releases and are the best practice
  (they store metadata like tagger, date, and message).
- Do not create patch tags such as `vX.Y.1`.
- Do not create bare tags such as `X.Y.0`.

### 6) Push commits and the new tag

```
git push
git push origin vX.Y.0
```

- Push the tag explicitly to avoid conflicts with existing tags.
- `gh release create` can auto-create a tag if it doesn't exist; using
  `--verify-tag` ensures you only release a tag you already created
  and pushed.
- If you let `gh release create` auto-create a tag, fetch tags afterward
  to sync locally: `git fetch --tags origin`.
- If you do let it auto-create a tag, use `--target <branch|sha>` to pin
  the release to the desired commit.

### 7) Prepare release notes and publish release

If you need a quick summary of commits since the last release:

```
git log --oneline "$(git describe --tags --abbrev=0)..HEAD"
```

GitHub Releases should include a clear, hand-written release note (not just
a verbatim copy of `CHANGELOG.md`). Use the changelog and commit history as
inputs, then write a concise, user-facing summary of what changed since the
last published GitHub Release. Because only minor releases are tagged, this
range is the full set of patch-bump commits that must be reflected in the
release notes. The release entry itself must target the canonical `vX.Y.0`
tag. Do not publish releases against patch tags or bare tags.

Option A: Use the changelog entry as the release body.

1. Extract the new `vX.Y.0` section into `release-notes.md` (manual or script).
2. Create the release with a title and notes file:

```
gh release create vX.Y.0 \
  --repo Aureuma/fort \
  --title "vX.Y.0 - Suggested Name" \
  --notes-file release-notes.md \
  --verify-tag
```

Option B: Use the annotated tag message as the release body.

```
gh release create vX.Y.0 \
  --repo Aureuma/fort \
  --title "vX.Y.0 - Suggested Name" \
  --notes-from-tag \
  --verify-tag
```

Notes:

- `--notes-from-tag` uses the annotated tag message when present; otherwise
  it falls back to the commit message.

Option C: Use GitHub auto-generated release notes and prepend highlights.

```
gh release create vX.Y.0 \
  --repo Aureuma/fort \
  --title "vX.Y.0 - Suggested Name" \
  --generate-notes \
  --notes-start-tag vA.B.0 \
  --notes "Highlights:\n- ...\n- ..." \
  --verify-tag
```

Notes:

- `--verify-tag` aborts if the tag doesn't already exist on the remote.
- `--generate-notes` uses GitHub's Release Notes API and can be combined
  with `--notes`.
- Add `--notes-start-tag vA.B.0` to define the start tag for generated
  notes when needed.
- Add `--fail-on-no-commits` if you want to prevent duplicate releases
  when there are no new commits.

### 8) Verify the published release

```
gh release view vX.Y.0 --repo Aureuma/fort --web
```

- Confirm title, notes, and tag target are correct.
- Release artifacts carry build-provenance attestations; verify with
  `gh attestation verify <asset> --repo Aureuma/fort` after download.
- Confirm the release `tag_name` is exactly `vX.Y.0`.
- Confirm there is no duplicate bare-tag release such as `X.Y.0`.
- Confirm there is no GitHub Release entry for any patch tag in that
  release line (other than the grandfathered `v1.0.8`).

### 8.1) Canonicalize accidental duplicate release entries

If you discover a non-canonical release entry after publication:

- Keep the canonical `vX.Y.0` tag and GitHub Release.
- Remove patch-version GitHub Releases; patch versions are not published
  release lines in Fort (except the grandfathered `v1.0.8`).
- Remove bare-tag GitHub Releases such as `1.1.0` when a canonical
  `v1.1.0` release already exists.
- If both local and remote git tags exist for a non-canonical tag, delete
  both:

```
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
```

- Re-fetch tags after cleanup so local state matches the remote:

```
git fetch --tags --prune origin
```

### 9) Verify automated release assets

When a GitHub Release is published, workflow
`.github/workflows/release.yml` builds and uploads release archives
automatically, then:

- updates the Homebrew tap formula in `Aureuma/homebrew-fort` (when
  `HOMEBREW_TAP_PUSH_TOKEN` is configured, with fallback to
  `GH_PAT_AUREUMA` when that token has tap push access)
- verifies release assets + Homebrew sync in a final gate job
- runs a macOS Homebrew smoke install lane through
  `fort-release installer smoke-homebrew`

Supported targets:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`

Expected assets:

- `fort_<version>_linux_amd64.tar.gz`
- `fort_<version>_linux_arm64.tar.gz`
- `fort_<version>_darwin_amd64.tar.gz`
- `fort_<version>_darwin_arm64.tar.gz`
- `checksums.txt`

Verification commands:

```
gh run list --workflow "Release Assets" --repo Aureuma/fort --limit 1
gh release view vX.Y.0 --repo Aureuma/fort --json assets --jq '.assets[].name'
```

Verify Homebrew tap formula version:

```
curl -fsSL https://raw.githubusercontent.com/Aureuma/homebrew-fort/main/Formula/fort.rb | grep -n 'version "'
```

Notes:

- The workflow validates that the `Cargo.toml` version matches the
  release tag.
- Release assets are built by explicit GitHub Actions target jobs for
  Linux AMD64, Linux ARM64, macOS AMD64, and macOS ARM64.
- `fort-release self verify` checks checksums, archive contents, and
  binary format before upload.
- A failed workflow means release notes/tag were published, but binary
  assets were not fully attached.
- Use `cargo run --quiet --locked --bin fort-release -- homebrew
  render-tap-formula --version vX.Y.0 --checksums <file|url>
  --tap-dir <dir>` to refresh tap formula metadata; it defaults to the
  canonical Fort version from root `Cargo.toml` when `--version` is
  omitted.

## Tagging Rules

- Use annotated tags only for minor releases:
  `git tag -a vX.Y.0 -m "vX.Y.0" <commit>`.
- Tags should point at the release commit that includes the changelog update.
- Push tags explicitly: `git push origin vX.Y.0`.
- Tag names are canonical only in `vX.Y.0` form.
- Do not create bare release tags such as `1.1.0`.
- Do not create or keep patch-only release tags as part of the published
  release surface (except the grandfathered `v1.0.8`).

## Release Notes Style

- Lead with 2–4 key changes.
- Balance Added/Changed/Fixed where possible.
- Keep tone concise and user-focused.
