#!/usr/bin/env bash
# Local-only gates for Fort (zero GitHub Actions).
#
# Replaces .github/workflows/{ci,install-smoke,release}.yml. Every lane runs
# on the maintainer's machine before push; nothing runs in CI.
#
# Usage: scripts/local-gates.sh [check|test|smoke|release|all] (default: all)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

lane="${1:-all}"

run_check() {
  ./scripts/build-guard.sh cargo fmt --all -- --check
  ./scripts/build-guard.sh cargo clippy --locked --all-targets --jobs 2 -- -D warnings
  ./scripts/build-guard.sh cargo check --locked --all-targets --jobs 2
}

run_test() {
  ./scripts/build-guard.sh cargo test --locked --jobs 2
}

run_smoke() {
  ./scripts/build-guard.sh cargo run --quiet --locked --jobs 2 --bin fort-release -- installer smoke-host
  local version out_dir fake_dir
  version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
  out_dir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${out_dir}'" EXIT
  ./scripts/build-guard.sh cargo run --quiet --locked --jobs 2 --bin fort-release -- self assets --out-dir "${out_dir}"
  fake_dir="$(mktemp -d)"
  for target in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
    os="${target%%-*}"
    arch="${target##*-}"
    cp "${out_dir}/fort_${version}_linux_amd64.tar.gz" "${fake_dir}/fort_${version}_${os}_${arch}.tar.gz"
  done
  (cd "${fake_dir}" && sha256sum fort_*.tar.gz > checksums.txt)
  ./scripts/build-guard.sh cargo run --quiet --locked --jobs 2 --bin fort-release -- installer smoke-homebrew \
    --version "${version}" \
    --checksums "${fake_dir}/checksums.txt"
  rm -rf "${fake_dir}" "${out_dir}"
  trap - EXIT
}

run_release() {
  local version out_dir
  version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
  out_dir=".artifacts/local-release"
  rm -rf "${out_dir}"
  ./scripts/build-guard.sh cargo run --quiet --locked --jobs 2 --bin fort-release -- self assets --out-dir "${out_dir}"
  ./scripts/build-guard.sh cargo run --quiet --locked --jobs 2 --bin fort-release -- self verify \
    --version "${version}" --out-dir "${out_dir}"
  echo "local release assets verified in ${out_dir}"
}

case "${lane}" in
  check) run_check ;;
  test) run_test ;;
  smoke) run_smoke ;;
  release) run_release ;;
  all) run_check; run_test; run_smoke; run_release ;;
  *) echo "usage: scripts/local-gates.sh [check|test|smoke|release|all]" >&2; exit 64 ;;
esac
