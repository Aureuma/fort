#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo build --locked --release --bin fort --bin fortd --bin fort-agent --bin fort-seed
docker build -t fort:smoke .
ARTIFACT_ROOT="$(pwd)/.artifacts/smoke-container"
mkdir -p "${ARTIFACT_ROOT}"
STATE_DIR="$(mktemp -d "${ARTIFACT_ROOT}/state.XXXXXX")"
SAFE_DIR="$(mktemp -d "${ARTIFACT_ROOT}/safe.XXXXXX")"
trap 'docker rm -f fort-smoke >/dev/null 2>&1 || true; rm -rf "$STATE_DIR" "$SAFE_DIR"' EXIT
mkdir -p "$SAFE_DIR/safe"
ADMIN_TOKEN_PATH="$STATE_DIR/admin.token"
ADMIN_TOKEN="$(STATE_PATH="$STATE_DIR/state.json" KEYRING_PATH="$STATE_DIR/si-vault-keyring.json" SIGNING_KEY_PATH="$STATE_DIR/jwt-signing.key" cargo run --quiet --bin fort-seed)"
printf '%s' "$ADMIN_TOKEN" > "$ADMIN_TOKEN_PATH"
chmod 600 "$ADMIN_TOKEN_PATH"
docker run -d \
  --name fort-smoke \
  -e FORT_ADDR=:8088 \
  -e FORT_STATE_PATH=/var/lib/fort/state.json \
  -e FORT_JWT_SIGNING_KEY_FILE=/var/lib/fort/jwt-signing.key \
  -e FORT_SAFE_ROOT=/safe \
  -e FORT_VAULT_KEYRING_FILE=/var/lib/fort/si-vault-keyring.json \
  -v "$STATE_DIR:/var/lib/fort" \
  -v "$SAFE_DIR:/safe" \
  fort:smoke >/dev/null
for _ in $(seq 1 30); do
  if docker exec fort-smoke /usr/local/bin/fort --host http://127.0.0.1:8088 doctor >/dev/null 2>&1; then
    break
  fi
  status="$(docker inspect --format '{{.State.Status}}' fort-smoke)"
  if [[ "$status" != "running" ]]; then
    docker logs fort-smoke
    exit 1
  fi
  sleep 1
done
if ! docker exec fort-smoke /usr/local/bin/fort --host http://127.0.0.1:8088 doctor >/dev/null 2>&1; then
  docker logs fort-smoke
  echo "fort-smoke did not become healthy" >&2
  exit 1
fi
docker exec fort-smoke /usr/local/bin/fort --host http://127.0.0.1:8088 doctor
docker exec fort-smoke /usr/local/bin/fort --host http://127.0.0.1:8088 --token-file /var/lib/fort/admin.token auth whoami "$@"
