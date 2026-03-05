#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for smoke-container.sh" >&2
  exit 1
fi

echo "[smoke] building fort binaries"
go build -o .dist/fort ./cmd/fort
go build -o .dist/fortd ./cmd/fortd

echo "[smoke] building docker image"
IMAGE_TAG="fort:smoke"
docker build -t "$IMAGE_TAG" .

NETWORK_NAME="fort-smoke-net"
CONTAINER_NAME="fort-smoke-fortd"
STATE_DIR="$(mktemp -d)"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR"
}
trap cleanup EXIT

echo "[smoke] preparing network/container"
docker network create "$NETWORK_NAME" >/dev/null
docker run -d --rm \
  --name "$CONTAINER_NAME" \
  --network "$NETWORK_NAME" \
  -e FORT_ADDR=":8088" \
  -e FORT_STATE_PATH="/var/lib/fort/state.json" \
  -e FORT_JWT_SIGNING_KEY="smoke-signing-key" \
  -e FORT_BOOTSTRAP_KEY="smoke-bootstrap-key" \
  -e FORT_TOKEN_TTL="15m" \
  -e FORT_REFRESH_SESSION_TTL="24h" \
  -v "$STATE_DIR:/var/lib/fort" \
  "$IMAGE_TAG" >/dev/null

echo "[smoke] waiting for fortd"
for _ in $(seq 1 40); do
  if docker exec "$CONTAINER_NAME" /usr/local/bin/fort --host http://127.0.0.1:8088 doctor >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
if ! docker exec "$CONTAINER_NAME" /usr/local/bin/fort --host http://127.0.0.1:8088 doctor >/dev/null 2>&1; then
  docker logs "$CONTAINER_NAME" >&2 || true
  echo "fortd did not become ready" >&2
  exit 1
fi

FORT="docker exec $CONTAINER_NAME /usr/local/bin/fort --host http://127.0.0.1:8088"

echo "[smoke] bootstrap admin + workload"
$FORT --bootstrap-key smoke-bootstrap-key agent create --id admin --type user >/dev/null
$FORT --bootstrap-key smoke-bootstrap-key agent policy set --id admin --bind '*:*:*' >/dev/null
ADMIN_TOKEN="$($FORT --json --bootstrap-key smoke-bootstrap-key auth issue --agent admin | sed -n 's/.*"token": "\(.*\)".*/\1/p' | head -n1)"
if [[ -z "${ADMIN_TOKEN}" ]]; then
  echo "failed to mint admin token" >&2
  exit 1
fi
$FORT --token "$ADMIN_TOKEN" agent create --id workload-a --type workload >/dev/null
$FORT --token "$ADMIN_TOKEN" agent policy set --id workload-a --bind 'safe:prod:get,run,list,set' >/dev/null

echo "[smoke] open refresh session"
SESSION_JSON="$($FORT --json --token "$ADMIN_TOKEN" auth session open --agent workload-a --access-ttl 5m --refresh-ttl 30m)"
REFRESH_TOKEN="$(echo "$SESSION_JSON" | sed -n 's/.*"refresh_token": "\(.*\)".*/\1/p' | head -n1)"
if [[ -z "${REFRESH_TOKEN}" ]]; then
  echo "failed to parse refresh token from session open output" >&2
  exit 1
fi

echo "[smoke] spawn container with fort-agent then validate token in-container"
WHOAMI_JSON="$(docker run --rm \
  --network "$NETWORK_NAME" \
  --entrypoint /bin/sh \
  -e FORT_HOST="http://$CONTAINER_NAME:8088" \
  -e FORT_REFRESH_TOKEN="$REFRESH_TOKEN" \
  -e FORT_TOKEN_PATH="/tmp/fort/access.token" \
  "$IMAGE_TAG" \
  -lc 'mkdir -p /tmp/fort && /usr/local/bin/fort-agent --once >/dev/null && TOKEN="$(cat /tmp/fort/access.token)" && /usr/local/bin/fort --json --host "$FORT_HOST" --token "$TOKEN" auth whoami')"
if ! echo "$WHOAMI_JSON" | grep -q '"id": "workload-a"'; then
  echo "unexpected whoami output: $WHOAMI_JSON" >&2
  exit 1
fi

echo "[smoke] success"
