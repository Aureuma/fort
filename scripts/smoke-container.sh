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
SAFE_DIR="$(mktemp -d)"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR"
  rm -rf "$SAFE_DIR"
}
trap cleanup EXIT

echo "[smoke] seeding local control-plane state and vault keyring"
SEEDER_FILE="$ROOT_DIR/smoke_seed_tmp.go"
cat > "$SEEDER_FILE" <<'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fort/internal/auth"
	"fort/internal/model"
	"fort/internal/store"
	ecies "github.com/ecies/go/v2"
)

func main() {
	stateDir := os.Getenv("STATE_DIR")
	repo := "safe"
	env := "prod"
	signingKey := "smoke-signing-key"
	statePath := filepath.Join(stateDir, "state.json")
	keyringPath := filepath.Join(stateDir, "si-vault-keyring.json")

	st, err := store.New(statePath)
	if err != nil {
		panic(err)
	}
	now := time.Now().UTC()
	admin, err := st.CreateAgent("admin", model.AgentTypeUser, model.AgentStatusActive, now)
	if err != nil {
		panic(err)
	}
	if _, err := st.SetPolicy(admin.ID, []model.Binding{{Repo: "*", Env: "*", Ops: []model.Operation{model.OpAny}}}, now); err != nil {
		panic(err)
	}
	manager := &auth.Manager{SigningKey: []byte(signingKey), Store: st}
	token, _, err := manager.Issue(admin, 24*time.Hour, "fort-api")
	if err != nil {
		panic(err)
	}
	key, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}
	doc := map[string]any{
		"entries": map[string]any{
			repo + "/" + env: map[string]any{
				"repo":        repo,
				"env":         env,
				"public_key":  key.PublicKey.Hex(true),
				"private_key": key.Hex(),
			},
		},
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(keyringPath, raw, 0o600); err != nil {
		panic(err)
	}
	fmt.Print(token)
}
EOF
ADMIN_TOKEN="$(STATE_DIR="$STATE_DIR" go run "$SEEDER_FILE")"
rm -f "$SEEDER_FILE"
if [[ -z "${ADMIN_TOKEN}" ]]; then
  echo "failed to generate admin token" >&2
  exit 1
fi

echo "[smoke] preparing network/container"
docker network create "$NETWORK_NAME" >/dev/null
docker run -d --rm \
  --name "$CONTAINER_NAME" \
  --network "$NETWORK_NAME" \
  -e FORT_ADDR=":8088" \
  -e FORT_STATE_PATH="/var/lib/fort/state.json" \
  -e FORT_JWT_SIGNING_KEY="smoke-signing-key" \
  -e FORT_SAFE_ROOT="/safe" \
  -e FORT_VAULT_KEYRING_FILE="/var/lib/fort/si-vault-keyring.json" \
  -e FORT_TOKEN_TTL="15m" \
  -e FORT_REFRESH_SESSION_TTL="24h" \
  -v "$STATE_DIR:/var/lib/fort" \
  -v "$SAFE_DIR:/safe" \
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

echo "[smoke] create workload + policy"
$FORT --token "$ADMIN_TOKEN" agent create --id workload-a --type workload >/dev/null
$FORT --token "$ADMIN_TOKEN" agent policy set --id workload-a --bind 'safe:prod:get,run,list,set' >/dev/null

echo "[smoke] open refresh session"
REFRESH_FILE_IN_FORT="/var/lib/fort/workload-a.refresh.token"
$FORT --token "$ADMIN_TOKEN" auth session open --agent workload-a --access-ttl 5m --refresh-ttl 30m --refresh-token-out "$REFRESH_FILE_IN_FORT" >/dev/null
REFRESH_FILE_ON_HOST="$STATE_DIR/workload-a.refresh.token"
if [[ ! -s "$REFRESH_FILE_ON_HOST" ]]; then
  echo "failed to write refresh token file" >&2
  exit 1
fi

echo "[smoke] spawn container with fort-agent then validate token in-container"
WHOAMI_JSON="$(docker run --rm \
  --network "$NETWORK_NAME" \
  --entrypoint /bin/sh \
  -v "$REFRESH_FILE_ON_HOST:/run/secrets/fort.refresh:ro" \
  -e FORT_HOST="http://$CONTAINER_NAME:8088" \
  "$IMAGE_TAG" \
  -lc 'mkdir -p /tmp/fort && /usr/local/bin/fort-agent --once --refresh-token-file /run/secrets/fort.refresh --token-path /tmp/fort/access.token >/dev/null && TOKEN="$(cat /tmp/fort/access.token)" && /usr/local/bin/fort --json --host "$FORT_HOST" --token "$TOKEN" auth whoami')"
if ! echo "$WHOAMI_JSON" | grep -q '"id": "workload-a"'; then
  echo "unexpected whoami output: $WHOAMI_JSON" >&2
  exit 1
fi

echo "[smoke] success"
