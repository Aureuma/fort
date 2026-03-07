#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORT_REPO="$ROOT_DIR"
SI_REPO="${SI_REPO:-$ROOT_DIR/../si}"

if [[ ! -d "$SI_REPO/tools/si" ]]; then
  echo "si repo not found at $SI_REPO (set SI_REPO to override)" >&2
  exit 1
fi

TMP_ROOT="$(mktemp -d)"
STATE_DIR="$TMP_ROOT/state"
SAFE_ROOT="$TMP_ROOT/safe"
mkdir -p "$STATE_DIR" "$SAFE_ROOT/safe"

ENV_FILE="$SAFE_ROOT/safe/.env.dev"
KEYRING_FILE="$STATE_DIR/si-vault-keyring.json"
SIGNING_KEY_FILE="$STATE_DIR/jwt-signing.key"
STATE_FILE="$STATE_DIR/state.json"
FORT_ADDR="127.0.0.1:18088"
FORT_HOST="http://$FORT_ADDR"
FORT_LOG="$STATE_DIR/fortd.log"
SEED_FILE="$FORT_REPO/tmp_e2e_seed.go"
MANUAL_FILE="$FORT_REPO/tmp_e2e_manual_decrypt.go"
FORTD_PID=""

cleanup() {
  if [[ -n "$FORTD_PID" ]]; then
    kill "$FORTD_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$SEED_FILE" "$MANUAL_FILE"
  if [[ "${E2E_KEEP_TMP:-0}" != "1" ]]; then
    rm -rf "$TMP_ROOT"
  fi
}
trap cleanup EXIT

echo "[e2e] temp root: $TMP_ROOT"
echo "[e2e] building fort binaries"
(
  cd "$FORT_REPO"
  go build -o "$STATE_DIR/fort" ./cmd/fort
  go build -o "$STATE_DIR/fortd" ./cmd/fortd
  go build -o "$STATE_DIR/fort-agent" ./cmd/fort-agent
)

echo "[e2e] seeding fort admin state + SI vault keyring"
cat > "$SEED_FILE" <<'GOEOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"fort/internal/auth"
	"fort/internal/model"
	"fort/internal/store"
	ecies "github.com/ecies/go/v2"
)

func main() {
	statePath := os.Getenv("STATE_PATH")
	keyringPath := os.Getenv("KEYRING_PATH")
	signingKeyPath := os.Getenv("SIGNING_KEY_PATH")
	signingKey := "e2e-signing-key-012345678901234567890123"
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
	mgr := &auth.Manager{SigningKey: []byte(signingKey), Store: st}
	token, _, err := mgr.Issue(admin, 24*time.Hour, "fort-api")
	if err != nil {
		panic(err)
	}
	key, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}
	entry := map[string]any{
		"repo":       "safe",
		"env":        "dev",
		"public_key": key.PublicKey.Hex(true),
		"private_key": key.Hex(),
	}
	doc := map[string]any{"entries": map[string]any{"safe/dev": entry}}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(keyringPath, raw, 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(signingKeyPath, []byte(signingKey), 0o600); err != nil {
		panic(err)
	}
	fmt.Print(token)
}
GOEOF

ADMIN_TOKEN="$(
  cd "$FORT_REPO"
  STATE_PATH="$STATE_FILE" KEYRING_PATH="$KEYRING_FILE" SIGNING_KEY_PATH="$SIGNING_KEY_FILE" go run "$SEED_FILE"
)"

echo "[e2e] starting fortd"
FORT_ADDR="$FORT_ADDR" \
FORT_STATE_PATH="$STATE_FILE" \
FORT_JWT_SIGNING_KEY_FILE="$SIGNING_KEY_FILE" \
FORT_SAFE_ROOT="$SAFE_ROOT" \
FORT_VAULT_KEYRING_FILE="$KEYRING_FILE" \
FORT_TOKEN_TTL=5m \
FORT_REFRESH_SESSION_TTL=30m \
"$STATE_DIR/fortd" >"$FORT_LOG" 2>&1 &
FORTD_PID="$!"

for _ in $(seq 1 80); do
  if "$STATE_DIR/fort" --host "$FORT_HOST" doctor >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
"$STATE_DIR/fort" --host "$FORT_HOST" doctor >/dev/null

echo "[e2e] creating workload + session and rotating via fort-agent"
"$STATE_DIR/fort" --host "$FORT_HOST" --token "$ADMIN_TOKEN" agent create --id e2e-agent --type workload >/dev/null
"$STATE_DIR/fort" --host "$FORT_HOST" --token "$ADMIN_TOKEN" agent policy set --id e2e-agent --bind 'safe:dev:get,set,list,batch-get,run' >/dev/null
REFRESH_FILE="$STATE_DIR/e2e.refresh"
ACCESS_FILE="$STATE_DIR/e2e.access"
"$STATE_DIR/fort" --host "$FORT_HOST" --token "$ADMIN_TOKEN" auth session open --agent e2e-agent --access-ttl 3m --refresh-ttl 30m --refresh-token-out "$REFRESH_FILE" >/dev/null
chmod 600 "$REFRESH_FILE"
"$STATE_DIR/fort-agent" --once --host "$FORT_HOST" --refresh-token-file "$REFRESH_FILE" --token-path "$ACCESS_FILE" >/dev/null
TOKEN="$(cat "$ACCESS_FILE")"

echo "[e2e] fort set/get"
"$STATE_DIR/fort" --host "$FORT_HOST" --token "$TOKEN" set --repo safe --env dev --key E2E_KEY --value from-fort >/dev/null
FORT_GOT="$("$STATE_DIR/fort" --host "$FORT_HOST" --token "$TOKEN" get --repo safe --env dev --key E2E_KEY --format raw)"
[[ "$FORT_GOT" == "from-fort" ]]

echo "[e2e] manual ciphertext decrypt comparison"
cat > "$MANUAL_FILE" <<'GOEOF'
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ecies "github.com/ecies/go/v2"
)

func main() {
	envFile := os.Getenv("ENV_FILE")
	keyringFile := os.Getenv("KEYRING_FILE")
	keyName := os.Getenv("KEY")
	b, err := os.ReadFile(envFile)
	if err != nil {
		panic(err)
	}
	var cipher string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, keyName+"=") {
			continue
		}
		cipher = strings.TrimPrefix(line, keyName+"=")
		break
	}
	if !strings.HasPrefix(cipher, "encrypted:si-vault:") {
		panic("cipher missing si-vault prefix")
	}
	payload := strings.TrimPrefix(cipher, "encrypted:si-vault:")
	blob, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		panic(err)
	}
	raw, err := os.ReadFile(keyringFile)
	if err != nil {
		panic(err)
	}
	var doc struct {
		Entries map[string]struct {
			PrivateKey string `json:"private_key"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(err)
	}
	entry, ok := doc.Entries["safe/dev"]
	if !ok {
		panic("missing keyring entry safe/dev")
	}
	priv, err := ecies.NewPrivateKeyFromHex(strings.TrimSpace(entry.PrivateKey))
	if err != nil {
		panic(err)
	}
	plain, err := ecies.Decrypt(priv, blob)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(plain))
}
GOEOF

MANUAL_GOT="$(
  cd "$FORT_REPO"
  ENV_FILE="$ENV_FILE" KEYRING_FILE="$KEYRING_FILE" KEY=E2E_KEY go run "$MANUAL_FILE"
)"
[[ "$MANUAL_GOT" == "$FORT_GOT" ]]

echo "[e2e] si vault -> fort and fort -> si vault compatibility"
SI_GOT="$(
  cd "$SI_REPO"
  SI_VAULT_KEYRING_FILE="$KEYRING_FILE" go run ./tools/si vault get E2E_KEY --repo safe --env dev --env-file "$ENV_FILE" --reveal
)"
[[ "$SI_GOT" == "$FORT_GOT" ]]

(
  cd "$SI_REPO"
  SI_VAULT_KEYRING_FILE="$KEYRING_FILE" go run ./tools/si vault set SI_TO_FORT from-si --repo safe --env dev --env-file "$ENV_FILE" >/dev/null
)
FROM_SI="$("$STATE_DIR/fort" --host "$FORT_HOST" --token "$TOKEN" get --repo safe --env dev --key SI_TO_FORT --format raw)"
[[ "$FROM_SI" == "from-si" ]]

echo "[e2e] si fort wrapper compatibility"
SI_FORT_GOT="$(
  cd "$SI_REPO"
  FORT_HOST="$FORT_HOST" FORT_TOKEN="$TOKEN" go run ./tools/si fort --repo "$FORT_REPO" --bin "$STATE_DIR/fort" get --repo safe --env dev --key SI_TO_FORT --format raw
)"
[[ "$SI_FORT_GOT" == "$FROM_SI" ]]

echo "[e2e] success"
