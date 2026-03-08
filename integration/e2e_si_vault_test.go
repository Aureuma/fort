//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fort/internal/auth"
	"fort/internal/model"
	"fort/internal/store"

	ecies "github.com/ecies/go/v2"
)

func TestFortE2ESIVault(t *testing.T) {
	t.Parallel()
	requireCmd(t, "go")

	fortRepo := repoRoot(t)
	siRepo := strings.TrimSpace(os.Getenv("SI_REPO"))
	if siRepo == "" {
		siRepo = filepath.Clean(filepath.Join(fortRepo, "..", "si"))
	}
	if _, err := os.Stat(siRepo); err != nil {
		t.Fatalf("SI repo not found at %s; set SI_REPO", siRepo)
	}

	tmpRoot := t.TempDir()
	stateDir := filepath.Join(tmpRoot, "state")
	safeRoot := filepath.Join(tmpRoot, "safe")
	envFile := filepath.Join(safeRoot, "safe", ".env.dev")
	ensureDir(t, stateDir)
	ensureDir(t, filepath.Dir(envFile))

	stateFile := filepath.Join(stateDir, "state.json")
	keyringFile := filepath.Join(stateDir, "si-vault-keyring.json")
	signingKeyFile := filepath.Join(stateDir, "jwt-signing.key")
	fortHost := "127.0.0.1:0"
	fortAddr := freeTCPAddress(t, fortHost)
	fortBase := "http://" + fortAddr

	fortClient := filepath.Join(stateDir, "fort")
	fortDaemon := filepath.Join(stateDir, "fortd")
	fortAgent := filepath.Join(stateDir, "fort-agent")
	buildGoBinary(t, fortRepo, fortClient, "./cmd/fort")
	buildGoBinary(t, fortRepo, fortDaemon, "./cmd/fortd")
	buildGoBinary(t, fortRepo, fortAgent, "./cmd/fort-agent")

	adminToken := seedFortStateForE2E(t, stateFile, keyringFile, signingKeyFile, "e2e-signing-key-012345678901234567890123", "safe", "dev")

	var fortOut bytes.Buffer
	var fortErr bytes.Buffer
	cmd := exec.Command(fortDaemon)
	cmd.Env = mergeEnv([]string{
		envKV("FORT_ADDR", fortAddr),
		envKV("FORT_STATE_PATH", stateFile),
		envKV("FORT_JWT_SIGNING_KEY_FILE", signingKeyFile),
		envKV("FORT_SAFE_ROOT", safeRoot),
		envKV("FORT_VAULT_KEYRING_FILE", keyringFile),
		"FORT_TOKEN_TTL=5m",
		"FORT_REFRESH_SESSION_TTL=30m",
	})
	cmd.Stdout = &fortOut
	cmd.Stderr = &fortErr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fortd: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process == nil {
			return
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	waitFor(t, 10*time.Second, 100*time.Millisecond, func() error {
		_, err := exec.Command(fortClient, "--host", fortBase, "doctor").CombinedOutput()
		if err == nil {
			return nil
		}
		return err
	}, "fortd readiness")

	runCmd(t, "", nil, fortClient, "--host", fortBase, "--token", adminToken, "agent", "create", "--id", "e2e-agent", "--type", "workload")
	runCmd(t, "", nil, fortClient, "--host", fortBase, "--token", adminToken, "agent", "policy", "set", "--id", "e2e-agent", "--bind", "safe:dev:get,set,list,batch-get,run")
	refreshFile := filepath.Join(stateDir, "e2e.refresh")
	accessFile := filepath.Join(stateDir, "e2e.access")
	runCmd(t, "", nil, fortClient, "--host", fortBase, "--token", adminToken, "auth", "session", "open", "--agent", "e2e-agent", "--access-ttl", "3m", "--refresh-ttl", "30m", "--refresh-token-out", refreshFile)
	if err := os.Chmod(refreshFile, 0o600); err != nil {
		t.Fatalf("chmod refresh token: %v", err)
	}
	runCmd(t, "", nil, fortAgent, "--once", "--host", fortBase, "--refresh-token-file", refreshFile, "--token-path", accessFile)
	accessToken := strings.TrimSpace(stringMustRead(t, accessFile, "read workload access token"))

	runCmd(t, "", nil, fortClient, "--host", fortBase, "--token", accessToken, "set", "--repo", "safe", "--env", "dev", "--key", "E2E_KEY", "--value", "from-fort")
	fortGot := runCmd(t, "", nil, fortClient, "--host", fortBase, "--token", accessToken, "get", "--repo", "safe", "--env", "dev", "--key", "E2E_KEY", "--format", "raw")
	manualGot := decryptVaultCipherForTest(t, envFile, "E2E_KEY", keyringFile)
	if fortGot != manualGot {
		t.Fatalf("fort get and manual decrypt mismatch: fort=%q manual=%q", fortGot, manualGot)
	}

	siGot := runCmd(t, siRepo, []string{envKV("SI_VAULT_KEYRING_FILE", keyringFile)}, "go", "run", "./tools/si", "vault", "get", "E2E_KEY", "--repo", "safe", "--env", "dev", "--env-file", envFile, "--reveal")
	if siGot != fortGot {
		t.Fatalf("si vault get mismatch: si=%q fort=%q", siGot, fortGot)
	}
	runCmd(t, siRepo, []string{envKV("SI_VAULT_KEYRING_FILE", keyringFile)}, "go", "run", "./tools/si", "vault", "set", "E2E_SI_FORT_BRIDGE", "from-si", "--repo", "safe", "--env", "dev", "--env-file", envFile)
	fromSi := runCmd(t, "", nil, fortClient, "--host", fortBase, "--token", accessToken, "get", "--repo", "safe", "--env", "dev", "--key", "E2E_SI_FORT_BRIDGE", "--format", "raw")
	if fromSi != "from-si" {
		t.Fatalf("fort get from si set value mismatch: %q", fromSi)
	}

	siFortGot := runCmd(t, siRepo, []string{
		envKV("FORT_HOST", fortBase),
		envKV("FORT_TOKEN", accessToken),
	}, "go", "run", "./tools/si", "fort", "--repo", fortRepo, "--bin", fortClient, "get", "--repo", "safe", "--env", "dev", "--key", "E2E_SI_FORT_BRIDGE", "--format", "raw")
	if siFortGot != fromSi {
		t.Fatalf("si fort wrapper mismatch: si=%q fort=%q", siFortGot, fromSi)
	}
}

type e2eFortKeyring struct {
	Entries map[string]e2eFortKeyringEntry `json:"entries"`
}

type e2eFortKeyringEntry struct {
	Repo        string `json:"repo"`
	Env         string `json:"env"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
}

func seedFortStateForE2E(t *testing.T, statePath, keyringPath, signingKeyPath, signingKey, repo, env string) string {
	t.Helper()

	st, err := store.New(statePath)
	if err != nil {
		t.Fatalf("create state: %v", err)
	}
	now := time.Now().UTC()
	admin, err := st.CreateAgent("admin", model.AgentTypeUser, model.AgentStatusActive, now)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if _, err := st.SetPolicy(admin.ID, []model.Binding{{
		Repo: "*",
		Env:  "*",
		Ops:  []model.Operation{model.OpAny},
	}}, now); err != nil {
		t.Fatalf("set admin policy: %v", err)
	}

	manager := &auth.Manager{
		SigningKey: []byte(signingKey),
		Store:      st,
	}
	adminToken, _, err := manager.Issue(admin, 24*time.Hour, "fort-api")
	if err != nil {
		t.Fatalf("issue admin token: %v", err)
	}

	key, err := ecies.GenerateKey()
	if err != nil {
		t.Fatalf("generate ecies key: %v", err)
	}
	entry := e2eFortKeyring{
		Entries: map[string]e2eFortKeyringEntry{
			fmt.Sprintf("%s/%s", repo, env): {
				Repo:       repo,
				Env:        env,
				PublicKey:  key.PublicKey.Hex(true),
				PrivateKey: key.Hex(),
			},
		},
	}
	raw, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		t.Fatalf("marshal keyring: %v", err)
	}
	raw = append(raw, '\n')
	writeFile(t, keyringPath, raw, 0o600)
	writeFile(t, signingKeyPath, []byte(signingKey), 0o600)

	return adminToken
}

func freeTCPAddress(t *testing.T, listenAddr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("find free tcp port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func stringMustRead(t *testing.T, path string, context string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s from %s: %v", context, path, err)
	}
	return string(raw)
}

func decryptVaultCipherForTest(t *testing.T, envFile, keyName, keyringPath string) string {
	t.Helper()
	cipher := findVaultCipherInEnvFile(t, envFile, keyName)
	if !strings.HasPrefix(cipher, "encrypted:si-vault:") {
		t.Fatalf("secret %s in %s is not encrypted cipher: %q", keyName, envFile, cipher)
	}
	payload := strings.TrimPrefix(cipher, "encrypted:si-vault:")
	blob, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("base64 decrypt decode: %v", err)
	}

	var doc e2eFortKeyring
	raw, err := os.ReadFile(keyringPath)
	if err != nil {
		t.Fatalf("read keyring %s: %v", keyringPath, err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal keyring: %v", err)
	}
	entry, ok := doc.Entries["safe/dev"]
	if !ok {
		t.Fatalf("missing keyring entry safe/dev")
	}
	privateKey, err := ecies.NewPrivateKeyFromHex(entry.PrivateKey)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	plain, err := ecies.Decrypt(privateKey, blob)
	if err != nil {
		t.Fatalf("ecies decrypt: %v", err)
	}
	return string(plain)
}

func findVaultCipherInEnvFile(t *testing.T, envFile, keyName string) string {
	t.Helper()
	f, err := os.Open(envFile)
	if err != nil {
		t.Fatalf("open env file %s: %v", envFile, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	target := keyName + "="
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, target) {
			return strings.TrimPrefix(line, target)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan env file %s: %v", envFile, err)
	}
	t.Fatalf("missing key %s in %s", keyName, envFile)
	return ""
}
