package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fort/internal/auth"
	"fort/internal/config"
	"fort/internal/model"
	"fort/internal/store"
	"fort/internal/vaultbridge"

	ecies "github.com/ecies/go/v2"
)

type apiResp map[string]any

func newTestAPI(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	tmp := t.TempDir()
	st, err := store.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	key, err := ecies.GenerateKey()
	if err != nil {
		t.Fatalf("generate vault key: %v", err)
	}
	keyringPath := filepath.Join(tmp, "keyring.json")
	keyringJSON := map[string]any{
		"entries": map[string]any{
			"safe/prod": map[string]any{
				"repo":        "safe",
				"env":         "prod",
				"public_key":  key.PublicKey.Hex(true),
				"private_key": key.Hex(),
			},
		},
	}
	raw, err := json.Marshal(keyringJSON)
	if err != nil {
		t.Fatalf("marshal keyring: %v", err)
	}
	if err := os.WriteFile(keyringPath, raw, 0o600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}
	cfg := config.Config{
		Addr:        ":0",
		StatePath:   filepath.Join(t.TempDir(), "unused.json"),
		SigningKey:  "test-signing-key",
		SafeRoot:    tmp,
		KeyringPath: keyringPath,
		TokenTTL:    15 * time.Minute,
		RunTTL:      60 * time.Second,
		SecretTTL:   120 * time.Second,
	}
	admin, err := st.CreateAgent("admin", model.AgentTypeUser, model.AgentStatusActive, time.Now().UTC())
	if err != nil {
		t.Fatalf("create admin agent: %v", err)
	}
	if _, err := st.SetPolicy("admin", []model.Binding{{Repo: "*", Env: "*", Ops: []model.Operation{model.OpAny}}}, time.Now().UTC()); err != nil {
		t.Fatalf("set admin policy: %v", err)
	}
	manager := &auth.Manager{SigningKey: []byte(cfg.SigningKey), Store: st}
	adminToken, _, err := manager.Issue(admin, cfg.TokenTTL, "fort-api")
	if err != nil {
		t.Fatalf("issue admin token: %v", err)
	}
	backend, err := vaultTestBackend(cfg)
	if err != nil {
		t.Fatalf("new vault backend: %v", err)
	}
	ts := httptest.NewServer(newHandler(cfg, st, backend))
	t.Cleanup(ts.Close)
	return ts, adminToken
}

func vaultTestBackend(cfg config.Config) (secretBackend, error) {
	return vaultbridge.New(vaultbridge.Config{
		SafeRoot:      cfg.SafeRoot,
		KeyringPath:   cfg.KeyringPath,
		ExtraPrivKeys: cfg.ExtraPrivateKeys,
	})
}

func doJSON(t *testing.T, client *http.Client, method, url string, body any, headers map[string]string) (int, apiResp) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	var out apiResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func mustCreateAgent(t *testing.T, client *http.Client, base, adminToken, id, typ string) {
	t.Helper()
	status, body := doJSON(t, client, http.MethodPost, base+"/v1/agents", map[string]any{
		"id":   id,
		"type": typ,
	}, map[string]string{"Authorization": "Bearer " + adminToken})
	if status != http.StatusCreated {
		t.Fatalf("create agent failed status=%d body=%v", status, body)
	}
}

func mustSetPolicy(t *testing.T, client *http.Client, base, adminToken, id string, bindings []map[string]any) {
	t.Helper()
	status, body := doJSON(t, client, http.MethodPut, base+"/v1/agents/"+id+"/policy", map[string]any{
		"bindings": bindings,
	}, map[string]string{"Authorization": "Bearer " + adminToken})
	if status != http.StatusOK {
		t.Fatalf("set policy failed status=%d body=%v", status, body)
	}
}

func mustIssueToken(t *testing.T, client *http.Client, base, agentID string, extraHeaders map[string]string) string {
	t.Helper()
	headers := map[string]string{}
	for k, v := range extraHeaders {
		headers[k] = v
	}
	status, body := doJSON(t, client, http.MethodPost, base+"/v1/auth/token", map[string]any{
		"agent_id": agentID,
	}, headers)
	if status != http.StatusOK {
		t.Fatalf("issue token failed status=%d body=%v", status, body)
	}
	tok, _ := body["token"].(string)
	if tok == "" {
		t.Fatalf("missing token in response: %v", body)
	}
	return tok
}

func TestEndToEndAuthSecretsAndRunSession(t *testing.T) {
	ts, adminToken := newTestAPI(t)
	client := ts.Client()

	adminHeaders := map[string]string{"Authorization": "Bearer " + adminToken}
	status, body := doJSON(t, client, http.MethodPost, ts.URL+"/v1/agents", map[string]any{
		"id":   "profile-codex-a",
		"type": "workload",
	}, adminHeaders)
	if status != http.StatusCreated {
		t.Fatalf("admin create workload failed status=%d body=%v", status, body)
	}

	status, body = doJSON(t, client, http.MethodPut, ts.URL+"/v1/agents/profile-codex-a/policy", map[string]any{
		"bindings": []map[string]any{{
			"repo": "safe",
			"env":  "prod",
			"ops":  []string{"get", "set", "list", "run"},
		}},
	}, adminHeaders)
	if status != http.StatusOK {
		t.Fatalf("admin set workload policy failed status=%d body=%v", status, body)
	}

	workloadToken := mustIssueToken(t, client, ts.URL, "profile-codex-a", adminHeaders)
	workloadHeaders := map[string]string{"Authorization": "Bearer " + workloadToken}

	status, body = doJSON(t, client, http.MethodPost, ts.URL+"/v1/secrets/set", map[string]any{
		"repo":  "safe",
		"env":   "prod",
		"key":   "API_KEY",
		"value": "secret-value",
	}, workloadHeaders)
	if status != http.StatusOK {
		t.Fatalf("secret set failed status=%d body=%v", status, body)
	}

	status, body = doJSON(t, client, http.MethodPost, ts.URL+"/v1/secrets/get", map[string]any{
		"repo": "safe",
		"env":  "prod",
		"key":  "API_KEY",
	}, workloadHeaders)
	if status != http.StatusOK {
		t.Fatalf("secret get failed status=%d body=%v", status, body)
	}
	if got, _ := body["value"].(string); got != "secret-value" {
		t.Fatalf("unexpected get value: %v", body)
	}

	status, body = doJSON(t, client, http.MethodPost, ts.URL+"/v1/secrets/list", map[string]any{
		"repo": "safe",
		"env":  "prod",
	}, workloadHeaders)
	if status != http.StatusOK {
		t.Fatalf("secret list failed status=%d body=%v", status, body)
	}

	status, body = doJSON(t, client, http.MethodPost, ts.URL+"/v1/run/session/open", map[string]any{
		"repo": "safe",
		"env":  "prod",
		"keys": []string{"API_KEY"},
		"mode": "files",
	}, workloadHeaders)
	if status != http.StatusOK {
		t.Fatalf("run open failed status=%d body=%v", status, body)
	}
	sessionID, _ := body["session_id"].(string)
	oneTimeToken, _ := body["one_time_token"].(string)
	if sessionID == "" || oneTimeToken == "" {
		t.Fatalf("missing session fields: %v", body)
	}

	status, body = doJSON(t, client, http.MethodPost, ts.URL+"/v1/run/session/materialize", map[string]any{
		"session_id":     sessionID,
		"one_time_token": oneTimeToken,
	}, workloadHeaders)
	if status != http.StatusOK {
		t.Fatalf("run materialize failed status=%d body=%v", status, body)
	}
	values, _ := body["values"].(map[string]any)
	if got, _ := values["API_KEY"].(string); got != "secret-value" {
		t.Fatalf("unexpected materialized value: %v", body)
	}

	status, _ = doJSON(t, client, http.MethodPost, ts.URL+"/v1/run/session/materialize", map[string]any{
		"session_id":     sessionID,
		"one_time_token": oneTimeToken,
	}, workloadHeaders)
	if status != http.StatusConflict {
		t.Fatalf("expected conflict on second materialize, got %d", status)
	}

	status, body = doJSON(t, client, http.MethodPost, ts.URL+"/v1/run/session/close", map[string]any{
		"session_id": sessionID,
	}, workloadHeaders)
	if status != http.StatusOK {
		t.Fatalf("run close failed status=%d body=%v", status, body)
	}
}

func TestDefaultDenyWithoutBinding(t *testing.T) {
	ts, adminToken := newTestAPI(t)
	client := ts.Client()

	adminHeaders := map[string]string{"Authorization": "Bearer " + adminToken}

	mustCreateAgent(t, client, ts.URL, adminToken, "no-access", "workload")
	noAccessToken := mustIssueToken(t, client, ts.URL, "no-access", adminHeaders)

	status, _ := doJSON(t, client, http.MethodPost, ts.URL+"/v1/secrets/get", map[string]any{
		"repo": "safe",
		"env":  "prod",
		"key":  "API_KEY",
	}, map[string]string{"Authorization": "Bearer " + noAccessToken})
	if status != http.StatusForbidden {
		t.Fatalf("expected forbidden for default deny, got %d", status)
	}
}

func TestAuthSessionOpenRefreshAndClose(t *testing.T) {
	ts, adminToken := newTestAPI(t)
	client := ts.Client()

	mustCreateAgent(t, client, ts.URL, adminToken, "profile-a", "workload")
	adminHeaders := map[string]string{"Authorization": "Bearer " + adminToken}

	status, body := doJSON(t, client, http.MethodPost, ts.URL+"/v1/auth/session/open", map[string]any{
		"agent_id":    "profile-a",
		"access_ttl":  "90s",
		"refresh_ttl": "10m",
	}, adminHeaders)
	if status != http.StatusOK {
		t.Fatalf("session open failed status=%d body=%v", status, body)
	}
	sessionID, _ := body["session_id"].(string)
	refreshToken, _ := body["refresh_token"].(string)
	if sessionID == "" || refreshToken == "" {
		t.Fatalf("missing open session fields: %v", body)
	}

	status, body = doJSON(t, client, http.MethodPost, ts.URL+"/v1/auth/session/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("session refresh failed status=%d body=%v", status, body)
	}
	refreshToken2, _ := body["refresh_token"].(string)
	if refreshToken2 == "" || refreshToken2 == refreshToken {
		t.Fatalf("expected rotated refresh token, got %v", body["refresh_token"])
	}

	status, _ = doJSON(t, client, http.MethodPost, ts.URL+"/v1/auth/session/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized for old refresh token, got %d", status)
	}
	status, _ = doJSON(t, client, http.MethodPost, ts.URL+"/v1/auth/session/refresh", map[string]any{
		"refresh_token": refreshToken2,
	}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized for latest refresh token after old-token reuse, got %d", status)
	}

	status, body = doJSON(t, client, http.MethodPost, ts.URL+"/v1/auth/session/close", map[string]any{
		"session_id": sessionID,
	}, adminHeaders)
	if status != http.StatusOK {
		t.Fatalf("session close failed status=%d body=%v", status, body)
	}

	status, _ = doJSON(t, client, http.MethodPost, ts.URL+"/v1/auth/session/refresh", map[string]any{
		"refresh_token": refreshToken2,
	}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized after close, got %d", status)
	}
}

func TestAgentRotateInvalidatesExistingRefreshSessions(t *testing.T) {
	ts, adminToken := newTestAPI(t)
	client := ts.Client()

	mustCreateAgent(t, client, ts.URL, adminToken, "profile-b", "workload")
	adminHeaders := map[string]string{"Authorization": "Bearer " + adminToken}

	status, body := doJSON(t, client, http.MethodPost, ts.URL+"/v1/auth/session/open", map[string]any{
		"agent_id":    "profile-b",
		"access_ttl":  "90s",
		"refresh_ttl": "10m",
	}, adminHeaders)
	if status != http.StatusOK {
		t.Fatalf("session open failed status=%d body=%v", status, body)
	}
	refreshToken, _ := body["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatalf("missing refresh token")
	}

	status, body = doJSON(t, client, http.MethodPost, ts.URL+"/v1/agents/profile-b/rotate", map[string]any{}, adminHeaders)
	if status != http.StatusOK {
		t.Fatalf("rotate failed status=%d body=%v", status, body)
	}
	if got, _ := body["revoked_session_count"].(float64); got < 1 {
		t.Fatalf("expected revoked_session_count >= 1, got %v", body)
	}

	status, _ = doJSON(t, client, http.MethodPost, ts.URL+"/v1/auth/session/refresh", map[string]any{
		"refresh_token": refreshToken,
	}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized after rotate, got %d", status)
	}
}
