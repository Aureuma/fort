package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestComputeNextSleepBounds(t *testing.T) {
	now := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	expires := now.Add(10 * time.Minute)
	rng := deterministicRand()

	got := computeNextSleep(now, expires, 0.70, 30*time.Second, 5*time.Second, rng)
	if got < 5*time.Second {
		t.Fatalf("sleep below min: %s", got)
	}
	if got > (10*time.Minute - 5*time.Second) {
		t.Fatalf("sleep above ceiling: %s", got)
	}
}

func TestRuntimeRunOnceWritesToken(t *testing.T) {
	nextRefresh := "refresh-2"
	access := "access-1"
	expires := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/session/refresh" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      access,
			"refresh_token":     nextRefresh,
			"access_expires_at": expires,
		})
	}))
	defer ts.Close()

	workdir := t.TempDir()
	tokenPath := filepath.Join(workdir, "token.txt")
	refreshPath := filepath.Join(workdir, "refresh.token")
	if err := os.WriteFile(refreshPath, []byte("refresh-1"), 0o600); err != nil {
		t.Fatalf("write refresh token file: %v", err)
	}
	rt, err := New(Config{
		Host:             ts.URL,
		RefreshTokenFile: refreshPath,
		TokenPath:        tokenPath,
		Once:             true,
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	if err := rt.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	b, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(b) != access {
		t.Fatalf("unexpected token written: %q", string(b))
	}
	refreshed, err := os.ReadFile(refreshPath)
	if err != nil {
		t.Fatalf("read refresh token file: %v", err)
	}
	if string(refreshed) != nextRefresh {
		t.Fatalf("unexpected rotated refresh token written: %q", string(refreshed))
	}
}

func TestNewRejectsMissingRefreshTokenFile(t *testing.T) {
	if _, err := New(Config{Host: "http://127.0.0.1:8088", TokenPath: "/tmp/access.token"}); err == nil {
		t.Fatalf("expected missing refresh token file to fail")
	}
}

func TestReadSecretTokenFileRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refresh.token")
	if err := os.WriteFile(path, []byte("rft_123"), 0o644); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if _, err := readSecretTokenFile(path); err == nil {
		t.Fatalf("expected broad file permissions to fail")
	}
}

func deterministicRand() *timeRand {
	return &timeRand{seed: 1}
}

type timeRand struct {
	seed int64
}

func (r *timeRand) Int63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	r.seed = (1103515245*r.seed + 12345) & 0x7fffffff
	return r.seed % n
}
