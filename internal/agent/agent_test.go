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

	tokenPath := filepath.Join(t.TempDir(), "token.txt")
	rt, err := New(Config{
		Host:         ts.URL,
		RefreshToken: "refresh-1",
		TokenPath:    tokenPath,
		Once:         true,
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
