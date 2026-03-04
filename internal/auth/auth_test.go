package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"fort/internal/model"
	"fort/internal/store"
)

func newAuthManager(t *testing.T, now time.Time) (*Manager, *store.Store, model.Agent) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	agent, err := st.CreateAgent("agent-1", model.AgentTypeWorkload, model.AgentStatusActive, now)
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	mgr := &Manager{SigningKey: []byte("test-signing-key"), Store: st, Now: func() time.Time { return now }}
	return mgr, st, agent
}

func TestIssueParseRevoke(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	mgr, _, agent := newAuthManager(t, now)

	token, rec, err := mgr.Issue(agent, 15*time.Minute, "fort-api")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if token == "" || rec.JTI == "" {
		t.Fatalf("expected token+jti")
	}
	claims, err := mgr.Parse(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.AgentID != agent.ID {
		t.Fatalf("unexpected claims agent_id=%s", claims.AgentID)
	}

	if _, err := mgr.Revoke(rec.JTI, "test revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := mgr.Parse(token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized after revoke, got %v", err)
	}
}

func TestParseExpired(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	mgr, _, agent := newAuthManager(t, now)
	token, _, err := mgr.Issue(agent, time.Minute, "fort-api")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	mgr.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := mgr.Parse(token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized for expired token, got %v", err)
	}
}
