package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"fort/internal/model"
	"fort/internal/store"

	"github.com/golang-jwt/jwt/v5"
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
	mgr := &Manager{
		SigningKey: []byte("test-signing-key"),
		Issuer:     "fortd-test",
		Store:      st,
		Now:        func() time.Time { return now },
	}
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

func TestRefreshSessionLifecycle(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	mgr, _, agent := newAuthManager(t, now)

	accessToken, rec, session, refreshToken, err := mgr.OpenRefreshSession(agent, 2*time.Minute, time.Hour, "fort-api")
	if err != nil {
		t.Fatalf("open refresh session: %v", err)
	}
	if accessToken == "" || rec.JTI == "" || session.ID == "" || refreshToken == "" {
		t.Fatalf("expected non-empty session artifacts")
	}
	if _, err := mgr.Parse(accessToken); err != nil {
		t.Fatalf("parse opened access token: %v", err)
	}

	mgr.Now = func() time.Time { return now.Add(30 * time.Second) }
	accessToken2, rec2, session2, refreshToken2, err := mgr.RefreshByToken(refreshToken)
	if err != nil {
		t.Fatalf("refresh by token: %v", err)
	}
	if accessToken2 == "" || rec2.JTI == "" || refreshToken2 == "" {
		t.Fatalf("expected refreshed session artifacts")
	}
	if session2.ID != session.ID {
		t.Fatalf("expected same session id, got %s vs %s", session2.ID, session.ID)
	}
	if refreshToken2 == refreshToken {
		t.Fatalf("expected rotated refresh token")
	}
	if _, _, _, _, err := mgr.RefreshByToken(refreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected old refresh token to be unauthorized, got %v", err)
	}

	if _, err := mgr.CloseRefreshSessionByToken(refreshToken2); err != nil {
		t.Fatalf("close by token: %v", err)
	}
	if _, _, _, _, err := mgr.RefreshByToken(refreshToken2); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized after close, got %v", err)
	}
}

func TestParseRejectsIssuerMismatch(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	mgr, st, agent := newAuthManager(t, now)

	token, _, err := mgr.Issue(agent, 15*time.Minute, "fort-api")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	mgrWrongIssuer := &Manager{
		SigningKey: []byte("test-signing-key"),
		Issuer:     "another-issuer",
		Store:      st,
		Now:        mgr.Now,
	}
	if _, err := mgrWrongIssuer.Parse(token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized for issuer mismatch, got %v", err)
	}
}

func TestParseRejectsAudienceMismatchAgainstStoredToken(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	mgr, st, agent := newAuthManager(t, now)

	token, rec, err := mgr.Issue(agent, 15*time.Minute, "fort-api")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	rec.Audience = "different-aud"
	if err := st.PutToken(rec); err != nil {
		t.Fatalf("put token: %v", err)
	}
	if _, err := mgr.Parse(token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized for audience mismatch, got %v", err)
	}
}

func TestParseRejectsSubjectAgentIDMismatch(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	mgr, st, agent := newAuthManager(t, now)

	jti := "mismatch-sub-jti"
	claims := Claims{
		AgentID: agent.ID,
		Type:    string(agent.Type),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    mgr.Issuer,
			Subject:   "some-other-agent",
			Audience:  jwt.ClaimStrings{"fort-api"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("test-signing-key"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := st.PutToken(model.TokenRecord{
		JTI:       jti,
		AgentID:   agent.ID,
		Audience:  "fort-api",
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("put token: %v", err)
	}
	if _, err := mgr.Parse(signed); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized for subject mismatch, got %v", err)
	}
}
