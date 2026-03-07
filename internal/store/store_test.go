package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"fort/internal/model"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return st
}

func TestPolicyWildcardAllowsAllOps(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	if _, err := st.CreateAgent("codex-dev", model.AgentTypeWorkload, model.AgentStatusActive, now); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	_, err := st.SetPolicy("codex-dev", []model.Binding{{Repo: "*", Env: "*", Ops: []model.Operation{model.OpAny}}}, now)
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}

	cases := []model.Operation{model.OpGet, model.OpSet, model.OpRun, model.OpList, model.OpBatchGet}
	for _, op := range cases {
		allowed, reason := st.CheckPermission("codex-dev", "safe", "prod", op)
		if !allowed {
			t.Fatalf("expected allow for op=%s, reason=%s", op, reason)
		}
	}
}

func TestPolicyDefaultDenyAndDisabledAgent(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	if _, err := st.CreateAgent("a1", model.AgentTypeUser, model.AgentStatusActive, now); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	allowed, reason := st.CheckPermission("a1", "safe", "prod", model.OpGet)
	if allowed || reason != "no_matching_binding" {
		t.Fatalf("expected default deny, got allowed=%v reason=%s", allowed, reason)
	}

	if _, err := st.SetAgentStatus("a1", model.AgentStatusDisabled, now); err != nil {
		t.Fatalf("disable agent: %v", err)
	}
	allowed, reason = st.CheckPermission("a1", "safe", "prod", model.OpGet)
	if allowed || reason != "agent_disabled" {
		t.Fatalf("expected disabled deny, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestBindingNormalizationAndDedup(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	if _, err := st.CreateAgent("a1", model.AgentTypeCI, model.AgentStatusActive, now); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	p, err := st.SetPolicy("a1", []model.Binding{
		{Repo: "safe", Env: "prod", Ops: []model.Operation{model.OpBatchGet, model.OpGet, model.OpGet}},
		{Repo: "safe", Env: "prod", Ops: []model.Operation{model.OpGet}},
	}, now)
	if err != nil {
		t.Fatalf("set policy: %v", err)
	}
	if len(p.Bindings) != 1 {
		t.Fatalf("expected 1 deduped binding, got %d", len(p.Bindings))
	}
	if len(p.Bindings[0].Ops) != 1 || p.Bindings[0].Ops[0] != model.OpGet {
		t.Fatalf("unexpected normalized ops: %#v", p.Bindings[0].Ops)
	}
}

func TestAddAndRemoveBinding(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	if _, err := st.CreateAgent("a1", model.AgentTypeWorkload, model.AgentStatusActive, now); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	if _, err := st.AddBinding("a1", model.Binding{Repo: "safe", Env: "prod", Ops: []model.Operation{model.OpRun}}, now); err != nil {
		t.Fatalf("add binding: %v", err)
	}
	allowed, _ := st.CheckPermission("a1", "safe", "prod", model.OpRun)
	if !allowed {
		t.Fatalf("expected allow after add")
	}

	if _, err := st.RemoveBinding("a1", model.Binding{Repo: "safe", Env: "prod", Ops: []model.Operation{model.OpRun}}, now); err != nil {
		t.Fatalf("remove binding: %v", err)
	}
	allowed, reason := st.CheckPermission("a1", "safe", "prod", model.OpRun)
	if allowed || reason != "no_matching_binding" {
		t.Fatalf("expected deny after remove, allowed=%v reason=%s", allowed, reason)
	}
}

func TestSessionOneTimeMaterialize(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	err := st.PutSession(model.RunSession{ID: "s1", AgentID: "a1", ExpiresAt: now.Add(time.Minute), CreatedAt: now})
	if err != nil {
		t.Fatalf("put session: %v", err)
	}
	if _, err := st.MarkSessionUsed("s1", now); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	if _, err := st.MarkSessionUsed("s1", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict on second use, got %v", err)
	}
}

func TestRemoveAgentRemovesRelatedTokensAndSessions(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	if _, err := st.CreateAgent("a1", model.AgentTypeWorkload, model.AgentStatusActive, now); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	if err := st.PutToken(model.TokenRecord{JTI: "t1", AgentID: "a1", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("put token: %v", err)
	}
	if err := st.PutRefreshSession(model.RefreshSession{
		ID:               "rs1",
		AgentID:          "a1",
		Audience:         "fort-api",
		AccessTTLSeconds: 600,
		RefreshTokenHash: "hash",
		RefreshExpiresAt: now.Add(time.Hour),
		CreatedAt:        now,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("put refresh session: %v", err)
	}
	if err := st.PutSession(model.RunSession{ID: "s1", AgentID: "a1", ExpiresAt: now.Add(time.Minute), CreatedAt: now}); err != nil {
		t.Fatalf("put session: %v", err)
	}

	if err := st.RemoveAgent("a1"); err != nil {
		t.Fatalf("remove agent: %v", err)
	}
	if _, err := st.GetToken("t1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected token removed, got %v", err)
	}
	if _, err := st.GetRefreshSession("rs1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected refresh session removed, got %v", err)
	}
	if _, err := st.GetSession("s1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected session removed, got %v", err)
	}
}

func TestRefreshSessionLookupRotateAndRevoke(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	session := model.RefreshSession{
		ID:               "rs1",
		AgentID:          "agent-a",
		Audience:         "fort-api",
		AccessTTLSeconds: 300,
		RefreshTokenHash: hashRefreshToken("refresh-1"),
		RefreshExpiresAt: now.Add(time.Hour),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := st.PutRefreshSession(session); err != nil {
		t.Fatalf("put refresh session: %v", err)
	}
	got, err := st.GetRefreshSessionByToken("refresh-1")
	if err != nil {
		t.Fatalf("lookup by token: %v", err)
	}
	if got.ID != "rs1" {
		t.Fatalf("unexpected session id: %s", got.ID)
	}
	got, err = st.RotateRefreshSessionToken("rs1", "refresh-2", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("rotate token: %v", err)
	}
	if got.RefreshTokenHash != hashRefreshToken("refresh-2") {
		t.Fatalf("refresh token hash not rotated")
	}
	if _, err := st.GetRefreshSessionByToken("refresh-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected old token lookup to fail, got %v", err)
	}
	got, err = st.RevokeRefreshSessionByToken("refresh-2", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("revoke by token: %v", err)
	}
	if got.RevokedAt.IsZero() {
		t.Fatalf("expected revoked timestamp")
	}
}

func TestRotateAgentCredentialsRevokesTokenAndRefreshSessions(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	if _, err := st.CreateAgent("a1", model.AgentTypeWorkload, model.AgentStatusActive, now); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	if err := st.PutToken(model.TokenRecord{
		JTI:       "t1",
		AgentID:   "a1",
		Audience:  "fort-api",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("put token: %v", err)
	}
	if err := st.PutRefreshSession(model.RefreshSession{
		ID:               "rs1",
		AgentID:          "a1",
		Audience:         "fort-api",
		AccessTTLSeconds: 600,
		RefreshTokenHash: hashRefreshToken("refresh-1"),
		RefreshExpiresAt: now.Add(time.Hour),
		CreatedAt:        now,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("put refresh session: %v", err)
	}

	agent, revokedTokens, revokedSessions, err := st.RotateAgentCredentials("a1", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("rotate agent credentials: %v", err)
	}
	if agent.CredentialVersion != 2 {
		t.Fatalf("expected credential version=2, got %d", agent.CredentialVersion)
	}
	if revokedTokens != 1 {
		t.Fatalf("expected revoked token count=1, got %d", revokedTokens)
	}
	if revokedSessions != 1 {
		t.Fatalf("expected revoked session count=1, got %d", revokedSessions)
	}

	tok, err := st.GetToken("t1")
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if tok.RevokedAt.IsZero() {
		t.Fatalf("expected token to be revoked")
	}
	if tok.Reason != "agent_credentials_rotated" {
		t.Fatalf("unexpected token revoke reason=%q", tok.Reason)
	}
	session, err := st.GetRefreshSession("rs1")
	if err != nil {
		t.Fatalf("get refresh session: %v", err)
	}
	if session.RevokedAt.IsZero() {
		t.Fatalf("expected refresh session revoked")
	}
}

func TestGetRefreshSessionByAnyTokenDetectsRotatedTokenReuse(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	session := model.RefreshSession{
		ID:               "rs1",
		AgentID:          "agent-a",
		Audience:         "fort-api",
		AccessTTLSeconds: 300,
		RefreshTokenHash: hashRefreshToken("refresh-1"),
		RefreshExpiresAt: now.Add(time.Hour),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := st.PutRefreshSession(session); err != nil {
		t.Fatalf("put refresh session: %v", err)
	}
	if _, err := st.RotateRefreshSessionToken("rs1", "refresh-2", now.Add(time.Minute)); err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}

	_, reused, err := st.GetRefreshSessionByAnyToken("refresh-2")
	if err != nil {
		t.Fatalf("lookup new token: %v", err)
	}
	if reused {
		t.Fatalf("expected current token lookup to report reused=false")
	}

	sess, reused, err := st.GetRefreshSessionByAnyToken("refresh-1")
	if err != nil {
		t.Fatalf("lookup old token: %v", err)
	}
	if !reused {
		t.Fatalf("expected old token lookup to report reuse candidate")
	}
	if sess.ID != "rs1" {
		t.Fatalf("unexpected session id: %s", sess.ID)
	}
}

func TestRevokeActiveRefreshSessionsForAgent(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	if _, err := st.CreateAgent("a1", model.AgentTypeWorkload, model.AgentStatusActive, now); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	if err := st.PutRefreshSession(model.RefreshSession{
		ID:               "active-1",
		AgentID:          "a1",
		Audience:         "fort-api",
		AccessTTLSeconds: 600,
		RefreshTokenHash: hashRefreshToken("refresh-active-1"),
		RefreshExpiresAt: now.Add(time.Hour),
		CreatedAt:        now,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("put active refresh session: %v", err)
	}
	if err := st.PutRefreshSession(model.RefreshSession{
		ID:               "expired-1",
		AgentID:          "a1",
		Audience:         "fort-api",
		AccessTTLSeconds: 600,
		RefreshTokenHash: hashRefreshToken("refresh-expired-1"),
		RefreshExpiresAt: now.Add(-time.Minute),
		CreatedAt:        now,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("put expired refresh session: %v", err)
	}
	if err := st.PutRefreshSession(model.RefreshSession{
		ID:               "other-agent",
		AgentID:          "a2",
		Audience:         "fort-api",
		AccessTTLSeconds: 600,
		RefreshTokenHash: hashRefreshToken("refresh-other"),
		RefreshExpiresAt: now.Add(time.Hour),
		CreatedAt:        now,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("put other agent refresh session: %v", err)
	}

	revoked, err := st.RevokeActiveRefreshSessionsForAgent("a1", now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("revoke active refresh sessions: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("expected revoked count=1, got %d", revoked)
	}

	active, err := st.GetRefreshSession("active-1")
	if err != nil {
		t.Fatalf("get active session: %v", err)
	}
	if active.RevokedAt.IsZero() {
		t.Fatalf("expected active session revoked")
	}
	expired, err := st.GetRefreshSession("expired-1")
	if err != nil {
		t.Fatalf("get expired session: %v", err)
	}
	if !expired.RevokedAt.IsZero() {
		t.Fatalf("expected expired session unchanged")
	}
	other, err := st.GetRefreshSession("other-agent")
	if err != nil {
		t.Fatalf("get other session: %v", err)
	}
	if !other.RevokedAt.IsZero() {
		t.Fatalf("expected other-agent session unchanged")
	}
}

func TestRevokeActiveTokensForAgent(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	if _, err := st.CreateAgent("a1", model.AgentTypeWorkload, model.AgentStatusActive, now); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	if err := st.PutToken(model.TokenRecord{
		JTI:       "active-token",
		AgentID:   "a1",
		Audience:  "fort-api",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("put active token: %v", err)
	}
	if err := st.PutToken(model.TokenRecord{
		JTI:       "expired-token",
		AgentID:   "a1",
		Audience:  "fort-api",
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("put expired token: %v", err)
	}
	if err := st.PutToken(model.TokenRecord{
		JTI:       "other-agent-token",
		AgentID:   "a2",
		Audience:  "fort-api",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("put other agent token: %v", err)
	}

	revoked, err := st.RevokeActiveTokensForAgent("a1", "rotation", now.Add(time.Second))
	if err != nil {
		t.Fatalf("revoke active tokens: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("expected revoked count=1, got %d", revoked)
	}

	active, err := st.GetToken("active-token")
	if err != nil {
		t.Fatalf("get active token: %v", err)
	}
	if active.RevokedAt.IsZero() || active.Reason != "rotation" {
		t.Fatalf("expected active token revoked with reason")
	}
	expired, err := st.GetToken("expired-token")
	if err != nil {
		t.Fatalf("get expired token: %v", err)
	}
	if !expired.RevokedAt.IsZero() {
		t.Fatalf("expected expired token unchanged")
	}
	other, err := st.GetToken("other-agent-token")
	if err != nil {
		t.Fatalf("get other agent token: %v", err)
	}
	if !other.RevokedAt.IsZero() {
		t.Fatalf("expected other-agent token unchanged")
	}
}
