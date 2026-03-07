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
