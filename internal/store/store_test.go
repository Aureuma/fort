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
	if err := st.PutSession(model.RunSession{ID: "s1", AgentID: "a1", ExpiresAt: now.Add(time.Minute), CreatedAt: now}); err != nil {
		t.Fatalf("put session: %v", err)
	}

	if err := st.RemoveAgent("a1"); err != nil {
		t.Fatalf("remove agent: %v", err)
	}
	if _, err := st.GetToken("t1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected token removed, got %v", err)
	}
	if _, err := st.GetSession("s1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected session removed, got %v", err)
	}
}
