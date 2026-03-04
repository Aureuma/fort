package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"fort/internal/model"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type persistentState struct {
	Agents   map[string]model.Agent                `json:"agents"`
	Policies map[string]model.Policy               `json:"policies"`
	Secrets  map[string]map[string]map[string]string `json:"secrets"`
	Tokens   map[string]model.TokenRecord          `json:"tokens"`
	Sessions map[string]model.RunSession           `json:"sessions"`
	Audit    []model.AuditEvent                    `json:"audit"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	state persistentState
}

func New(path string) (*Store, error) {
	s := &Store{path: path}
	s.state = persistentState{
		Agents:   map[string]model.Agent{},
		Policies: map[string]model.Policy{},
		Secrets:  map[string]map[string]map[string]string{},
		Tokens:   map[string]model.TokenRecord{},
		Sessions: map[string]model.RunSession{},
		Audit:    make([]model.AuditEvent, 0, 64),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	var st persistentState
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("decode state: %w", err)
	}
	if st.Agents == nil {
		st.Agents = map[string]model.Agent{}
	}
	if st.Policies == nil {
		st.Policies = map[string]model.Policy{}
	}
	if st.Secrets == nil {
		st.Secrets = map[string]map[string]map[string]string{}
	}
	if st.Tokens == nil {
		st.Tokens = map[string]model.TokenRecord{}
	}
	if st.Sessions == nil {
		st.Sessions = map[string]model.RunSession{}
	}
	s.state = st
	return nil
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) CreateAgent(id string, t model.AgentType, status model.AgentStatus, now time.Time) (model.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Agents[id]; ok {
		return model.Agent{}, ErrConflict
	}
	a := model.Agent{
		ID:                id,
		Type:              t,
		Status:            status,
		CredentialVersion: 1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	s.state.Agents[id] = a
	if err := s.persistLocked(); err != nil {
		return model.Agent{}, err
	}
	return a, nil
}

func (s *Store) GetAgent(id string) (model.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.state.Agents[id]
	if !ok {
		return model.Agent{}, ErrNotFound
	}
	return a, nil
}

func (s *Store) ListAgents(filterType model.AgentType, filterStatus model.AgentStatus) []model.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Agent, 0, len(s.state.Agents))
	for _, a := range s.state.Agents {
		if filterType != "" && a.Type != filterType {
			continue
		}
		if filterStatus != "" && a.Status != filterStatus {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) SetAgentStatus(id string, status model.AgentStatus, now time.Time) (model.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.state.Agents[id]
	if !ok {
		return model.Agent{}, ErrNotFound
	}
	a.Status = status
	a.UpdatedAt = now
	s.state.Agents[id] = a
	if err := s.persistLocked(); err != nil {
		return model.Agent{}, err
	}
	return a, nil
}

func (s *Store) RotateAgent(id string, now time.Time) (model.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.state.Agents[id]
	if !ok {
		return model.Agent{}, ErrNotFound
	}
	a.CredentialVersion++
	a.UpdatedAt = now
	s.state.Agents[id] = a
	if err := s.persistLocked(); err != nil {
		return model.Agent{}, err
	}
	return a, nil
}

func (s *Store) RemoveAgent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Agents[id]; !ok {
		return ErrNotFound
	}
	delete(s.state.Agents, id)
	delete(s.state.Policies, id)
	if err := s.persistLocked(); err != nil {
		return err
	}
	return nil
}

func normalizeOps(ops []model.Operation) []model.Operation {
	m := map[model.Operation]struct{}{}
	for _, op := range ops {
		if op == model.OpBatch {
			op = model.OpGet
		}
		m[op] = struct{}{}
	}
	out := make([]model.Operation, 0, len(m))
	for op := range m {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *Store) GetPolicy(agentID string) (model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.state.Policies[agentID]
	if !ok {
		return model.Policy{AgentID: agentID, Bindings: []model.Binding{}}, nil
	}
	return p, nil
}

func (s *Store) SetPolicy(agentID string, bindings []model.Binding, now time.Time) (model.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Agents[agentID]; !ok {
		return model.Policy{}, ErrNotFound
	}
	norm := make([]model.Binding, 0, len(bindings))
	for _, b := range bindings {
		b.Repo = strings.TrimSpace(b.Repo)
		b.Env = strings.TrimSpace(b.Env)
		b.Ops = normalizeOps(b.Ops)
		if b.Repo == "" || b.Env == "" || len(b.Ops) == 0 {
			continue
		}
		norm = append(norm, b)
	}
	p := model.Policy{AgentID: agentID, Bindings: norm, UpdatedAt: now}
	s.state.Policies[agentID] = p
	if err := s.persistLocked(); err != nil {
		return model.Policy{}, err
	}
	return p, nil
}

func sameBinding(a, b model.Binding) bool {
	if a.Repo != b.Repo || a.Env != b.Env {
		return false
	}
	if len(a.Ops) != len(b.Ops) {
		return false
	}
	for i := range a.Ops {
		if a.Ops[i] != b.Ops[i] {
			return false
		}
	}
	return true
}

func (s *Store) AddBinding(agentID string, binding model.Binding, now time.Time) (model.Policy, error) {
	p, err := s.GetPolicy(agentID)
	if err != nil {
		return model.Policy{}, err
	}
	binding.Ops = normalizeOps(binding.Ops)
	for _, b := range p.Bindings {
		if sameBinding(b, binding) {
			return p, nil
		}
	}
	p.Bindings = append(p.Bindings, binding)
	return s.SetPolicy(agentID, p.Bindings, now)
}

func (s *Store) RemoveBinding(agentID string, binding model.Binding, now time.Time) (model.Policy, error) {
	p, err := s.GetPolicy(agentID)
	if err != nil {
		return model.Policy{}, err
	}
	binding.Ops = normalizeOps(binding.Ops)
	out := make([]model.Binding, 0, len(p.Bindings))
	for _, b := range p.Bindings {
		if sameBinding(b, binding) {
			continue
		}
		out = append(out, b)
	}
	return s.SetPolicy(agentID, out, now)
}

func (s *Store) CheckPermission(agentID, repo, env string, op model.Operation) (bool, string) {
	a, err := s.GetAgent(agentID)
	if err != nil {
		return false, "agent_not_found"
	}
	if a.Status != model.AgentStatusActive {
		return false, "agent_disabled"
	}
	p, _ := s.GetPolicy(agentID)
	for _, b := range p.Bindings {
		if b.Repo != repo || b.Env != env {
			continue
		}
		for _, allowed := range b.Ops {
			if allowed == op || (op == model.OpBatch && allowed == model.OpGet) {
				return true, "allowed"
			}
		}
	}
	return false, "no_matching_binding"
}

func (s *Store) SetSecret(repo, env, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Secrets[repo]; !ok {
		s.state.Secrets[repo] = map[string]map[string]string{}
	}
	if _, ok := s.state.Secrets[repo][env]; !ok {
		s.state.Secrets[repo][env] = map[string]string{}
	}
	s.state.Secrets[repo][env][key] = value
	return s.persistLocked()
}

func (s *Store) GetSecret(repo, env, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.state.Secrets[repo]; !ok {
		return "", ErrNotFound
	}
	if _, ok := s.state.Secrets[repo][env]; !ok {
		return "", ErrNotFound
	}
	v, ok := s.state.Secrets[repo][env][key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (s *Store) BatchGet(repo, env string, keys []string) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range keys {
		v, err := s.GetSecret(repo, env, k)
		if err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}

func (s *Store) ListSecretKeys(repo, env, prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []string{}
	envMap := s.state.Secrets[repo][env]
	for k := range envMap {
		if prefix != "" && !strings.HasPrefix(k, prefix) {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Store) PutToken(rec model.TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Tokens[rec.JTI] = rec
	return s.persistLocked()
}

func (s *Store) GetToken(jti string) (model.TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.state.Tokens[jti]
	if !ok {
		return model.TokenRecord{}, ErrNotFound
	}
	return rec, nil
}

func (s *Store) ListTokens(agentID string, activeOnly bool, now time.Time) []model.TokenRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.TokenRecord, 0, len(s.state.Tokens))
	for _, t := range s.state.Tokens {
		if agentID != "" && t.AgentID != agentID {
			continue
		}
		if activeOnly && (!t.RevokedAt.IsZero() || now.After(t.ExpiresAt)) {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	return out
}

func (s *Store) RevokeToken(jti, reason string, now time.Time) (model.TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Tokens[jti]
	if !ok {
		return model.TokenRecord{}, ErrNotFound
	}
	t.RevokedAt = now
	t.Reason = reason
	s.state.Tokens[jti] = t
	if err := s.persistLocked(); err != nil {
		return model.TokenRecord{}, err
	}
	return t, nil
}

func (s *Store) PutSession(sess model.RunSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Sessions[sess.ID] = sess
	return s.persistLocked()
}

func (s *Store) GetSession(id string) (model.RunSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.state.Sessions[id]
	if !ok {
		return model.RunSession{}, ErrNotFound
	}
	return sess, nil
}

func (s *Store) MarkSessionUsed(id string, now time.Time) (model.RunSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.state.Sessions[id]
	if !ok {
		return model.RunSession{}, ErrNotFound
	}
	sess.Materialized = true
	sess.UsedAt = now
	s.state.Sessions[id] = sess
	if err := s.persistLocked(); err != nil {
		return model.RunSession{}, err
	}
	return sess, nil
}

func (s *Store) CloseSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Sessions[id]; !ok {
		return ErrNotFound
	}
	delete(s.state.Sessions, id)
	return s.persistLocked()
}

func (s *Store) AddAudit(e model.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Audit = append(s.state.Audit, e)
	if len(s.state.Audit) > 5000 {
		s.state.Audit = s.state.Audit[len(s.state.Audit)-5000:]
	}
	return s.persistLocked()
}
