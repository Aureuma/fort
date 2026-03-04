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
	ErrInvalid  = errors.New("invalid")
)

type persistentState struct {
	Agents   map[string]model.Agent                  `json:"agents"`
	Policies map[string]model.Policy                 `json:"policies"`
	Secrets  map[string]map[string]map[string]string `json:"secrets"`
	Tokens   map[string]model.TokenRecord            `json:"tokens"`
	Sessions map[string]model.RunSession             `json:"sessions"`
	Audit    []model.AuditEvent                      `json:"audit"`
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
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
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
	if st.Audit == nil {
		st.Audit = []model.AuditEvent{}
	}
	s.state = st
	return nil
}

func (s *Store) persistLocked() error {
	if strings.TrimSpace(s.path) == "" {
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

func validAgentType(t model.AgentType) bool {
	switch t {
	case model.AgentTypeWorkload, model.AgentTypeUser, model.AgentTypeCI:
		return true
	default:
		return false
	}
}

func validAgentStatus(status model.AgentStatus) bool {
	switch status {
	case model.AgentStatusActive, model.AgentStatusDisabled:
		return true
	default:
		return false
	}
}

func (s *Store) CreateAgent(id string, t model.AgentType, status model.AgentStatus, now time.Time) (model.Agent, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return model.Agent{}, ErrInvalid
	}
	if t == "" {
		t = model.AgentTypeWorkload
	}
	if status == "" {
		status = model.AgentStatusActive
	}
	if !validAgentType(t) || !validAgentStatus(status) {
		return model.Agent{}, ErrInvalid
	}

	now = now.UTC()
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
	if !validAgentStatus(status) {
		return model.Agent{}, ErrInvalid
	}
	now = now.UTC()
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
	now = now.UTC()
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
	for jti, tok := range s.state.Tokens {
		if tok.AgentID == id {
			delete(s.state.Tokens, jti)
		}
	}
	for sessID, sess := range s.state.Sessions {
		if sess.AgentID == id {
			delete(s.state.Sessions, sessID)
		}
	}
	return s.persistLocked()
}

func normalizeOps(ops []model.Operation) []model.Operation {
	seen := map[model.Operation]struct{}{}
	for _, op := range ops {
		op = model.NormalizeOperation(model.Operation(strings.TrimSpace(string(op))))
		if !model.IsSupportedOperation(op) {
			continue
		}
		if op == model.OpAny {
			return []model.Operation{model.OpAny}
		}
		seen[op] = struct{}{}
	}
	out := make([]model.Operation, 0, len(seen))
	for op := range seen {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func normalizeBinding(binding model.Binding) (model.Binding, bool) {
	binding.Repo = strings.TrimSpace(binding.Repo)
	binding.Env = strings.TrimSpace(binding.Env)
	binding.Ops = normalizeOps(binding.Ops)
	if binding.Repo == "" || binding.Env == "" || len(binding.Ops) == 0 {
		return model.Binding{}, false
	}
	return binding, true
}

func bindingKey(binding model.Binding) string {
	opParts := make([]string, 0, len(binding.Ops))
	for _, op := range binding.Ops {
		opParts = append(opParts, string(op))
	}
	return binding.Repo + "|" + binding.Env + "|" + strings.Join(opParts, ",")
}

func sortBindings(bindings []model.Binding) {
	sort.Slice(bindings, func(i, j int) bool {
		a := bindingKey(bindings[i])
		b := bindingKey(bindings[j])
		return a < b
	})
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
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.state.Agents[agentID]; !ok {
		return model.Policy{}, ErrNotFound
	}

	norm := make([]model.Binding, 0, len(bindings))
	seen := map[string]struct{}{}
	for _, binding := range bindings {
		normalized, ok := normalizeBinding(binding)
		if !ok {
			continue
		}
		k := bindingKey(normalized)
		if _, exists := seen[k]; exists {
			continue
		}
		seen[k] = struct{}{}
		norm = append(norm, normalized)
	}
	sortBindings(norm)

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
	if _, err := s.GetAgent(agentID); err != nil {
		return model.Policy{}, err
	}
	normalized, ok := normalizeBinding(binding)
	if !ok {
		return model.Policy{}, ErrInvalid
	}
	p, err := s.GetPolicy(agentID)
	if err != nil {
		return model.Policy{}, err
	}
	for _, b := range p.Bindings {
		if sameBinding(b, normalized) {
			return p, nil
		}
	}
	p.Bindings = append(p.Bindings, normalized)
	return s.SetPolicy(agentID, p.Bindings, now)
}

func (s *Store) RemoveBinding(agentID string, binding model.Binding, now time.Time) (model.Policy, error) {
	if _, err := s.GetAgent(agentID); err != nil {
		return model.Policy{}, err
	}
	normalized, ok := normalizeBinding(binding)
	if !ok {
		return model.Policy{}, ErrInvalid
	}
	p, err := s.GetPolicy(agentID)
	if err != nil {
		return model.Policy{}, err
	}
	out := make([]model.Binding, 0, len(p.Bindings))
	for _, b := range p.Bindings {
		if sameBinding(b, normalized) {
			continue
		}
		out = append(out, b)
	}
	return s.SetPolicy(agentID, out, now)
}

func matchPattern(pattern, value string) bool {
	return pattern == "*" || pattern == value
}

func (s *Store) CheckPermission(agentID, repo, env string, op model.Operation) (bool, string) {
	a, err := s.GetAgent(agentID)
	if err != nil {
		return false, "agent_not_found"
	}
	if a.Status != model.AgentStatusActive {
		return false, "agent_disabled"
	}

	op = model.NormalizeOperation(op)
	if !model.IsSupportedOperation(op) {
		return false, "unsupported_op"
	}
	p, _ := s.GetPolicy(agentID)
	for _, b := range p.Bindings {
		if !matchPattern(b.Repo, repo) || !matchPattern(b.Env, env) {
			continue
		}
		for _, allowed := range b.Ops {
			if allowed == model.OpAny || model.NormalizeOperation(allowed) == op {
				return true, "allowed"
			}
		}
	}
	return false, "no_matching_binding"
}

func (s *Store) SetSecret(repo, env, key, value string) error {
	repo = strings.TrimSpace(repo)
	env = strings.TrimSpace(env)
	key = strings.TrimSpace(key)
	if repo == "" || env == "" || key == "" {
		return ErrInvalid
	}

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
	repo = strings.TrimSpace(repo)
	env = strings.TrimSpace(env)
	key = strings.TrimSpace(key)
	if repo == "" || env == "" || key == "" {
		return "", ErrInvalid
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	envMap, ok := s.state.Secrets[repo]
	if !ok {
		return "", ErrNotFound
	}
	keys, ok := envMap[env]
	if !ok {
		return "", ErrNotFound
	}
	v, ok := keys[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (s *Store) BatchGet(repo, env string, keys []string) (map[string]string, error) {
	out := make(map[string]string, len(keys))
	for _, key := range keys {
		v, err := s.GetSecret(repo, env, key)
		if err != nil {
			return nil, err
		}
		out[strings.TrimSpace(key)] = v
	}
	return out, nil
}

func (s *Store) ListSecretKeys(repo, env, prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	envMap, ok := s.state.Secrets[repo]
	if !ok {
		return []string{}
	}
	keyMap, ok := envMap[env]
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(keyMap))
	for key := range keyMap {
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func (s *Store) PutToken(rec model.TokenRecord) error {
	if strings.TrimSpace(rec.JTI) == "" {
		return ErrInvalid
	}
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
	now = now.UTC()
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuedAt.Equal(out[j].IssuedAt) {
			return out[i].JTI < out[j].JTI
		}
		return out[i].IssuedAt.After(out[j].IssuedAt)
	})
	return out
}

func (s *Store) RevokeToken(jti, reason string, now time.Time) (model.TokenRecord, error) {
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.state.Tokens[jti]
	if !ok {
		return model.TokenRecord{}, ErrNotFound
	}
	if t.RevokedAt.IsZero() {
		t.RevokedAt = now
	}
	t.Reason = strings.TrimSpace(reason)
	s.state.Tokens[jti] = t
	if err := s.persistLocked(); err != nil {
		return model.TokenRecord{}, err
	}
	return t, nil
}

func (s *Store) PutSession(sess model.RunSession) error {
	if strings.TrimSpace(sess.ID) == "" {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.state.Sessions[sess.ID]; exists {
		return ErrConflict
	}
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
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.state.Sessions[id]
	if !ok {
		return model.RunSession{}, ErrNotFound
	}
	if sess.Materialized {
		return model.RunSession{}, ErrConflict
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

	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	s.state.Audit = append(s.state.Audit, e)
	if len(s.state.Audit) > 5000 {
		s.state.Audit = s.state.Audit[len(s.state.Audit)-5000:]
	}
	return s.persistLocked()
}

func (s *Store) ListAudit(limit int) []model.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.state.Audit) {
		limit = len(s.state.Audit)
	}
	out := make([]model.AuditEvent, 0, limit)
	for i := len(s.state.Audit) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.state.Audit[i])
	}
	return out
}
