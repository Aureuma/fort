package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fort/internal/auth"
	"fort/internal/config"
	"fort/internal/model"
	"fort/internal/store"
	"fort/internal/vaultbridge"
)

type actorContext struct {
	AgentID  string
	TokenJTI string
}

type secretBackend interface {
	Get(repo, env, key string) (string, error)
	BatchGet(repo, env string, keys []string) (map[string]string, error)
	List(repo, env, prefix string) ([]string, error)
	Set(repo, env, key, value string) error
}

type handler struct {
	cfg   config.Config
	st    *store.Store
	vault secretBackend
	auth  *auth.Manager
	mux   *http.ServeMux
	now   func() time.Time
}

func newHandler(cfg config.Config, st *store.Store, vault secretBackend) http.Handler {
	h := &handler{
		cfg:   cfg,
		st:    st,
		vault: vault,
		auth:  &auth.Manager{SigningKey: []byte(cfg.SigningKey), Store: st},
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
	h.auth.Now = h.now
	h.mux = http.NewServeMux()
	h.routes()
	return h.mux
}

func (h *handler) routes() {
	h.mux.HandleFunc("GET /v1/health", h.handleHealth)
	h.mux.HandleFunc("GET /v1/ready", h.handleReady)

	h.mux.HandleFunc("POST /v1/auth/token", h.handleAuthToken)
	h.mux.HandleFunc("POST /v1/auth/session/open", h.handleAuthSessionOpen)
	h.mux.HandleFunc("POST /v1/auth/session/refresh", h.handleAuthSessionRefresh)
	h.mux.HandleFunc("POST /v1/auth/session/close", h.handleAuthSessionClose)
	h.mux.HandleFunc("GET /v1/auth/whoami", h.handleAuthWhoAmI)
	h.mux.HandleFunc("GET /v1/auth/list", h.handleAuthList)
	h.mux.HandleFunc("POST /v1/auth/revoke", h.handleAuthRevoke)

	h.mux.HandleFunc("POST /v1/secrets/get", h.handleSecretGet)
	h.mux.HandleFunc("POST /v1/secrets/batch-get", h.handleSecretBatchGet)
	h.mux.HandleFunc("POST /v1/secrets/list", h.handleSecretList)
	h.mux.HandleFunc("POST /v1/secrets/set", h.handleSecretSet)

	h.mux.HandleFunc("POST /v1/run/session/open", h.handleRunSessionOpen)
	h.mux.HandleFunc("POST /v1/run/session/materialize", h.handleRunSessionMaterialize)
	h.mux.HandleFunc("POST /v1/run/session/close", h.handleRunSessionClose)

	h.mux.HandleFunc("GET /v1/agents", h.handleAgentList)
	h.mux.HandleFunc("POST /v1/agents", h.handleAgentCreate)
	h.mux.HandleFunc("GET /v1/agents/{id}", h.handleAgentGet)
	h.mux.HandleFunc("POST /v1/agents/{id}/rotate", h.handleAgentRotate)
	h.mux.HandleFunc("POST /v1/agents/{id}/disable", h.handleAgentDisable)
	h.mux.HandleFunc("POST /v1/agents/{id}/enable", h.handleAgentEnable)
	h.mux.HandleFunc("DELETE /v1/agents/{id}", h.handleAgentRemove)

	h.mux.HandleFunc("GET /v1/agents/{id}/policy", h.handleAgentPolicyGet)
	h.mux.HandleFunc("PUT /v1/agents/{id}/policy", h.handleAgentPolicySet)
	h.mux.HandleFunc("POST /v1/agents/{id}/policy/add", h.handleAgentPolicyAdd)
	h.mux.HandleFunc("POST /v1/agents/{id}/policy/remove", h.handleAgentPolicyRemove)
	h.mux.HandleFunc("POST /v1/agents/{id}/policy/check", h.handleAgentPolicyCheck)
}

func (h *handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) handleReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) requireActor(w http.ResponseWriter, r *http.Request) (actorContext, bool) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return actorContext{}, false
	}
	claims, err := h.auth.Parse(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return actorContext{}, false
	}
	return actorContext{AgentID: claims.AgentID, TokenJTI: claims.ID}, true
}

func (h *handler) requireAdmin(w http.ResponseWriter, r *http.Request) (actorContext, bool) {
	actor, ok := h.requireActor(w, r)
	if !ok {
		return actorContext{}, false
	}
	if !h.isAdminAgent(actor.AgentID) {
		writeError(w, http.StatusForbidden, "admin access required")
		return actorContext{}, false
	}
	return actor, true
}

func (h *handler) isAdminAgent(agentID string) bool {
	policy, err := h.st.GetPolicy(agentID)
	if err != nil {
		return false
	}
	for _, b := range policy.Bindings {
		if b.Repo != "*" || b.Env != "*" {
			continue
		}
		for _, op := range b.Ops {
			if op == model.OpAny {
				return true
			}
		}
	}
	return false
}

func (h *handler) parseBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return errors.New("empty body")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return err
	}
	return nil
}

func randomID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return prefix + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return prefix + hex.EncodeToString(b)
}

func (h *handler) addAudit(actorID, action, repo, env, key, decision, reason string) {
	if strings.TrimSpace(action) == "" {
		return
	}
	_ = h.st.AddAudit(model.AuditEvent{
		ID:        randomID("aud_"),
		AgentID:   strings.TrimSpace(actorID),
		Action:    action,
		Repo:      repo,
		Env:       env,
		Key:       key,
		Decision:  decision,
		Reason:    reason,
		CreatedAt: h.now(),
	})
}

func parseOptionalBool(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "1" || v == "true" || v == "yes"
}

func parseTTL(ttlRaw string, ttlSeconds int64, fallback time.Duration) (time.Duration, error) {
	if ttlSeconds > 0 {
		return time.Duration(ttlSeconds) * time.Second, nil
	}
	ttlRaw = strings.TrimSpace(ttlRaw)
	if ttlRaw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(ttlRaw)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("ttl must be positive")
	}
	return d, nil
}

func sanitizeKeys(keys []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func (h *handler) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		AgentID    string `json:"agent_id"`
		TTL        string `json:"ttl"`
		TTLSeconds int64  `json:"ttl_seconds"`
		Audience   string `json:"aud"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.AgentID = strings.TrimSpace(req.AgentID)
	if req.AgentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	agent, err := h.st.GetAgent(req.AgentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if agent.Status != model.AgentStatusActive {
		writeError(w, http.StatusForbidden, "agent is disabled")
		return
	}
	ttl, err := parseTTL(req.TTL, req.TTLSeconds, h.cfg.TokenTTL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ttl")
		return
	}
	aud := strings.TrimSpace(req.Audience)
	if aud == "" {
		aud = "fort-api"
	}
	token, rec, err := h.auth.Issue(agent, ttl, aud)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue token failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"token_type": "Bearer",
		"agent_id":   rec.AgentID,
		"jti":        rec.JTI,
		"aud":        rec.Audience,
		"issued_at":  rec.IssuedAt,
		"expires_at": rec.ExpiresAt,
	})
}

func (h *handler) handleAuthSessionOpen(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		AgentID           string `json:"agent_id"`
		Audience          string `json:"aud"`
		AccessTTL         string `json:"access_ttl"`
		AccessTTLSeconds  int64  `json:"access_ttl_seconds"`
		RefreshTTL        string `json:"refresh_ttl"`
		RefreshTTLSeconds int64  `json:"refresh_ttl_seconds"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.AgentID = strings.TrimSpace(req.AgentID)
	if req.AgentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	agent, err := h.st.GetAgent(req.AgentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if agent.Status != model.AgentStatusActive {
		writeError(w, http.StatusForbidden, "agent is disabled")
		return
	}
	accessTTL, err := parseTTL(req.AccessTTL, req.AccessTTLSeconds, h.cfg.TokenTTL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid access ttl")
		return
	}
	refreshTTL, err := parseTTL(req.RefreshTTL, req.RefreshTTLSeconds, h.cfg.RefreshSessionTTL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid refresh ttl")
		return
	}
	aud := strings.TrimSpace(req.Audience)
	if aud == "" {
		aud = "fort-api"
	}
	token, rec, session, refreshToken, err := h.auth.OpenRefreshSession(agent, accessTTL, refreshTTL, aud)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "open session failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":         session.ID,
		"agent_id":           rec.AgentID,
		"aud":                rec.Audience,
		"token_type":         "Bearer",
		"access_token":       token,
		"access_jti":         rec.JTI,
		"access_issued_at":   rec.IssuedAt,
		"access_expires_at":  rec.ExpiresAt,
		"refresh_token":      refreshToken,
		"refresh_expires_at": session.RefreshExpiresAt,
	})
}

func (h *handler) handleAuthSessionRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.RefreshToken = strings.TrimSpace(req.RefreshToken)
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}
	token, rec, session, refreshToken, err := h.auth.RefreshByToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthorized) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeError(w, http.StatusInternalServerError, "refresh failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":         session.ID,
		"agent_id":           rec.AgentID,
		"aud":                rec.Audience,
		"token_type":         "Bearer",
		"access_token":       token,
		"access_jti":         rec.JTI,
		"access_issued_at":   rec.IssuedAt,
		"access_expires_at":  rec.ExpiresAt,
		"refresh_token":      refreshToken,
		"refresh_expires_at": session.RefreshExpiresAt,
	})
}

func (h *handler) handleAuthSessionClose(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID    string `json:"session_id"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sessionID := strings.TrimSpace(req.SessionID)
	refreshToken := strings.TrimSpace(req.RefreshToken)
	if sessionID == "" && refreshToken == "" {
		writeError(w, http.StatusBadRequest, "session_id or refresh_token is required")
		return
	}
	if refreshToken != "" {
		sess, err := h.auth.CloseRefreshSessionByToken(refreshToken)
		if err != nil {
			if errors.Is(err, auth.ErrUnauthorized) {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			writeError(w, http.StatusInternalServerError, "close session failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session_id": sess.ID})
		return
	}

	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	sess, err := h.st.GetRefreshSession(sessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if actor.AgentID != sess.AgentID && !h.isAdminAgent(actor.AgentID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, err := h.auth.CloseRefreshSessionByID(sessionID); err != nil {
		if errors.Is(err, auth.ErrUnauthorized) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeError(w, http.StatusInternalServerError, "close session failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session_id": sessionID})
}

func (h *handler) handleAuthWhoAmI(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	agent, err := h.st.GetAgent(actor.AgentID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agent":     agent,
		"token_jti": actor.TokenJTI,
	})
}

func (h *handler) handleAuthList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	activeOnly := parseOptionalBool(r.URL.Query().Get("active_only"))
	writeJSON(w, http.StatusOK, map[string]any{
		"tokens": h.auth.List(agentID, activeOnly),
	})
}

func (h *handler) handleAuthRevoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		JTI    string `json:"jti"`
		Reason string `json:"reason"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rec, err := h.auth.Revoke(strings.TrimSpace(req.JTI), strings.TrimSpace(req.Reason))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": rec})
}

func (h *handler) handleSecretGet(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	var req struct {
		Repo string `json:"repo"`
		Env  string `json:"env"`
		Key  string `json:"key"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	repo, env, key := strings.TrimSpace(req.Repo), strings.TrimSpace(req.Env), strings.TrimSpace(req.Key)
	if repo == "" || env == "" || key == "" {
		writeError(w, http.StatusBadRequest, "repo, env, key are required")
		return
	}
	if allowed, reason := h.st.CheckPermission(actor.AgentID, repo, env, model.OpGet); !allowed {
		h.addAudit(actor.AgentID, "secret_get", repo, env, key, "deny", reason)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	value, err := h.vault.Get(repo, env, key)
	if err != nil {
		if errors.Is(err, vaultbridge.ErrNotFound) {
			h.addAudit(actor.AgentID, "secret_get", repo, env, key, "deny", "key_not_found")
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		if errors.Is(err, vaultbridge.ErrInvalid) {
			writeError(w, http.StatusBadRequest, "invalid secret target")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get secret")
		return
	}
	h.addAudit(actor.AgentID, "secret_get", repo, env, key, "allow", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"value":        value,
		"ttl_seconds":  int(h.cfg.SecretTTL.Seconds()),
		"version":      1,
		"retrieved_at": h.now(),
	})
}

func (h *handler) handleSecretBatchGet(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	var req struct {
		Repo string   `json:"repo"`
		Env  string   `json:"env"`
		Keys []string `json:"keys"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	repo, env := strings.TrimSpace(req.Repo), strings.TrimSpace(req.Env)
	keys := sanitizeKeys(req.Keys)
	if repo == "" || env == "" || len(keys) == 0 {
		writeError(w, http.StatusBadRequest, "repo, env, keys are required")
		return
	}
	if allowed, reason := h.st.CheckPermission(actor.AgentID, repo, env, model.OpBatchGet); !allowed {
		h.addAudit(actor.AgentID, "secret_batch_get", repo, env, "", "deny", reason)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	values, err := h.vault.BatchGet(repo, env, keys)
	if err != nil {
		if errors.Is(err, vaultbridge.ErrNotFound) {
			h.addAudit(actor.AgentID, "secret_batch_get", repo, env, "", "deny", "key_not_found")
			writeError(w, http.StatusNotFound, "one or more secrets not found")
			return
		}
		if errors.Is(err, vaultbridge.ErrInvalid) {
			writeError(w, http.StatusBadRequest, "invalid secret target")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to batch get")
		return
	}
	h.addAudit(actor.AgentID, "secret_batch_get", repo, env, "", "allow", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"values":       values,
		"ttl_seconds":  int(h.cfg.SecretTTL.Seconds()),
		"retrieved_at": h.now(),
	})
}

func (h *handler) handleSecretList(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	var req struct {
		Repo   string `json:"repo"`
		Env    string `json:"env"`
		Prefix string `json:"prefix"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	repo, env := strings.TrimSpace(req.Repo), strings.TrimSpace(req.Env)
	prefix := strings.TrimSpace(req.Prefix)
	if repo == "" || env == "" {
		writeError(w, http.StatusBadRequest, "repo and env are required")
		return
	}
	if allowed, reason := h.st.CheckPermission(actor.AgentID, repo, env, model.OpList); !allowed {
		h.addAudit(actor.AgentID, "secret_list", repo, env, "", "deny", reason)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	keys, err := h.vault.List(repo, env, prefix)
	if err != nil {
		if errors.Is(err, vaultbridge.ErrInvalid) {
			writeError(w, http.StatusBadRequest, "invalid secret target")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to list")
		return
	}
	h.addAudit(actor.AgentID, "secret_list", repo, env, "", "allow", "")
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (h *handler) handleSecretSet(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	var req struct {
		Repo       string `json:"repo"`
		Env        string `json:"env"`
		Key        string `json:"key"`
		Value      string `json:"value"`
		CASVersion int64  `json:"cas_version"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	repo, env, key := strings.TrimSpace(req.Repo), strings.TrimSpace(req.Env), strings.TrimSpace(req.Key)
	if repo == "" || env == "" || key == "" {
		writeError(w, http.StatusBadRequest, "repo, env, key are required")
		return
	}
	if allowed, reason := h.st.CheckPermission(actor.AgentID, repo, env, model.OpSet); !allowed {
		h.addAudit(actor.AgentID, "secret_set", repo, env, key, "deny", reason)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.vault.Set(repo, env, key, req.Value); err != nil {
		if errors.Is(err, vaultbridge.ErrInvalid) {
			writeError(w, http.StatusBadRequest, "invalid secret target")
			return
		}
		writeError(w, http.StatusInternalServerError, "set failed")
		return
	}
	h.addAudit(actor.AgentID, "secret_set", repo, env, key, "allow", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": 1})
}

func (h *handler) handleRunSessionOpen(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	var req struct {
		Repo       string   `json:"repo"`
		Env        string   `json:"env"`
		Keys       []string `json:"keys"`
		Mode       string   `json:"mode"`
		TTLSeconds int64    `json:"ttl_seconds"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	repo, env := strings.TrimSpace(req.Repo), strings.TrimSpace(req.Env)
	keys := sanitizeKeys(req.Keys)
	mode := strings.TrimSpace(strings.ToLower(req.Mode))
	if mode == "" {
		mode = "files"
	}
	if mode != "files" && mode != "env" {
		writeError(w, http.StatusBadRequest, "mode must be files or env")
		return
	}
	if repo == "" || env == "" || len(keys) == 0 {
		writeError(w, http.StatusBadRequest, "repo, env, keys are required")
		return
	}
	if allowed, reason := h.st.CheckPermission(actor.AgentID, repo, env, model.OpRun); !allowed {
		h.addAudit(actor.AgentID, "run_open", repo, env, "", "deny", reason)
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	ttl := h.cfg.RunTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	sess := model.RunSession{
		ID:           randomID("sess_"),
		AgentID:      actor.AgentID,
		Repo:         repo,
		Env:          env,
		Keys:         keys,
		Mode:         mode,
		OneTimeToken: randomID("wrp_"),
		ExpiresAt:    h.now().Add(ttl),
		CreatedAt:    h.now(),
	}
	if err := h.st.PutSession(sess); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open session")
		return
	}
	h.addAudit(actor.AgentID, "run_open", repo, env, "", "allow", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":     sess.ID,
		"one_time_token": sess.OneTimeToken,
		"expires_at":     sess.ExpiresAt,
	})
}

func (h *handler) handleRunSessionMaterialize(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	var req struct {
		SessionID    string `json:"session_id"`
		OneTimeToken string `json:"one_time_token"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sessionID := strings.TrimSpace(req.SessionID)
	oneTimeToken := strings.TrimSpace(req.OneTimeToken)
	if sessionID == "" || oneTimeToken == "" {
		writeError(w, http.StatusBadRequest, "session_id and one_time_token are required")
		return
	}
	sess, err := h.st.GetSession(sessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if actor.AgentID != sess.AgentID && !h.isAdminAgent(actor.AgentID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.now().After(sess.ExpiresAt) {
		h.addAudit(actor.AgentID, "run_materialize", sess.Repo, sess.Env, "", "deny", "session_expired")
		writeError(w, http.StatusGone, "session expired")
		return
	}
	if subtle.ConstantTimeCompare([]byte(oneTimeToken), []byte(sess.OneTimeToken)) != 1 {
		h.addAudit(actor.AgentID, "run_materialize", sess.Repo, sess.Env, "", "deny", "invalid_one_time_token")
		writeError(w, http.StatusForbidden, "invalid one-time token")
		return
	}
	if _, err := h.st.MarkSessionUsed(sess.ID, h.now()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "session already materialized")
			return
		}
		writeError(w, http.StatusInternalServerError, "mark used failed")
		return
	}
	values, err := h.vault.BatchGet(sess.Repo, sess.Env, sess.Keys)
	if err != nil {
		writeError(w, http.StatusNotFound, "one or more secrets not found")
		return
	}
	h.addAudit(actor.AgentID, "run_materialize", sess.Repo, sess.Env, "", "allow", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":       sess.Mode,
		"values":     values,
		"expires_at": sess.ExpiresAt,
	})
}

func (h *handler) handleRunSessionClose(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}
	sess, err := h.st.GetSession(sessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if actor.AgentID != sess.AgentID && !h.isAdminAgent(actor.AgentID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := h.st.CloseSession(sessionID); err != nil {
		writeError(w, http.StatusInternalServerError, "close failed")
		return
	}
	h.addAudit(actor.AgentID, "run_close", sess.Repo, sess.Env, "", "allow", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) handleAgentCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		ID     string            `json:"id"`
		Type   model.AgentType   `json:"type"`
		Status model.AgentStatus `json:"status"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agent, err := h.st.CreateAgent(req.ID, req.Type, req.Status, h.now())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "agent already exists")
		case errors.Is(err, store.ErrInvalid):
			writeError(w, http.StatusBadRequest, "invalid agent values")
		default:
			writeError(w, http.StatusInternalServerError, "create failed")
		}
		return
	}
	writeJSON(w, http.StatusCreated, agent)
}

func (h *handler) handleAgentList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	filterType := model.AgentType(strings.TrimSpace(r.URL.Query().Get("type")))
	filterStatus := model.AgentStatus(strings.TrimSpace(r.URL.Query().Get("status")))
	writeJSON(w, http.StatusOK, map[string]any{"agents": h.st.ListAgents(filterType, filterStatus)})
}

func (h *handler) handleAgentGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	actor, ok := h.requireActor(w, r)
	if !ok {
		return
	}
	if actor.AgentID != id && !h.isAdminAgent(actor.AgentID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	agent, err := h.st.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *handler) handleAgentRotate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	agent, revokedTokens, revokedSessions, err := h.st.RotateAgentCredentials(strings.TrimSpace(r.PathValue("id")), h.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "rotate failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agent":                  agent,
		"revoked_token_count":    revokedTokens,
		"revoked_session_count":  revokedSessions,
		"credential_version":     agent.CredentialVersion,
		"credentials_rotated_at": agent.UpdatedAt,
	})
}

func (h *handler) handleAgentDisable(w http.ResponseWriter, r *http.Request) {
	h.handleAgentSetStatus(w, r, model.AgentStatusDisabled)
}

func (h *handler) handleAgentEnable(w http.ResponseWriter, r *http.Request) {
	h.handleAgentSetStatus(w, r, model.AgentStatusActive)
}

func (h *handler) handleAgentSetStatus(w http.ResponseWriter, r *http.Request, status model.AgentStatus) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	agent, err := h.st.SetAgentStatus(strings.TrimSpace(r.PathValue("id")), status, h.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "status update failed")
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *handler) handleAgentRemove(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	if err := h.st.RemoveAgent(strings.TrimSpace(r.PathValue("id"))); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "remove failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *handler) handleAgentPolicyGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	agentID := strings.TrimSpace(r.PathValue("id"))
	policy, err := h.st.GetPolicy(agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *handler) handleAgentPolicySet(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		Bindings []model.Binding `json:"bindings"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	policy, err := h.st.SetPolicy(strings.TrimSpace(r.PathValue("id")), req.Bindings, h.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "set policy failed")
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *handler) handleAgentPolicyAdd(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		Binding model.Binding `json:"binding"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	policy, err := h.st.AddBinding(strings.TrimSpace(r.PathValue("id")), req.Binding, h.now())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "agent not found")
		case errors.Is(err, store.ErrInvalid):
			writeError(w, http.StatusBadRequest, "invalid binding")
		default:
			writeError(w, http.StatusInternalServerError, "add binding failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *handler) handleAgentPolicyRemove(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		Binding model.Binding `json:"binding"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	policy, err := h.st.RemoveBinding(strings.TrimSpace(r.PathValue("id")), req.Binding, h.now())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "agent not found")
		case errors.Is(err, store.ErrInvalid):
			writeError(w, http.StatusBadRequest, "invalid binding")
		default:
			writeError(w, http.StatusInternalServerError, "remove binding failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *handler) handleAgentPolicyCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		Repo string          `json:"repo"`
		Env  string          `json:"env"`
		Op   model.Operation `json:"op"`
	}
	if err := h.parseBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agentID := strings.TrimSpace(r.PathValue("id"))
	allowed, reason := h.st.CheckPermission(agentID, strings.TrimSpace(req.Repo), strings.TrimSpace(req.Env), req.Op)
	writeJSON(w, http.StatusOK, map[string]any{"allowed": allowed, "reason": reason})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
