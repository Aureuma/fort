package server

import (
	"encoding/json"
	"net/http"

	"fort/internal/auth"
	"fort/internal/config"
	"fort/internal/store"
)

type handler struct {
	cfg  config.Config
	st   *store.Store
	auth *auth.Manager
	mux  *http.ServeMux
}

func newHandler(cfg config.Config, st *store.Store) http.Handler {
	h := &handler{cfg: cfg, st: st}
	h.auth = &auth.Manager{SigningKey: []byte(cfg.SigningKey), Store: st}
	h.mux = http.NewServeMux()
	h.routes()
	return h.mux
}

func (h *handler) routes() {
	h.mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	h.mux.HandleFunc("/v1/ready", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
