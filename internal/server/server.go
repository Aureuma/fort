package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"fort/internal/config"
	"fort/internal/store"
)

func Run(cfg config.Config, st *store.Store) error {
	h := newHandler(cfg, st)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Printf("fortd listening on %s\n", cfg.Addr)
	return srv.ListenAndServe()
}

func Shutdown(ctx context.Context, srv *http.Server) error {
	return srv.Shutdown(ctx)
}
