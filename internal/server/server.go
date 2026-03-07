package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"fort/internal/config"
	"fort/internal/store"
	"fort/internal/vaultbridge"
)

func Run(cfg config.Config, st *store.Store) error {
	backend, err := vaultbridge.New(vaultbridge.Config{
		SafeRoot:      cfg.SafeRoot,
		KeyringPath:   cfg.KeyringPath,
		ExtraPrivKeys: cfg.ExtraPrivateKeys,
	})
	if err != nil {
		return err
	}
	h := newHandler(cfg, st, backend)
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
