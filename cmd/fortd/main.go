package main

import (
	"log"

	"fort/internal/config"
	"fort/internal/server"
	"fort/internal/store"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	st, err := store.New(cfg.StatePath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	if err := server.Run(cfg, st); err != nil {
		log.Fatalf("server: %v", err)
	}
}
