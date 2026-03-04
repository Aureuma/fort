package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr         string
	StatePath    string
	SigningKey   string
	BootstrapKey string
	TokenTTL     time.Duration
	RunTTL       time.Duration
	SecretTTL    time.Duration
}

func FromEnv() (Config, error) {
	cfg := Config{
		Addr:         env("FORT_ADDR", ":8088"),
		StatePath:    env("FORT_STATE_PATH", "./fort-state.json"),
		SigningKey:   env("FORT_JWT_SIGNING_KEY", "dev-only-change-me"),
		BootstrapKey: env("FORT_BOOTSTRAP_KEY", "fort-bootstrap-dev"),
		TokenTTL:     durationEnv("FORT_TOKEN_TTL", 15*time.Minute),
		RunTTL:       durationEnv("FORT_RUN_TTL", 60*time.Second),
		SecretTTL:    durationEnv("FORT_SECRET_TTL", 120*time.Second),
	}
	if strings.TrimSpace(cfg.SigningKey) == "" {
		return Config{}, fmt.Errorf("FORT_JWT_SIGNING_KEY is required")
	}
	return cfg, nil
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err == nil {
		return d
	}
	if i, convErr := strconv.Atoi(v); convErr == nil {
		return time.Duration(i) * time.Second
	}
	return fallback
}

func env(name, fallback string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	return v
}
