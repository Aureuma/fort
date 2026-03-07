package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr              string
	StatePath         string
	SigningKeyFile    string
	SigningKey        string
	SafeRoot          string
	KeyringPath       string
	ExtraPrivateKeys  []string
	TokenTTL          time.Duration
	RefreshSessionTTL time.Duration
	RunTTL            time.Duration
	SecretTTL         time.Duration
}

func FromEnv() (Config, error) {
	signingKeyRaw := strings.TrimSpace(os.Getenv("FORT_JWT_SIGNING_KEY"))
	signingKeyFile := strings.TrimSpace(os.Getenv("FORT_JWT_SIGNING_KEY_FILE"))
	if signingKeyRaw != "" {
		return Config{}, fmt.Errorf("FORT_JWT_SIGNING_KEY is disallowed; use FORT_JWT_SIGNING_KEY_FILE")
	}
	if signingKeyFile == "" {
		return Config{}, fmt.Errorf("FORT_JWT_SIGNING_KEY_FILE is required")
	}
	signingKey, err := readSecretFile(signingKeyFile)
	if err != nil {
		return Config{}, fmt.Errorf("read signing key file: %w", err)
	}
	cfg := Config{
		Addr:              env("FORT_ADDR", ":8088"),
		StatePath:         env("FORT_STATE_PATH", "./fort-state.json"),
		SigningKeyFile:    signingKeyFile,
		SigningKey:        signingKey,
		SafeRoot:          env("FORT_SAFE_ROOT", "/safe"),
		KeyringPath:       env("FORT_VAULT_KEYRING_FILE", defaultVaultKeyringPath()),
		ExtraPrivateKeys:  splitCSV(env("FORT_VAULT_PRIVATE_KEYS", "")),
		TokenTTL:          durationEnv("FORT_TOKEN_TTL", 15*time.Minute),
		RefreshSessionTTL: durationEnv("FORT_REFRESH_SESSION_TTL", 24*time.Hour),
		RunTTL:            durationEnv("FORT_RUN_TTL", 60*time.Second),
		SecretTTL:         durationEnv("FORT_SECRET_TTL", 120*time.Second),
	}
	if len(cfg.SigningKey) < 32 {
		return Config{}, fmt.Errorf("JWT signing key must be at least 32 characters")
	}
	switch strings.ToLower(cfg.SigningKey) {
	case "change-me", "dev-only-change-me":
		return Config{}, fmt.Errorf("JWT signing key uses an insecure placeholder value")
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

func readSecretFile(path string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return "", fmt.Errorf("secret path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("secret file permissions must be 0600 or stricter")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return value, nil
}

func splitCSV(raw string) []string {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func defaultVaultKeyringPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return home + "/.si/vault/si-vault-keyring.json"
}
