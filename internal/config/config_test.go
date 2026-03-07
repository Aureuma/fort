package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSigningKeyFile(t *testing.T, mode os.FileMode, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwt-signing.key")
	if err := os.WriteFile(path, []byte(value), mode); err != nil {
		t.Fatalf("write signing key file: %v", err)
	}
	return path
}

func TestFromEnvRequiresSigningKeyFile(t *testing.T) {
	t.Setenv("FORT_JWT_SIGNING_KEY", "")
	t.Setenv("FORT_JWT_SIGNING_KEY_FILE", "")
	if _, err := FromEnv(); err == nil {
		t.Fatalf("expected missing signing key file to fail")
	}
}

func TestFromEnvRejectsInlineSigningKey(t *testing.T) {
	t.Setenv("FORT_JWT_SIGNING_KEY", "01234567890123456789012345678901")
	t.Setenv("FORT_JWT_SIGNING_KEY_FILE", "")
	if _, err := FromEnv(); err == nil {
		t.Fatalf("expected inline signing key to fail")
	}
}

func TestFromEnvRejectsWeakSigningKeyFromFile(t *testing.T) {
	path := writeSigningKeyFile(t, 0o600, "too-short")
	t.Setenv("FORT_JWT_SIGNING_KEY", "")
	t.Setenv("FORT_JWT_SIGNING_KEY_FILE", path)
	if _, err := FromEnv(); err == nil {
		t.Fatalf("expected short signing key to fail")
	}
}

func TestFromEnvRejectsBroadSigningKeyFilePermissions(t *testing.T) {
	path := writeSigningKeyFile(t, 0o644, "01234567890123456789012345678901")
	t.Setenv("FORT_JWT_SIGNING_KEY", "")
	t.Setenv("FORT_JWT_SIGNING_KEY_FILE", path)
	if _, err := FromEnv(); err == nil {
		t.Fatalf("expected broad permissions to fail")
	}
}

func TestFromEnvAcceptsStrongSigningKeyFile(t *testing.T) {
	path := writeSigningKeyFile(t, 0o600, "01234567890123456789012345678901")
	t.Setenv("FORT_JWT_SIGNING_KEY", "")
	t.Setenv("FORT_JWT_SIGNING_KEY_FILE", path)
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("expected strong signing key to pass, got %v", err)
	}
	if cfg.SigningKey != "01234567890123456789012345678901" {
		t.Fatalf("unexpected signing key in config")
	}
	if cfg.SigningKeyFile != path {
		t.Fatalf("unexpected signing key file path in config")
	}
}
