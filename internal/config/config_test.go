package config

import "testing"

func TestFromEnvRequiresExplicitSigningKey(t *testing.T) {
	t.Setenv("FORT_JWT_SIGNING_KEY", "")
	if _, err := FromEnv(); err == nil {
		t.Fatalf("expected missing signing key to fail")
	}
}

func TestFromEnvRejectsWeakSigningKey(t *testing.T) {
	t.Setenv("FORT_JWT_SIGNING_KEY", "too-short")
	if _, err := FromEnv(); err == nil {
		t.Fatalf("expected short signing key to fail")
	}
}

func TestFromEnvAcceptsStrongSigningKey(t *testing.T) {
	t.Setenv("FORT_JWT_SIGNING_KEY", "01234567890123456789012345678901")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("expected strong signing key to pass, got %v", err)
	}
	if cfg.SigningKey != "01234567890123456789012345678901" {
		t.Fatalf("unexpected signing key in config")
	}
}
