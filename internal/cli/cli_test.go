package cli

import (
	"os"
	"strings"
	"testing"
)

func TestSanitizeChildEnvRemovesTokenEntries(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"FORT_TOKEN=secret",
		"FORT_REFRESH_TOKEN=refresh",
		"FORT_TOKEN_FILE=/tmp/legacy-admin.token",
		"FORT_BOOTSTRAP_TOKEN_FILE=/tmp/admin.token",
		"FORT_TOKEN_PATH=/tmp/access.token",
		"FORT_REFRESH_TOKEN_PATH=/tmp/refresh.token",
		"FOO=bar",
	}
	out := sanitizeChildEnv(in)
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "FORT_TOKEN=") {
		t.Fatalf("FORT_TOKEN leaked: %q", joined)
	}
	if strings.Contains(joined, "FORT_REFRESH_TOKEN=") {
		t.Fatalf("FORT_REFRESH_TOKEN leaked: %q", joined)
	}
	if strings.Contains(joined, "FORT_BOOTSTRAP_TOKEN_FILE=") {
		t.Fatalf("FORT_BOOTSTRAP_TOKEN_FILE leaked: %q", joined)
	}
	if strings.Contains(joined, "FORT_TOKEN_FILE=") {
		t.Fatalf("FORT_TOKEN_FILE leaked: %q", joined)
	}
	if strings.Contains(joined, "FORT_TOKEN_PATH=") {
		t.Fatalf("FORT_TOKEN_PATH leaked: %q", joined)
	}
	if strings.Contains(joined, "FORT_REFRESH_TOKEN_PATH=") {
		t.Fatalf("FORT_REFRESH_TOKEN_PATH leaked: %q", joined)
	}
	if !strings.Contains(joined, "PATH=/usr/bin") || !strings.Contains(joined, "FOO=bar") {
		t.Fatalf("non-secret env entries were unexpectedly removed: %q", joined)
	}
}

func TestRunRejectsTokenFlag(t *testing.T) {
	err := run([]string{"--token", "abc", "doctor"})
	if err == nil {
		t.Fatalf("expected error for unsupported --token flag")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "usage: fort") {
		t.Fatalf("expected usage error, got: %v", err)
	}
}

func TestDefaultTokenFilePrefersBootstrapPath(t *testing.T) {
	t.Setenv("FORT_TOKEN_PATH", "")
	t.Setenv("FORT_BOOTSTRAP_TOKEN_FILE", "/tmp/bootstrap.token")
	t.Setenv("FORT_TOKEN_FILE", "/tmp/legacy.token")
	if got := defaultTokenFile(); got != "/tmp/bootstrap.token" {
		t.Fatalf("defaultTokenFile()=%q want /tmp/bootstrap.token", got)
	}
}

func TestRunRejectsTokenEnvValue(t *testing.T) {
	t.Setenv("FORT_HOST", "https://fort.example.test")
	t.Setenv("FORT_TOKEN", "legacy-token")
	err := run([]string{"doctor"})
	if err == nil {
		t.Fatalf("expected error when FORT_TOKEN is set")
	}
	if !strings.Contains(err.Error(), "FORT_TOKEN is deprecated and disallowed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRejectsRefreshTokenEnvValue(t *testing.T) {
	t.Setenv("FORT_HOST", "https://fort.example.test")
	_ = os.Unsetenv("FORT_TOKEN")
	t.Setenv("FORT_REFRESH_TOKEN", "legacy-refresh-token")
	err := run([]string{"doctor"})
	if err == nil {
		t.Fatalf("expected error when FORT_REFRESH_TOKEN is set")
	}
	if !strings.Contains(err.Error(), "FORT_REFRESH_TOKEN is deprecated and disallowed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
