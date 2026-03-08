package vaultbridge

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func writeKeyring(t *testing.T, path string, entries map[string]any) {
	t.Helper()
	doc := map[string]any{
		"entries": entries,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal keyring: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}
}

func TestListReturnsNotFoundWhenEnvFileMissing(t *testing.T) {
	tmp := t.TempDir()
	safeRoot := filepath.Join(tmp, "safe-root")
	if err := os.MkdirAll(filepath.Join(safeRoot, "safe"), 0o755); err != nil {
		t.Fatalf("mkdir safe root: %v", err)
	}
	keyring := filepath.Join(tmp, "keyring.json")
	writeKeyring(t, keyring, map[string]any{
		"safe/dev": map[string]any{
			"repo": "safe",
			"env":  "dev",
		},
	})
	backend, err := New(Config{
		SafeRoot:    safeRoot,
		KeyringPath: keyring,
	})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	if _, err := backend.List("safe", "dev", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing env file, got %v", err)
	}
}

func TestListReturnsNotFoundWhenKeyringEntryMissing(t *testing.T) {
	tmp := t.TempDir()
	safeRoot := filepath.Join(tmp, "safe-root")
	repoDir := filepath.Join(safeRoot, "safe")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("mkdir repo dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".env.dev"), []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	keyring := filepath.Join(tmp, "keyring.json")
	writeKeyring(t, keyring, map[string]any{
		"safe/prod": map[string]any{
			"repo": "safe",
			"env":  "prod",
		},
	})
	backend, err := New(Config{
		SafeRoot:    safeRoot,
		KeyringPath: keyring,
	})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	if _, err := backend.List("safe", "dev", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing keyring entry, got %v", err)
	}
}

func TestWriteDotenvPreservesOwnerAndMode(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".env.dev")
	if err := os.WriteFile(path, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("seed env file: %v", err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat before: %v", err)
	}
	beforeStat, ok := beforeInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("unexpected stat type")
	}

	if err := writeDotenv(path, map[string]string{"BAR": "baz"}); err != nil {
		t.Fatalf("writeDotenv: %v", err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	afterStat, ok := afterInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("unexpected stat type")
	}
	if beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid {
		t.Fatalf("owner changed: before=%d:%d after=%d:%d", beforeStat.Uid, beforeStat.Gid, afterStat.Uid, afterStat.Gid)
	}
	if got := afterInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("unexpected mode: got %o want 600", got)
	}
}

func TestListRejectsBroadEnvFilePermissions(t *testing.T) {
	tmp := t.TempDir()
	safeRoot := filepath.Join(tmp, "safe-root")
	repoDir := filepath.Join(safeRoot, "safe")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("mkdir repo dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".env.dev"), []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	keyring := filepath.Join(tmp, "keyring.json")
	writeKeyring(t, keyring, map[string]any{
		"safe/dev": map[string]any{
			"repo": "safe",
			"env":  "dev",
		},
	})
	backend, err := New(Config{
		SafeRoot:    safeRoot,
		KeyringPath: keyring,
	})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	_, err = backend.List("safe", "dev", "")
	if err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected strict permission error, got %v", err)
	}
}

func TestLoadKeyringEntryRejectsKeypairSprawl(t *testing.T) {
	tmp := t.TempDir()
	safeRoot := filepath.Join(tmp, "safe-root")
	keyring := filepath.Join(tmp, "keyring.json")
	writeKeyring(t, keyring, map[string]any{
		"safe/dev": map[string]any{
			"repo":        "safe",
			"env":         "dev",
			"public_key":  "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		"safe/prod": map[string]any{
			"repo":        "safe",
			"env":         "prod",
			"public_key":  "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"private_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	})
	backend, err := New(Config{SafeRoot: safeRoot, KeyringPath: keyring})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	if _, err := backend.loadKeyringEntry("safe", "dev"); !errors.Is(err, ErrKeySprawl) {
		t.Fatalf("expected ErrKeySprawl, got %v", err)
	}
}

func TestLoadKeyringEntryRejectsBackupPrivateKeys(t *testing.T) {
	tmp := t.TempDir()
	safeRoot := filepath.Join(tmp, "safe-root")
	keyring := filepath.Join(tmp, "keyring.json")
	writeKeyring(t, keyring, map[string]any{
		"safe/dev": map[string]any{
			"repo":                "safe",
			"env":                 "dev",
			"public_key":          "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"private_key":         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"backup_private_keys": []string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
	})
	backend, err := New(Config{SafeRoot: safeRoot, KeyringPath: keyring})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	if _, err := backend.loadKeyringEntry("safe", "dev"); !errors.Is(err, ErrKeySprawl) {
		t.Fatalf("expected ErrKeySprawl, got %v", err)
	}
}

func TestLoadKeyringEntryAllowsSingleCanonicalKeypair(t *testing.T) {
	tmp := t.TempDir()
	safeRoot := filepath.Join(tmp, "safe-root")
	keyring := filepath.Join(tmp, "keyring.json")
	writeKeyring(t, keyring, map[string]any{
		"safe/dev": map[string]any{
			"repo":        "safe",
			"env":         "dev",
			"public_key":  "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		"safe/prod": map[string]any{
			"repo":        "safe",
			"env":         "prod",
			"public_key":  "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	})
	backend, err := New(Config{SafeRoot: safeRoot, KeyringPath: keyring})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	entry, err := backend.loadKeyringEntry("safe", "prod")
	if err != nil {
		t.Fatalf("loadKeyringEntry: %v", err)
	}
	if got := strings.TrimSpace(entry.PublicKey); got == "" {
		t.Fatalf("expected populated public key")
	}
}

func TestLoadKeyringEntryRejectsMismatchedExtraPrivateKey(t *testing.T) {
	tmp := t.TempDir()
	safeRoot := filepath.Join(tmp, "safe-root")
	keyring := filepath.Join(tmp, "keyring.json")
	writeKeyring(t, keyring, map[string]any{
		"safe/dev": map[string]any{
			"repo":        "safe",
			"env":         "dev",
			"public_key":  "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	})
	backend, err := New(Config{
		SafeRoot:      safeRoot,
		KeyringPath:   keyring,
		ExtraPrivKeys: []string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	})
	if err != nil {
		t.Fatalf("new backend: %v", err)
	}
	if _, err := backend.loadKeyringEntry("safe", "dev"); !errors.Is(err, ErrKeySprawl) {
		t.Fatalf("expected ErrKeySprawl, got %v", err)
	}
}
