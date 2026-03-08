package hostcfg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHostFromSettingsPrefersExplicitFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fort-settings.toml")
	if err := os.WriteFile(path, []byte("[fort]\nhost = \"https://fort.explicit.test\"\n"), 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	t.Setenv("FORT_SETTINGS_FILE", path)
	t.Setenv("HOME", t.TempDir())

	got := HostFromSettings()
	if got != "https://fort.explicit.test" {
		t.Fatalf("HostFromSettings()=%q", got)
	}
}

func TestHostFromSettingsReadsModuleSettingsFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("FORT_SETTINGS_FILE", "")
	t.Setenv("HOME", home)
	settingsPath := filepath.Join(home, ".si", "fort", "settings.toml")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(settingsPath, []byte("schema_version = 1\n[fort]\nhost = \"https://fort.module.test\"\n"), 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	got := HostFromSettings()
	if got != "https://fort.module.test" {
		t.Fatalf("HostFromSettings()=%q", got)
	}
}

func TestHostFromSettingsReadsRootSettingsFileFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("FORT_SETTINGS_FILE", "")
	t.Setenv("HOME", home)
	rootPath := filepath.Join(home, ".si", "settings.toml")
	if err := os.MkdirAll(filepath.Dir(rootPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(rootPath, []byte("[fort]\nhost = 'https://fort.root.test'\n"), 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	got := HostFromSettings()
	if got != "https://fort.root.test" {
		t.Fatalf("HostFromSettings()=%q", got)
	}
}

func TestHostFromSettingsReturnsEmptyWhenMissing(t *testing.T) {
	t.Setenv("FORT_SETTINGS_FILE", filepath.Join(t.TempDir(), "missing.toml"))
	if got := HostFromSettings(); got != "" {
		t.Fatalf("HostFromSettings()=%q want empty", got)
	}
}
