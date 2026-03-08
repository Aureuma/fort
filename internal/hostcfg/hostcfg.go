package hostcfg

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// HostFromSettings resolves Fort host URL from ~/.si settings.
// It checks FORT_SETTINGS_FILE first, then:
//
//	~/.si/fort/settings.toml
//	~/.si/settings.toml
func HostFromSettings() string {
	for _, path := range settingsPaths() {
		if host := parseHostFromFile(path); host != "" {
			return host
		}
	}
	return ""
}

func settingsPaths() []string {
	if explicit := strings.TrimSpace(os.Getenv("FORT_SETTINGS_FILE")); explicit != "" {
		return []string{filepath.Clean(explicit)}
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return nil
	}
	return []string{
		filepath.Join(home, ".si", "fort", "settings.toml"),
		filepath.Join(home, ".si", "settings.toml"),
	}
}

func parseHostFromFile(path string) string {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil || len(raw) == 0 {
		return ""
	}
	inFort := false
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inFort = strings.EqualFold(strings.TrimSpace(line[1:len(line)-1]), "fort")
			continue
		}
		if !inFort {
			continue
		}
		keyRaw, valueRaw, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(keyRaw))
		if key != "host" && key != "host_url" {
			continue
		}
		value := strings.TrimSpace(valueRaw)
		if value == "" {
			continue
		}
		if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
			unquoted, err := strconv.Unquote(value)
			if err == nil {
				value = strings.TrimSpace(unquoted)
			}
		} else if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") && len(value) >= 2 {
			value = strings.TrimSpace(value[1 : len(value)-1])
		}
		if value != "" {
			return value
		}
	}
	return ""
}
