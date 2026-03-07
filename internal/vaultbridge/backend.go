package vaultbridge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	ecies "github.com/ecies/go/v2"
)

const encryptedPrefix = "encrypted:si-vault:"

var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid")
)

type Config struct {
	SafeRoot      string
	KeyringPath   string
	ExtraPrivKeys []string
}

type keyringDoc struct {
	Entries map[string]keyringEntry `json:"entries"`
}

type keyringEntry struct {
	Repo              string   `json:"repo"`
	Env               string   `json:"env"`
	PublicKey         string   `json:"public_key"`
	PrivateKey        string   `json:"private_key"`
	BackupPrivateKeys []string `json:"backup_private_keys"`
}

type Backend struct {
	safeRoot      string
	keyringPath   string
	extraPrivKeys []string
	mu            sync.Mutex
}

func New(cfg Config) (*Backend, error) {
	root := filepath.Clean(strings.TrimSpace(cfg.SafeRoot))
	if root == "" {
		return nil, fmt.Errorf("safe root is required")
	}
	keyringPath := filepath.Clean(strings.TrimSpace(cfg.KeyringPath))
	if keyringPath == "" {
		return nil, fmt.Errorf("keyring path is required")
	}
	extra := make([]string, 0, len(cfg.ExtraPrivKeys))
	for _, raw := range cfg.ExtraPrivKeys {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if raw == "" {
			continue
		}
		extra = append(extra, raw)
	}
	return &Backend{
		safeRoot:      root,
		keyringPath:   keyringPath,
		extraPrivKeys: extra,
	}, nil
}

func isSafePathPart(v string) bool {
	if strings.TrimSpace(v) == "" {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func normalizeTarget(repo, env string) (string, string, error) {
	repo = strings.TrimSpace(repo)
	env = strings.TrimSpace(env)
	if !isSafePathPart(repo) || !isSafePathPart(env) {
		return "", "", ErrInvalid
	}
	return repo, env, nil
}

func normalizeSecretKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", ErrInvalid
	}
	if strings.ContainsAny(key, "\n\r") {
		return "", ErrInvalid
	}
	return key, nil
}

func entryMapKey(repo, env string) string {
	return strings.ToLower(strings.TrimSpace(repo)) + "/" + strings.ToLower(strings.TrimSpace(env))
}

func (b *Backend) envFilePath(repo, env string) string {
	return filepath.Join(b.safeRoot, repo, ".env."+env)
}

func loadDotenv(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	out := map[string]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, nil
}

func writeDotenv(path string, values map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(values[key])
		b.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (b *Backend) loadKeyringEntry(repo, env string) (keyringEntry, error) {
	raw, err := os.ReadFile(b.keyringPath)
	if err != nil {
		return keyringEntry{}, err
	}
	doc := keyringDoc{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return keyringEntry{}, err
	}
	if doc.Entries == nil {
		return keyringEntry{}, ErrNotFound
	}
	key := entryMapKey(repo, env)
	entry, ok := doc.Entries[key]
	if !ok {
		for _, candidate := range doc.Entries {
			if strings.EqualFold(strings.TrimSpace(candidate.Repo), repo) && strings.EqualFold(strings.TrimSpace(candidate.Env), env) {
				entry = candidate
				ok = true
				break
			}
		}
	}
	if !ok {
		return keyringEntry{}, ErrNotFound
	}
	return entry, nil
}

func encryptValue(plain, publicKeyHex string) (string, error) {
	publicKeyHex = strings.TrimSpace(publicKeyHex)
	if publicKeyHex == "" {
		return "", ErrInvalid
	}
	if plain == "" {
		return encryptedPrefix, nil
	}
	pub, err := ecies.NewPublicKeyFromHex(publicKeyHex)
	if err != nil {
		return "", err
	}
	blob, err := ecies.Encrypt(pub, []byte(plain))
	if err != nil {
		return "", err
	}
	return encryptedPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

func decryptValue(raw string, privateKeyHexes []string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.HasPrefix(raw, encryptedPrefix) {
		return raw, nil
	}
	encoded := strings.TrimSpace(strings.TrimPrefix(raw, encryptedPrefix))
	if encoded == "" {
		return "", nil
	}
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	var lastErr error
	for _, candidate := range privateKeyHexes {
		candidate = strings.TrimSpace(strings.ToLower(candidate))
		if candidate == "" {
			continue
		}
		priv, parseErr := ecies.NewPrivateKeyFromHex(candidate)
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		plain, decErr := ecies.Decrypt(priv, blob)
		if decErr != nil {
			lastErr = decErr
			continue
		}
		return string(plain), nil
	}
	if lastErr == nil {
		lastErr = ErrInvalid
	}
	return "", lastErr
}

func (b *Backend) privateKeyCandidates(entry keyringEntry) []string {
	out := make([]string, 0, 1+len(entry.BackupPrivateKeys)+len(b.extraPrivKeys))
	appendKey := func(raw string) {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if raw == "" {
			return
		}
		out = append(out, raw)
	}
	appendKey(entry.PrivateKey)
	for _, backup := range entry.BackupPrivateKeys {
		appendKey(backup)
	}
	for _, extra := range b.extraPrivKeys {
		appendKey(extra)
	}
	return out
}

func (b *Backend) Get(repo, env, key string) (string, error) {
	repo, env, err := normalizeTarget(repo, env)
	if err != nil {
		return "", err
	}
	key, err = normalizeSecretKey(key)
	if err != nil {
		return "", err
	}
	values, err := loadDotenv(b.envFilePath(repo, env))
	if err != nil {
		return "", err
	}
	rawValue, ok := values[key]
	if !ok {
		return "", ErrNotFound
	}
	entry, err := b.loadKeyringEntry(repo, env)
	if err != nil {
		return "", err
	}
	plain, err := decryptValue(rawValue, b.privateKeyCandidates(entry))
	if err != nil {
		return "", err
	}
	return plain, nil
}

func (b *Backend) BatchGet(repo, env string, keys []string) (map[string]string, error) {
	out := make(map[string]string, len(keys))
	for _, key := range keys {
		value, err := b.Get(repo, env, key)
		if err != nil {
			return nil, err
		}
		out[strings.TrimSpace(key)] = value
	}
	return out, nil
}

func (b *Backend) List(repo, env, prefix string) ([]string, error) {
	repo, env, err := normalizeTarget(repo, env)
	if err != nil {
		return nil, err
	}
	prefix = strings.TrimSpace(prefix)
	values, err := loadDotenv(b.envFilePath(repo, env))
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func (b *Backend) Set(repo, env, key, value string) error {
	repo, env, err := normalizeTarget(repo, env)
	if err != nil {
		return err
	}
	key, err = normalizeSecretKey(key)
	if err != nil {
		return err
	}
	entry, err := b.loadKeyringEntry(repo, env)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrInvalid
		}
		return err
	}
	cipher, err := encryptValue(value, strings.TrimSpace(entry.PublicKey))
	if err != nil {
		return err
	}

	path := b.envFilePath(repo, env)
	b.mu.Lock()
	defer b.mu.Unlock()
	values, err := loadDotenv(path)
	if err != nil {
		return err
	}
	values[key] = cipher
	return writeDotenv(path, values)
}
