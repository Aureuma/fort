package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Host             string
	RefreshTokenFile string
	TokenPath        string
	RefreshRatio     float64
	Jitter           time.Duration
	MinSleep         time.Duration
	MaxBackoff       time.Duration
	HTTPTimeout      time.Duration
	Once             bool
}

type Runtime struct {
	cfg      Config
	client   *http.Client
	rng      *rand.Rand
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
	readTok  func(path string) (string, error)
	writeTok func(path, value string) error
	writeRef func(path, value string) error
}

type jitterRand interface {
	Int63n(n int64) int64
}

func New(cfg Config) (*Runtime, error) {
	cfg.Host = strings.TrimRight(strings.TrimSpace(cfg.Host), "/")
	cfg.RefreshTokenFile = strings.TrimSpace(cfg.RefreshTokenFile)
	cfg.TokenPath = strings.TrimSpace(cfg.TokenPath)
	if cfg.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if cfg.RefreshTokenFile == "" {
		return nil, fmt.Errorf("refresh token file is required")
	}
	if cfg.TokenPath == "" {
		return nil, fmt.Errorf("token path is required")
	}
	if cfg.RefreshRatio <= 0 || cfg.RefreshRatio >= 1 {
		cfg.RefreshRatio = 0.70
	}
	if cfg.Jitter < 0 {
		cfg.Jitter = 0
	}
	if cfg.MinSleep <= 0 {
		cfg.MinSleep = 5 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 30 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	r := &Runtime{
		cfg:      cfg,
		client:   &http.Client{Timeout: cfg.HTTPTimeout},
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
		now:      func() time.Time { return time.Now().UTC() },
		sleep:    sleepContext,
		readTok:  readSecretTokenFile,
		writeTok: writeTokenAtomic,
		writeRef: writeSecretTokenFile,
	}
	return r, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type refreshResponse struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	AccessExpiresAt string `json:"access_expires_at"`
}

func (r *Runtime) refresh(ctx context.Context, refreshToken string) (refreshResponse, int, map[string]any, error) {
	reqBody := map[string]any{"refresh_token": refreshToken}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return refreshResponse{}, 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Host+"/v1/auth/session/refresh", bytes.NewReader(b))
	if err != nil {
		return refreshResponse{}, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := r.client.Do(req)
	if err != nil {
		return refreshResponse{}, 0, nil, err
	}
	defer res.Body.Close()

	raw := map[string]any{}
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&raw)
	if res.StatusCode != http.StatusOK {
		return refreshResponse{}, res.StatusCode, raw, nil
	}
	out := refreshResponse{}
	if access, _ := raw["access_token"].(string); access != "" {
		out.AccessToken = access
	}
	if next, _ := raw["refresh_token"].(string); next != "" {
		out.RefreshToken = next
	}
	if exp, _ := raw["access_expires_at"].(string); exp != "" {
		out.AccessExpiresAt = exp
	}
	if out.AccessToken == "" || out.RefreshToken == "" || out.AccessExpiresAt == "" {
		return refreshResponse{}, 0, nil, fmt.Errorf("invalid refresh response payload")
	}
	return out, res.StatusCode, raw, nil
}

func computeNextSleep(now time.Time, expiresAt time.Time, ratio float64, jitter time.Duration, minSleep time.Duration, rng jitterRand) time.Duration {
	ttl := expiresAt.Sub(now)
	if ttl <= 0 {
		return minSleep
	}
	base := time.Duration(float64(ttl) * ratio)
	if base < minSleep {
		base = minSleep
	}
	if jitter > 0 {
		maxJitterNs := jitter.Nanoseconds()
		if maxJitterNs > 0 {
			j := rng.Int63n(maxJitterNs*2+1) - maxJitterNs
			base += time.Duration(j)
		}
	}
	if base < minSleep {
		base = minSleep
	}
	ceiling := ttl - minSleep
	if ceiling < minSleep {
		ceiling = minSleep
	}
	if base > ceiling {
		base = ceiling
	}
	return base
}

func writeTokenAtomic(path, value string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return fmt.Errorf("token path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(value), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readSecretTokenFile(path string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return "", fmt.Errorf("refresh token path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("refresh token path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("refresh token file permissions must be 0600 or stricter")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("refresh token file is empty")
	}
	return token, nil
}

func writeSecretTokenFile(path, value string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	value = strings.TrimSpace(value)
	if path == "" {
		return fmt.Errorf("refresh token path is empty")
	}
	if value == "" {
		return fmt.Errorf("refresh token value is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refresh token path is not a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("refresh token file permissions must be 0600 or stricter")
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(value), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func (r *Runtime) Run(ctx context.Context) error {
	refreshToken, err := r.readTok(r.cfg.RefreshTokenFile)
	if err != nil {
		return fmt.Errorf("read refresh token file: %w", err)
	}
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		res, status, body, err := r.refresh(ctx, refreshToken)
		if err != nil {
			if err := r.sleep(ctx, backoff); err != nil {
				return err
			}
			backoff *= 2
			if backoff > r.cfg.MaxBackoff {
				backoff = r.cfg.MaxBackoff
			}
			continue
		}
		if status != http.StatusOK {
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return fmt.Errorf("refresh rejected (status=%d body=%v)", status, body)
			}
			if err := r.sleep(ctx, backoff); err != nil {
				return err
			}
			backoff *= 2
			if backoff > r.cfg.MaxBackoff {
				backoff = r.cfg.MaxBackoff
			}
			continue
		}
		accessExpiresAt, err := time.Parse(time.RFC3339Nano, res.AccessExpiresAt)
		if err != nil {
			return fmt.Errorf("parse access_expires_at: %w", err)
		}
		if err := r.writeRef(r.cfg.RefreshTokenFile, res.RefreshToken); err != nil {
			return fmt.Errorf("write refresh token: %w", err)
		}
		if err := r.writeTok(r.cfg.TokenPath, res.AccessToken); err != nil {
			return fmt.Errorf("write token: %w", err)
		}
		refreshToken = strings.TrimSpace(res.RefreshToken)
		backoff = time.Second
		if r.cfg.Once {
			return nil
		}
		nextSleep := computeNextSleep(r.now(), accessExpiresAt, r.cfg.RefreshRatio, r.cfg.Jitter, r.cfg.MinSleep, r.rng)
		if err := r.sleep(ctx, nextSleep); err != nil {
			return err
		}
	}
}
