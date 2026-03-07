package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fort/internal/model"
)

const version = "dev"

type Client struct {
	Host    string
	Token   string
	JSON    bool
	Timeout time.Duration
	http    *http.Client
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, strings.TrimSpace(v))
	return nil
}

func Run() error {
	return run(os.Args[1:])
}

func run(args []string) error {
	fs := flag.NewFlagSet("fort", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host", envOr("FORT_HOST", "http://127.0.0.1:8088"), "fort API host")
	token := fs.String("token", envOr("FORT_TOKEN", ""), "bearer token")
	jsonOut := fs.Bool("json", false, "output JSON")
	timeout := fs.Duration("timeout", durationEnv("FORT_TIMEOUT", 15*time.Second), "request timeout")
	if err := fs.Parse(args); err != nil {
		return usageRoot()
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return usageRoot()
	}

	client := &Client{
		Host:    strings.TrimRight(strings.TrimSpace(*host), "/"),
		Token:   strings.TrimSpace(*token),
		JSON:    *jsonOut,
		Timeout: *timeout,
		http:    &http.Client{Timeout: *timeout},
	}

	cmd := strings.TrimSpace(rest[0])
	args = rest[1:]
	switch cmd {
	case "doctor":
		return client.cmdDoctor(args)
	case "version":
		return client.cmdVersion(args)
	case "auth":
		return client.cmdAuth(args)
	case "get":
		return client.cmdGet(args)
	case "set":
		return client.cmdSet(args)
	case "list":
		return client.cmdList(args)
	case "batch-get":
		return client.cmdBatchGet(args)
	case "run":
		return client.cmdRun(args)
	case "agent":
		return client.cmdAgent(args)
	default:
		return usageRoot()
	}
}

func usageRoot() error {
	return errors.New(`usage: fort [--host URL] [--token TOKEN] [--json] <command> [args]

commands:
  doctor
  version
  auth issue|whoami|login|list|revoke|session
  get
  set
  list
  batch-get
  run
  agent create|get|list|set-status|rotate|remove|policy`)
}

func envOr(name, fallback string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	return v
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func readSecretFile(path string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return "", errors.New("secret file path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("secret path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("secret file permissions must be 0600 or stricter")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(b))
	if value == "" {
		return "", errors.New("secret file is empty")
	}
	return value, nil
}

func writeSecretFile(path, value string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	value = strings.TrimSpace(value)
	if path == "" {
		return errors.New("secret file path is empty")
	}
	if value == "" {
		return errors.New("secret value is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("secret path is not a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("secret file permissions must be 0600 or stricter")
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

func (c *Client) apiRequest(method, path string, body any, useToken bool) (int, map[string]any, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(b)
	}
	url := c.Host + path
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if useToken {
		if c.Token == "" {
			return 0, nil, errors.New("token is required")
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, nil
}

func apiErr(status int, body map[string]any) error {
	if e, _ := body["error"].(string); e != "" {
		return fmt.Errorf("api status %d: %s", status, e)
	}
	b, _ := json.Marshal(body)
	return fmt.Errorf("api status %d: %s", status, string(b))
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printTextf(format string, args ...any) {
	fmt.Fprintf(os.Stdout, format, args...)
}

func (c *Client) cmdVersion(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: fort version")
	}
	if c.JSON {
		return printJSON(map[string]any{"version": version})
	}
	printTextf("%s\n", version)
	return nil
}

func (c *Client) cmdDoctor(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: fort doctor")
	}
	healthStatus, health, err := c.apiRequest(http.MethodGet, "/v1/health", nil, false)
	if err != nil {
		return err
	}
	readyStatus, ready, err := c.apiRequest(http.MethodGet, "/v1/ready", nil, false)
	if err != nil {
		return err
	}
	out := map[string]any{
		"host":          c.Host,
		"health_status": healthStatus,
		"health":        health,
		"ready_status":  readyStatus,
		"ready":         ready,
	}
	if c.Token != "" {
		status, whoami, err := c.apiRequest(http.MethodGet, "/v1/auth/whoami", nil, true)
		if err == nil {
			out["whoami_status"] = status
			out["whoami"] = whoami
		}
	}
	if c.JSON {
		return printJSON(out)
	}
	printTextf("host: %s\n", c.Host)
	printTextf("health: %d\n", healthStatus)
	printTextf("ready: %d\n", readyStatus)
	if whoami, ok := out["whoami"]; ok {
		printTextf("auth: ok (%v)\n", whoami)
	}
	return nil
}

func (c *Client) cmdAuth(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fort auth issue|whoami|login|list|revoke|session")
	}
	switch args[0] {
	case "session":
		return c.cmdAuthSession(args[1:])
	case "issue", "login":
		fs := flag.NewFlagSet("fort auth issue", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		agentID := fs.String("agent", "", "agent id")
		ttl := fs.String("ttl", "", "token ttl")
		aud := fs.String("aud", "fort-api", "audience")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort auth issue --agent <id> [--ttl 15m] [--aud fort-api]")
		}
		if strings.TrimSpace(*agentID) == "" {
			return errors.New("--agent is required")
		}
		body := map[string]any{"agent_id": strings.TrimSpace(*agentID), "aud": strings.TrimSpace(*aud)}
		if strings.TrimSpace(*ttl) != "" {
			body["ttl"] = strings.TrimSpace(*ttl)
		}
		useToken := c.Token != ""
		if !useToken {
			return errors.New("auth issue requires --token (admin token)")
		}
		status, resp, err := c.apiRequest(http.MethodPost, "/v1/auth/token", body, useToken)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		if c.JSON {
			return printJSON(resp)
		}
		printTextf("%v\n", resp["token"])
		return nil
	case "whoami":
		if len(args) != 1 {
			return errors.New("usage: fort auth whoami")
		}
		status, resp, err := c.apiRequest(http.MethodGet, "/v1/auth/whoami", nil, true)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		if c.JSON {
			return printJSON(resp)
		}
		agent, _ := resp["agent"].(map[string]any)
		printTextf("agent_id=%v token_jti=%v\n", agent["id"], resp["token_jti"])
		return nil
	case "list":
		fs := flag.NewFlagSet("fort auth list", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		agentID := fs.String("agent", "", "agent id filter")
		activeOnly := fs.Bool("active-only", false, "only active tokens")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort auth list [--agent <id>] [--active-only]")
		}
		q := ""
		if strings.TrimSpace(*agentID) != "" {
			q = "?agent_id=" + strings.TrimSpace(*agentID)
		}
		if *activeOnly {
			if q == "" {
				q = "?active_only=true"
			} else {
				q += "&active_only=true"
			}
		}
		useToken := c.Token != ""
		if !useToken {
			return errors.New("auth list requires --token")
		}
		status, resp, err := c.apiRequest(http.MethodGet, "/v1/auth/list"+q, nil, useToken)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		if c.JSON {
			return printJSON(resp)
		}
		printTextf("%v\n", resp["tokens"])
		return nil
	case "revoke":
		fs := flag.NewFlagSet("fort auth revoke", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		jti := fs.String("jti", "", "token jti")
		reason := fs.String("reason", "", "reason")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort auth revoke --jti <id> [--reason text]")
		}
		if strings.TrimSpace(*jti) == "" {
			return errors.New("--jti is required")
		}
		useToken := c.Token != ""
		if !useToken {
			return errors.New("auth revoke requires --token")
		}
		status, resp, err := c.apiRequest(http.MethodPost, "/v1/auth/revoke", map[string]any{"jti": *jti, "reason": *reason}, useToken)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		if c.JSON {
			return printJSON(resp)
		}
		printTextf("revoked %s\n", *jti)
		return nil
	default:
		return errors.New("usage: fort auth issue|whoami|login|list|revoke|session")
	}
}

func (c *Client) cmdAuthSession(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fort auth session open|refresh|close")
	}
	switch args[0] {
	case "open":
		fs := flag.NewFlagSet("fort auth session open", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		agentID := fs.String("agent", "", "agent id")
		aud := fs.String("aud", "fort-api", "audience")
		accessTTL := fs.String("access-ttl", "", "access token ttl")
		refreshTTL := fs.String("refresh-ttl", "", "refresh session ttl")
		refreshTokenOut := fs.String("refresh-token-out", "", "path to write rotated refresh token (0600)")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort auth session open --agent <id> --refresh-token-out <path> [--access-ttl 15m] [--refresh-ttl 24h] [--aud fort-api]")
		}
		if strings.TrimSpace(*agentID) == "" {
			return errors.New("--agent is required")
		}
		if strings.TrimSpace(*refreshTokenOut) == "" {
			return errors.New("--refresh-token-out is required")
		}
		body := map[string]any{
			"agent_id": strings.TrimSpace(*agentID),
			"aud":      strings.TrimSpace(*aud),
		}
		if strings.TrimSpace(*accessTTL) != "" {
			body["access_ttl"] = strings.TrimSpace(*accessTTL)
		}
		if strings.TrimSpace(*refreshTTL) != "" {
			body["refresh_ttl"] = strings.TrimSpace(*refreshTTL)
		}
		useToken := c.Token != ""
		if !useToken {
			return errors.New("auth session open requires --token (admin token)")
		}
		status, resp, err := c.apiRequest(http.MethodPost, "/v1/auth/session/open", body, useToken)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		refreshToken, _ := resp["refresh_token"].(string)
		if strings.TrimSpace(refreshToken) == "" {
			return errors.New("open session response missing refresh_token")
		}
		if err := writeSecretFile(*refreshTokenOut, refreshToken); err != nil {
			return fmt.Errorf("write refresh token file: %w", err)
		}
		delete(resp, "refresh_token")
		resp["refresh_token_file"] = filepath.Clean(strings.TrimSpace(*refreshTokenOut))
		if c.JSON {
			return printJSON(resp)
		}
		printTextf("session_id=%v\n", resp["session_id"])
		printTextf("access_token=%v\n", resp["access_token"])
		printTextf("refresh_token_file=%v\n", resp["refresh_token_file"])
		printTextf("access_expires_at=%v\n", resp["access_expires_at"])
		printTextf("refresh_expires_at=%v\n", resp["refresh_expires_at"])
		return nil
	case "refresh":
		fs := flag.NewFlagSet("fort auth session refresh", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		refreshTokenFile := fs.String("refresh-token-file", "", "path to refresh token file (0600)")
		refreshTokenOut := fs.String("refresh-token-out", "", "path to write rotated refresh token (defaults to --refresh-token-file)")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort auth session refresh --refresh-token-file <path> [--refresh-token-out <path>]")
		}
		if strings.TrimSpace(*refreshTokenFile) == "" {
			return errors.New("--refresh-token-file is required")
		}
		refreshOut := strings.TrimSpace(*refreshTokenOut)
		if refreshOut == "" {
			refreshOut = strings.TrimSpace(*refreshTokenFile)
		}
		refreshToken, err := readSecretFile(*refreshTokenFile)
		if err != nil {
			return fmt.Errorf("read refresh token file: %w", err)
		}
		status, resp, err := c.apiRequest(http.MethodPost, "/v1/auth/session/refresh", map[string]any{
			"refresh_token": refreshToken,
		}, false)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		nextRefreshToken, _ := resp["refresh_token"].(string)
		if strings.TrimSpace(nextRefreshToken) == "" {
			return errors.New("refresh response missing refresh_token")
		}
		if err := writeSecretFile(refreshOut, nextRefreshToken); err != nil {
			return fmt.Errorf("write refresh token file: %w", err)
		}
		delete(resp, "refresh_token")
		resp["refresh_token_file"] = filepath.Clean(refreshOut)
		if c.JSON {
			return printJSON(resp)
		}
		printTextf("session_id=%v\n", resp["session_id"])
		printTextf("access_token=%v\n", resp["access_token"])
		printTextf("refresh_token_file=%v\n", resp["refresh_token_file"])
		printTextf("access_expires_at=%v\n", resp["access_expires_at"])
		printTextf("refresh_expires_at=%v\n", resp["refresh_expires_at"])
		return nil
	case "close":
		fs := flag.NewFlagSet("fort auth session close", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sessionID := fs.String("session-id", "", "session id")
		refreshTokenFile := fs.String("refresh-token-file", "", "path to refresh token file (0600)")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort auth session close [--session-id <id> | --refresh-token-file <path>]")
		}
		if strings.TrimSpace(*sessionID) == "" && strings.TrimSpace(*refreshTokenFile) == "" {
			return errors.New("--session-id or --refresh-token-file is required")
		}
		refreshToken := ""
		if strings.TrimSpace(*refreshTokenFile) != "" {
			value, err := readSecretFile(*refreshTokenFile)
			if err != nil {
				return fmt.Errorf("read refresh token file: %w", err)
			}
			refreshToken = value
		}
		useToken := strings.TrimSpace(*sessionID) != ""
		status, resp, err := c.apiRequest(http.MethodPost, "/v1/auth/session/close", map[string]any{
			"session_id":    strings.TrimSpace(*sessionID),
			"refresh_token": refreshToken,
		}, useToken)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		if c.JSON {
			return printJSON(resp)
		}
		printTextf("closed session %v\n", resp["session_id"])
		return nil
	default:
		return errors.New("usage: fort auth session open|refresh|close")
	}
}

func (c *Client) cmdGet(args []string) error {
	fs := flag.NewFlagSet("fort get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	repo := fs.String("repo", "", "repo")
	env := fs.String("env", "", "env")
	key := fs.String("key", "", "key")
	format := fs.String("format", "raw", "raw or json")
	if err := fs.Parse(args); err != nil {
		return errors.New("usage: fort get --repo <repo> --env <env> --key <key> [--format raw|json]")
	}
	if *repo == "" || *env == "" || *key == "" {
		return errors.New("--repo, --env, --key are required")
	}
	status, resp, err := c.apiRequest(http.MethodPost, "/v1/secrets/get", map[string]any{"repo": *repo, "env": *env, "key": *key}, true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiErr(status, resp)
	}
	if c.JSON || strings.TrimSpace(*format) == "json" {
		return printJSON(resp)
	}
	printTextf("%v\n", resp["value"])
	return nil
}

func (c *Client) cmdSet(args []string) error {
	fs := flag.NewFlagSet("fort set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	repo := fs.String("repo", "", "repo")
	env := fs.String("env", "", "env")
	key := fs.String("key", "", "key")
	value := fs.String("value", "", "value")
	casVersion := fs.Int64("cas-version", 0, "unused cas version")
	if err := fs.Parse(args); err != nil {
		return errors.New("usage: fort set --repo <repo> --env <env> --key <key> --value <value> [--cas-version n]")
	}
	if *repo == "" || *env == "" || *key == "" {
		return errors.New("--repo, --env, --key are required")
	}
	status, resp, err := c.apiRequest(http.MethodPost, "/v1/secrets/set", map[string]any{
		"repo":        *repo,
		"env":         *env,
		"key":         *key,
		"value":       *value,
		"cas_version": *casVersion,
	}, true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiErr(status, resp)
	}
	if c.JSON {
		return printJSON(resp)
	}
	printTextf("ok\n")
	return nil
}

func (c *Client) cmdList(args []string) error {
	fs := flag.NewFlagSet("fort list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	repo := fs.String("repo", "", "repo")
	env := fs.String("env", "", "env")
	prefix := fs.String("prefix", "", "optional prefix")
	if err := fs.Parse(args); err != nil {
		return errors.New("usage: fort list --repo <repo> --env <env> [--prefix pfx]")
	}
	if *repo == "" || *env == "" {
		return errors.New("--repo and --env are required")
	}
	status, resp, err := c.apiRequest(http.MethodPost, "/v1/secrets/list", map[string]any{"repo": *repo, "env": *env, "prefix": *prefix}, true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiErr(status, resp)
	}
	if c.JSON {
		return printJSON(resp)
	}
	if keys, ok := resp["keys"].([]any); ok {
		for _, key := range keys {
			printTextf("%v\n", key)
		}
		return nil
	}
	return printJSON(resp)
}

func (c *Client) cmdBatchGet(args []string) error {
	fs := flag.NewFlagSet("fort batch-get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	repo := fs.String("repo", "", "repo")
	env := fs.String("env", "", "env")
	keysRaw := fs.String("keys", "", "comma separated keys")
	if err := fs.Parse(args); err != nil {
		return errors.New("usage: fort batch-get --repo <repo> --env <env> --keys k1,k2")
	}
	if *repo == "" || *env == "" || *keysRaw == "" {
		return errors.New("--repo, --env, --keys are required")
	}
	keys := splitCSV(*keysRaw)
	if len(keys) == 0 {
		return errors.New("--keys must include at least one key")
	}
	status, resp, err := c.apiRequest(http.MethodPost, "/v1/secrets/batch-get", map[string]any{"repo": *repo, "env": *env, "keys": keys}, true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiErr(status, resp)
	}
	if c.JSON {
		return printJSON(resp)
	}
	if values, ok := resp["values"].(map[string]any); ok {
		for k, v := range values {
			printTextf("%s=%v\n", k, v)
		}
		return nil
	}
	return printJSON(resp)
}

func splitCSV(in string) []string {
	parts := strings.Split(in, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func parseDurationSeconds(raw string, fallback time.Duration) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return int64(fallback.Seconds()), nil
	}
	d, err := time.ParseDuration(raw)
	if err == nil {
		if d <= 0 {
			return 0, errors.New("duration must be positive")
		}
		return int64(d.Seconds()), nil
	}
	seconds, convErr := strconv.ParseInt(raw, 10, 64)
	if convErr != nil || seconds <= 0 {
		return 0, errors.New("invalid duration")
	}
	return seconds, nil
}

func (c *Client) cmdRun(args []string) error {
	fs := flag.NewFlagSet("fort run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	repo := fs.String("repo", "", "repo")
	env := fs.String("env", "", "env")
	keysRaw := fs.String("keys", "", "comma separated keys")
	mode := fs.String("mode", "files", "files or env")
	ttl := fs.String("ttl", "60s", "session ttl")
	if err := fs.Parse(args); err != nil {
		return errors.New("usage: fort run --repo <repo> --env <env> --keys k1,k2 [--mode files|env] [--ttl 60s] -- <cmd> [args...]")
	}
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return errors.New("run requires a command after --")
	}
	if *repo == "" || *env == "" || *keysRaw == "" {
		return errors.New("--repo, --env, --keys are required")
	}
	keys := splitCSV(*keysRaw)
	if len(keys) == 0 {
		return errors.New("--keys must include at least one key")
	}
	modeNorm := strings.TrimSpace(strings.ToLower(*mode))
	if modeNorm != "files" && modeNorm != "env" {
		return errors.New("--mode must be files or env")
	}
	ttlSeconds, err := parseDurationSeconds(*ttl, 60*time.Second)
	if err != nil {
		return err
	}

	openStatus, openResp, err := c.apiRequest(http.MethodPost, "/v1/run/session/open", map[string]any{
		"repo":        *repo,
		"env":         *env,
		"keys":        keys,
		"mode":        modeNorm,
		"ttl_seconds": ttlSeconds,
	}, true)
	if err != nil {
		return err
	}
	if openStatus != http.StatusOK {
		return apiErr(openStatus, openResp)
	}
	sessionID, _ := openResp["session_id"].(string)
	oneTimeToken, _ := openResp["one_time_token"].(string)
	if sessionID == "" || oneTimeToken == "" {
		return errors.New("open session response missing session_id/one_time_token")
	}

	defer func() {
		_, _, _ = c.apiRequest(http.MethodPost, "/v1/run/session/close", map[string]any{"session_id": sessionID}, true)
	}()

	materializeStatus, materializeResp, err := c.apiRequest(http.MethodPost, "/v1/run/session/materialize", map[string]any{
		"session_id":     sessionID,
		"one_time_token": oneTimeToken,
	}, true)
	if err != nil {
		return err
	}
	if materializeStatus != http.StatusOK {
		return apiErr(materializeStatus, materializeResp)
	}
	valuesAny, ok := materializeResp["values"].(map[string]any)
	if !ok {
		return errors.New("materialize response missing values")
	}
	values := map[string]string{}
	for k, v := range valuesAny {
		values[k] = fmt.Sprint(v)
	}
	if err := execWithSecrets(cmdArgs, values, modeNorm); err != nil {
		return err
	}
	return nil
}

func execWithSecrets(cmdArgs []string, values map[string]string, mode string) error {
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	env := os.Environ()
	cleanup := func() {}
	if mode == "env" {
		for key, value := range values {
			env = append(env, key+"="+value)
		}
	} else {
		secretsDir, err := os.MkdirTemp("", "fort-secrets-")
		if err != nil {
			return err
		}
		cleanup = func() { _ = os.RemoveAll(secretsDir) }
		for key, value := range values {
			safeKey := strings.ReplaceAll(key, "/", "_")
			path := filepath.Join(secretsDir, safeKey)
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				cleanup()
				return err
			}
			env = append(env, key+"_FILE="+path)
		}
	}
	defer cleanup()
	cmd.Env = env
	return cmd.Run()
}

func (c *Client) cmdAgent(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fort agent create|get|list|set-status|rotate|remove|policy")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("fort agent create", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		id := fs.String("id", "", "agent id")
		typeName := fs.String("type", "workload", "workload|user|ci")
		statusName := fs.String("status", "active", "active|disabled")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort agent create --id <agent-id> --type workload|user|ci [--status active|disabled]")
		}
		if *id == "" {
			return errors.New("--id is required")
		}
		status, resp, err := c.apiRequest(http.MethodPost, "/v1/agents", map[string]any{"id": *id, "type": *typeName, "status": *statusName}, c.Token != "")
		if err != nil {
			return err
		}
		if status != http.StatusCreated {
			return apiErr(status, resp)
		}
		if c.JSON {
			return printJSON(resp)
		}
		printTextf("created agent %s\n", *id)
		return nil
	case "get":
		fs := flag.NewFlagSet("fort agent get", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		id := fs.String("id", "", "agent id")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort agent get --id <agent-id>")
		}
		if *id == "" {
			return errors.New("--id is required")
		}
		status, resp, err := c.apiRequest(http.MethodGet, "/v1/agents/"+*id, nil, true)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		return printJSON(resp)
	case "list":
		fs := flag.NewFlagSet("fort agent list", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		typeName := fs.String("type", "", "optional type filter")
		statusName := fs.String("status", "", "optional status filter")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort agent list [--type workload|user|ci] [--status active|disabled]")
		}
		query := []string{}
		if *typeName != "" {
			query = append(query, "type="+*typeName)
		}
		if *statusName != "" {
			query = append(query, "status="+*statusName)
		}
		path := "/v1/agents"
		if len(query) > 0 {
			path += "?" + strings.Join(query, "&")
		}
		status, resp, err := c.apiRequest(http.MethodGet, path, nil, c.Token != "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		return printJSON(resp)
	case "set-status":
		fs := flag.NewFlagSet("fort agent set-status", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		id := fs.String("id", "", "agent id")
		statusName := fs.String("status", "", "active|disabled")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort agent set-status --id <agent-id> --status active|disabled")
		}
		if *id == "" || *statusName == "" {
			return errors.New("--id and --status are required")
		}
		endpoint := "/v1/agents/" + *id + "/disable"
		if strings.TrimSpace(*statusName) == "active" {
			endpoint = "/v1/agents/" + *id + "/enable"
		}
		status, resp, err := c.apiRequest(http.MethodPost, endpoint, map[string]any{}, c.Token != "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		return printJSON(resp)
	case "rotate":
		fs := flag.NewFlagSet("fort agent rotate", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		id := fs.String("id", "", "agent id")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort agent rotate --id <agent-id>")
		}
		if *id == "" {
			return errors.New("--id is required")
		}
		status, resp, err := c.apiRequest(http.MethodPost, "/v1/agents/"+*id+"/rotate", map[string]any{}, c.Token != "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		return printJSON(resp)
	case "remove":
		fs := flag.NewFlagSet("fort agent remove", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		id := fs.String("id", "", "agent id")
		_ = fs.Bool("force", false, "ignored")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort agent remove --id <agent-id> [--force]")
		}
		if *id == "" {
			return errors.New("--id is required")
		}
		status, resp, err := c.apiRequest(http.MethodDelete, "/v1/agents/"+*id, nil, c.Token != "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		if c.JSON {
			return printJSON(resp)
		}
		printTextf("removed agent %s\n", *id)
		return nil
	case "policy":
		return c.cmdAgentPolicy(args[1:])
	default:
		return errors.New("usage: fort agent create|get|list|set-status|rotate|remove|policy")
	}
}

func parseBinding(raw string) (model.Binding, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ":")
	if len(parts) != 3 {
		return model.Binding{}, errors.New("binding format must be <repo|*>:<env|*>:<ops|*>")
	}
	repo := strings.TrimSpace(parts[0])
	env := strings.TrimSpace(parts[1])
	opsRaw := strings.TrimSpace(parts[2])
	if repo == "" || env == "" || opsRaw == "" {
		return model.Binding{}, errors.New("binding parts cannot be empty")
	}
	opNames := splitCSV(opsRaw)
	if len(opNames) == 0 {
		return model.Binding{}, errors.New("binding must include at least one op")
	}
	ops := make([]model.Operation, 0, len(opNames))
	for _, op := range opNames {
		ops = append(ops, model.Operation(op))
	}
	return model.Binding{Repo: repo, Env: env, Ops: ops}, nil
}

func (c *Client) cmdAgentPolicy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fort agent policy get|set|add|remove|check")
	}
	sub := args[0]
	switch sub {
	case "get":
		fs := flag.NewFlagSet("fort agent policy get", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		id := fs.String("id", "", "agent id")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort agent policy get --id <agent-id>")
		}
		if *id == "" {
			return errors.New("--id is required")
		}
		status, resp, err := c.apiRequest(http.MethodGet, "/v1/agents/"+*id+"/policy", nil, c.Token != "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		return printJSON(resp)
	case "set":
		fs := flag.NewFlagSet("fort agent policy set", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		id := fs.String("id", "", "agent id")
		var binds stringSliceFlag
		fs.Var(&binds, "bind", "binding repo:env:ops")
		_ = fs.Bool("replace", true, "replace full set")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort agent policy set --id <agent-id> --bind <repo|*>:<env|*>:<ops|*> [--bind ...]")
		}
		if *id == "" || len(binds) == 0 {
			return errors.New("--id and at least one --bind are required")
		}
		bindings := make([]model.Binding, 0, len(binds))
		for _, raw := range binds {
			binding, err := parseBinding(raw)
			if err != nil {
				return err
			}
			bindings = append(bindings, binding)
		}
		status, resp, err := c.apiRequest(http.MethodPut, "/v1/agents/"+*id+"/policy", map[string]any{"bindings": bindings}, c.Token != "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		return printJSON(resp)
	case "add", "remove":
		fs := flag.NewFlagSet("fort agent policy "+sub, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		id := fs.String("id", "", "agent id")
		bind := fs.String("bind", "", "binding repo:env:ops")
		if err := fs.Parse(args[1:]); err != nil {
			return fmt.Errorf("usage: fort agent policy %s --id <agent-id> --bind <repo|*>:<env|*>:<ops|*>", sub)
		}
		if *id == "" || *bind == "" {
			return errors.New("--id and --bind are required")
		}
		binding, err := parseBinding(*bind)
		if err != nil {
			return err
		}
		path := "/v1/agents/" + *id + "/policy/" + sub
		status, resp, err := c.apiRequest(http.MethodPost, path, map[string]any{"binding": binding}, c.Token != "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		return printJSON(resp)
	case "check":
		fs := flag.NewFlagSet("fort agent policy check", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		id := fs.String("id", "", "agent id")
		repo := fs.String("repo", "", "repo")
		env := fs.String("env", "", "env")
		op := fs.String("op", "", "get|set|run|list|batch-get")
		if err := fs.Parse(args[1:]); err != nil {
			return errors.New("usage: fort agent policy check --id <agent-id> --repo <repo> --env <env> --op get|set|run|list")
		}
		if *id == "" || *repo == "" || *env == "" || *op == "" {
			return errors.New("--id, --repo, --env, --op are required")
		}
		status, resp, err := c.apiRequest(http.MethodPost, "/v1/agents/"+*id+"/policy/check", map[string]any{
			"repo": *repo,
			"env":  *env,
			"op":   *op,
		}, c.Token != "")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiErr(status, resp)
		}
		return printJSON(resp)
	default:
		return errors.New("usage: fort agent policy get|set|add|remove|check")
	}
}
