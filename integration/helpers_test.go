//go:build integration

package integration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func requireCmd(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Fatalf("required command not found: %s", name)
	}
}

func runCmd(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	cmd.Env = mergeEnv(env)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		out := strings.TrimSpace(stdout.String())
		errOut := strings.TrimSpace(stderr.String())
		t.Fatalf("command failed: %s %s\nerr=%v\nstdout=%s\nstderr=%s", name, strings.Join(args, " "), err, out, errOut)
	}
	return strings.TrimSpace(stdout.String())
}

func runCmdAllowError(t *testing.T, dir string, env []string, name string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	cmd.Env = mergeEnv(env)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), err
}

func mergeEnv(extra []string) []string {
	if len(extra) == 0 {
		return os.Environ()
	}
	base := os.Environ()
	for _, kv := range extra {
		key, _, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		prefix := key + "="
		filtered := base[:0]
		for _, existing := range base {
			if strings.HasPrefix(existing, prefix) {
				continue
			}
			filtered = append(filtered, existing)
		}
		base = append(filtered, kv)
	}
	return base
}

func buildGoBinary(t *testing.T, dir string, out string, pkg string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", out, err)
	}
	runCmd(t, dir, nil, "go", "build", "-o", out, pkg)
}

func waitFor(t *testing.T, timeout time.Duration, step time.Duration, fn func() error, context string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := fn()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s: %v", context, err)
		}
		time.Sleep(step)
	}
}

func ensureDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}

func isNotFoundDocker(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false
	}
	return errors.Is(err, exec.ErrNotFound)
}

func mustJSONContains(t *testing.T, jsonRaw string, needle string, context string) {
	t.Helper()
	if !strings.Contains(jsonRaw, needle) {
		t.Fatalf("unexpected %s: missing %q in %s", context, needle, jsonRaw)
	}
}

func envKV(key string, value string) string {
	return fmt.Sprintf("%s=%s", strings.TrimSpace(key), strings.TrimSpace(value))
}
