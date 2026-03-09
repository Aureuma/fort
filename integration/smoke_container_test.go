//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFortSmokeContainer(t *testing.T) {
	t.Parallel()
	requireCmd(t, "docker")
	requireCmd(t, "go")

	fortRepo := repoRoot(t)
	stateDir := t.TempDir()
	safeDir := t.TempDir()
	ensureDir(t, stateDir)
	ensureDir(t, filepath.Join(safeDir, "safe"))

	imageTag := fmt.Sprintf("fort:smoke-%d", time.Now().UnixNano())
	networkName := fmt.Sprintf("fort-smoke-net-%d", time.Now().UnixNano())
	containerName := fmt.Sprintf("fort-smoke-fortd-%d", time.Now().UnixNano())
	statePath := filepath.Join(stateDir, "state.json")
	keyringPath := filepath.Join(stateDir, "si-vault-keyring.json")
	signingKeyPath := filepath.Join(stateDir, "jwt-signing.key")
	adminToken := seedFortStateForE2E(t, statePath, keyringPath, signingKeyPath, "smoke-signing-key-0123456789012345", "safe", "prod")
	adminTokenFileOnHost := filepath.Join(stateDir, "admin.token")
	writeFile(t, adminTokenFileOnHost, []byte(adminToken), 0o600)
	adminTokenFileInContainer := "/var/lib/fort/admin.token"

	buildGoBinary(t, fortRepo, filepath.Join(fortRepo, ".dist", "fort"), "./cmd/fort")
	buildGoBinary(t, fortRepo, filepath.Join(fortRepo, ".dist", "fortd"), "./cmd/fortd")

	runCmd(t, fortRepo, nil, "docker", "build", "-t", imageTag, ".")
	t.Cleanup(func() {
		runCmdAllowError(t, "", nil, "docker", "rmi", imageTag)
	})
	runCmd(t, "", nil, "docker", "network", "create", networkName)
	t.Cleanup(func() {
		runCmdAllowError(t, "", nil, "docker", "network", "rm", networkName)
	})
	runCmd(t, "", nil, "docker", "run", "-d", "--rm",
		"--name", containerName,
		"--network", networkName,
		"-e", "FORT_ADDR=:8088",
		"-e", "FORT_STATE_PATH=/var/lib/fort/state.json",
		"-e", "FORT_JWT_SIGNING_KEY_FILE=/var/lib/fort/jwt-signing.key",
		"-e", "FORT_SAFE_ROOT=/safe",
		"-e", "FORT_VAULT_KEYRING_FILE=/var/lib/fort/si-vault-keyring.json",
		"-e", "FORT_TOKEN_TTL=15m",
		"-e", "FORT_REFRESH_SESSION_TTL=24h",
		"-v", stateDir+":/var/lib/fort",
		"-v", safeDir+":/safe",
		imageTag)
	t.Cleanup(func() {
		runCmdAllowError(t, "", nil, "docker", "rm", "-f", containerName)
	})
	waitFor(t, 10*time.Second, 250*time.Millisecond, func() error {
		cmd := exec.Command(
			"docker", "exec", containerName, "/usr/local/bin/fort", "--host", "http://127.0.0.1:8088", "doctor",
		)
		return cmd.Run()
	}, "fort smoke container ready")

	containerFort := func(tokenFile string, args ...string) string {
		cmdArgs := []string{"exec", containerName, "/usr/local/bin/fort", "--host", "http://127.0.0.1:8088"}
		if strings.TrimSpace(tokenFile) != "" {
			cmdArgs = append(cmdArgs, "--token-file", tokenFile)
		}
		cmdArgs = append(cmdArgs, args...)
		return runCmd(t, "", nil, "docker", cmdArgs...)
	}
	containerFort(adminTokenFileInContainer, "agent", "create", "--id", "workload-a", "--type", "workload")
	containerFort(adminTokenFileInContainer, "agent", "policy", "set", "--id", "workload-a", "--bind", "safe:prod:get,run,list,set")
	refreshFileInContainer := "/var/lib/fort/workload-a.refresh.token"
	containerFort(adminTokenFileInContainer, "auth", "session", "open", "--agent", "workload-a", "--access-ttl", "5m", "--refresh-ttl", "30m", "--refresh-token-out", refreshFileInContainer)
	refreshFileOnHost := filepath.Join(stateDir, "workload-a.refresh.token")
	info, err := os.Stat(refreshFileOnHost)
	if err != nil {
		t.Fatalf("refresh token did not materialize on host: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("refresh token file is empty: %s", refreshFileOnHost)
	}

	whoami := runCmd(t, "", nil, "docker", "run", "--rm",
		"--network", networkName,
		"--entrypoint", "/bin/sh",
		"-v", refreshFileOnHost+":/run/secrets/fort.refresh:ro",
		"-e", "FORT_HOST=http://"+containerName+":8088",
		imageTag,
		"-lc", "mkdir -p /tmp/fort && cp /run/secrets/fort.refresh /tmp/fort/refresh.token && chmod 600 /tmp/fort/refresh.token && /usr/local/bin/fort-agent --once --refresh-token-file /tmp/fort/refresh.token --token-path /tmp/fort/access.token >/dev/null && /usr/local/bin/fort --json --host \"$FORT_HOST\" --token-file /tmp/fort/access.token auth whoami")
	mustJSONContains(t, whoami, "\"id\": \"workload-a\"", "whoami output")
}
