use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

#[test]
fn fort_e2e_roundtrip_preserves_vault_ciphertext_contract() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let refresh_path = state_dir.join("e2e.refresh");
    let access_path = state_dir.join("e2e.access");
    let admin_token_path = state_dir.join("admin.token");
    let secret_value_path = state_dir.join("e2e-value");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let fort_agent = std::env::var("CARGO_BIN_EXE_fort-agent").expect("fort-agent path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });
    let invalid_token_path = state_dir.join("invalid.token");
    fs::write(&invalid_token_path, b"invalid-token\n").expect("write invalid token");
    set_0600(&invalid_token_path);
    run_fails(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            invalid_token_path.to_str().unwrap(),
            "doctor",
        ],
        "auth: failed",
    );

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "create",
            "--id",
            "e2e-agent",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "policy",
            "set",
            "--id",
            "e2e-agent",
            "--bind",
            "safe:dev:get,set,list,batch-get,run",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "auth",
            "session",
            "open",
            "--agent",
            "e2e-agent",
            "--access-ttl",
            "3m",
            "--refresh-ttl",
            "30m",
            "--refresh-token-out",
            refresh_path.to_str().unwrap(),
        ],
    );
    set_0600(&refresh_path);
    run_ok(
        &fort_agent,
        &[
            "--once",
            "--host",
            &host,
            "--refresh-token-file",
            refresh_path.to_str().unwrap(),
            "--token-path",
            access_path.to_str().unwrap(),
        ],
    );
    set_0600(&access_path);
    fs::write(&secret_value_path, b"from-fort\n").expect("write secret value");
    set_0600(&secret_value_path);

    let scope_output = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "scope",
            "ensure",
            "--repo",
            "agentic-language-development",
            "--env",
            "dev",
        ],
    );
    assert_eq!(
        scope_output.trim(),
        "scope agentic-language-development/dev created"
    );
    let existing_scope_output = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "scope",
            "ensure",
            "--repo",
            "agentic-language-development",
            "--env",
            "dev",
        ],
    );
    assert_eq!(
        existing_scope_output.trim(),
        "scope agentic-language-development/dev exists"
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "set",
            "--repo",
            "agentic-language-development",
            "--env",
            "dev",
            "--key",
            "E2E_SCOPE_KEY",
            "--value-file",
            secret_value_path.to_str().unwrap(),
        ],
    );
    let scoped_value = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "get",
            "--repo",
            "agentic-language-development",
            "--env",
            "dev",
            "--key",
            "E2E_SCOPE_KEY",
        ],
    );
    assert_eq!(scoped_value.trim(), "from-fort");
    let scoped_env = fs::read_to_string(
        safe_root
            .join("agentic-language-development")
            .join(".env.dev"),
    )
    .expect("read scoped env");
    assert!(scoped_env.contains("E2E_SCOPE_KEY=encrypted:vault:"));

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "set",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--key",
            "E2E_KEY",
            "--value-file",
            secret_value_path.to_str().unwrap(),
        ],
    );
    let get_output = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "get",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--key",
            "E2E_KEY",
            "--format",
            "raw",
        ],
    );
    assert_eq!(get_output.trim(), "from-fort");

    let env_file = safe_repo.join(".env.dev");
    let raw = fs::read_to_string(&env_file).expect("read env file");
    assert!(raw.contains("E2E_KEY=encrypted:vault:"));

    let backend = fort::vaultbridge::Backend::new(fort::vaultbridge::Config {
        safe_root: safe_root.display().to_string(),
        keyring_path: keyring_path.display().to_string(),
        extra_priv_keys: Vec::new(),
    })
    .expect("backend");
    let manual = backend
        .get("safe", "dev", "E2E_KEY")
        .expect("manual decrypt");
    assert_eq!(manual, "from-fort");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_cli_rotates_npm_token_through_mock_registry() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let refresh_path = state_dir.join("npm.refresh");
    let access_path = state_dir.join("npm.access");
    let admin_token_path = state_dir.join("admin.token");
    let otp_path = state_dir.join("npm.otp");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    fs::write(&otp_path, b"123456\n").expect("write otp");
    set_0600(&admin_token_path);
    set_0600(&otp_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let fort_agent = std::env::var("CARGO_BIN_EXE_fort-agent").expect("fort-agent path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "create",
            "--id",
            "npm-rotator",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "policy",
            "set",
            "--id",
            "npm-rotator",
            "--bind",
            "safe:dev:get,set",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "auth",
            "session",
            "open",
            "--agent",
            "npm-rotator",
            "--access-ttl",
            "3m",
            "--refresh-ttl",
            "30m",
            "--refresh-token-out",
            refresh_path.to_str().unwrap(),
        ],
    );
    set_0600(&refresh_path);
    run_ok(
        &fort_agent,
        &[
            "--once",
            "--host",
            &host,
            "--refresh-token-file",
            refresh_path.to_str().unwrap(),
            "--token-path",
            access_path.to_str().unwrap(),
        ],
    );
    set_0600(&access_path);

    for (key, value) in [
        (
            "NPM_PUBLISH_TOKEN",
            "npm_oldtoken000000000000000000000000000000",
        ),
        (
            "NPM_MANAGEMENT_TOKEN",
            "npm_management00000000000000000000000000",
        ),
        ("NPM_PASSWORD", "npm-password"),
        ("GITHUB_ACTIONS_TOKEN", "ghp_mockgithubtoken"),
    ] {
        run_ok(
            &fort,
            &[
                "--host",
                &host,
                "--token-file",
                access_path.to_str().unwrap(),
                "set",
                "--repo",
                "safe",
                "--env",
                "dev",
                "--key",
                key,
                "--value",
                value,
            ],
        );
    }

    let (registry_url, npm_mock) =
        start_mock_npm_registry(NpmMockMode::Password, "fort-e2e".to_string());
    let (github_url, github_mock) = start_mock_github_actions_secret_api(false);
    let output = Command::new(&fort)
        .args([
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "--json",
            "rotate",
            "npm",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--token-key",
            "NPM_PUBLISH_TOKEN",
            "--management-token-key",
            "NPM_MANAGEMENT_TOKEN",
            "--password-key",
            "NPM_PASSWORD",
            "--otp-file",
            otp_path.to_str().unwrap(),
            "--name",
            "fort-e2e",
            "--all-packages",
            "--bypass-2fa",
            "--revoke-old",
            "--registry",
            &registry_url,
            "--github-actions-repo",
            "Aureuma/svelta-blog",
            "--github-secret-name",
            "NPM_TOKEN",
            "--github-token-key",
            "GITHUB_ACTIONS_TOKEN",
            "--github-api-base",
            &github_url,
        ])
        .output()
        .expect("run npm rotation");
    assert!(
        output.status.success(),
        "npm rotation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"old_token_revoked\": true"));
    assert!(stdout.contains("\"github_actions_updated\""));
    assert!(stdout.contains("\"repo\": \"Aureuma/svelta-blog\""));
    assert!(!stdout.contains("npm_newtoken000000000000000000000000000000"));
    npm_mock.join().expect("mock npm registry");
    github_mock.join().expect("mock github api");

    let rotated = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "get",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--key",
            "NPM_PUBLISH_TOKEN",
            "--format",
            "raw",
        ],
    );
    assert_eq!(rotated.trim(), "npm_newtoken000000000000000000000000000000");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_cli_skips_npm_revoke_when_github_sink_fails() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let refresh_path = state_dir.join("npm.refresh");
    let access_path = state_dir.join("npm.access");
    let admin_token_path = state_dir.join("admin.token");
    let otp_path = state_dir.join("npm.otp");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    fs::write(&otp_path, b"123456\n").expect("write otp");
    set_0600(&admin_token_path);
    set_0600(&otp_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let fort_agent = std::env::var("CARGO_BIN_EXE_fort-agent").expect("fort-agent path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "create",
            "--id",
            "npm-rotator-sink-fail",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "policy",
            "set",
            "--id",
            "npm-rotator-sink-fail",
            "--bind",
            "safe:dev:get,set",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "auth",
            "session",
            "open",
            "--agent",
            "npm-rotator-sink-fail",
            "--access-ttl",
            "3m",
            "--refresh-ttl",
            "30m",
            "--refresh-token-out",
            refresh_path.to_str().unwrap(),
        ],
    );
    set_0600(&refresh_path);
    run_ok(
        &fort_agent,
        &[
            "--once",
            "--host",
            &host,
            "--refresh-token-file",
            refresh_path.to_str().unwrap(),
            "--token-path",
            access_path.to_str().unwrap(),
        ],
    );
    set_0600(&access_path);

    for (key, value) in [
        (
            "NPM_PUBLISH_TOKEN",
            "npm_oldtoken000000000000000000000000000000",
        ),
        (
            "NPM_MANAGEMENT_TOKEN",
            "npm_management00000000000000000000000000",
        ),
        ("NPM_PASSWORD", "npm-password"),
        ("GITHUB_ACTIONS_TOKEN", "ghp_mockgithubtoken"),
    ] {
        run_ok(
            &fort,
            &[
                "--host",
                &host,
                "--token-file",
                access_path.to_str().unwrap(),
                "set",
                "--repo",
                "safe",
                "--env",
                "dev",
                "--key",
                key,
                "--value",
                value,
            ],
        );
    }

    let (registry_url, npm_mock) =
        start_mock_npm_registry_without_revoke("fort-e2e-sink-fail".to_string());
    let (github_url, github_mock) = start_mock_github_actions_secret_api(true);
    let output = Command::new(&fort)
        .args([
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "--json",
            "rotate",
            "npm",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--token-key",
            "NPM_PUBLISH_TOKEN",
            "--management-token-key",
            "NPM_MANAGEMENT_TOKEN",
            "--password-key",
            "NPM_PASSWORD",
            "--otp-file",
            otp_path.to_str().unwrap(),
            "--name",
            "fort-e2e-sink-fail",
            "--all-packages",
            "--bypass-2fa",
            "--revoke-old",
            "--registry",
            &registry_url,
            "--github-actions-repo",
            "Aureuma/svelta-blog",
            "--github-secret-name",
            "NPM_TOKEN",
            "--github-token-key",
            "GITHUB_ACTIONS_TOKEN",
            "--github-api-base",
            &github_url,
        ])
        .output()
        .expect("run npm rotation");
    assert!(
        !output.status.success(),
        "npm rotation succeeded unexpectedly: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("github request failed (status=500)"),
        "command output missing expected sink failure: combined={combined}",
    );
    assert!(
        !combined.contains("npm_newtoken000000000000000000000000000000"),
        "failure output leaked the new token: combined={combined}",
    );
    // The npm mock panics if a revoke DELETE arrives; joining it proves the
    // old token was left alone after the sink failure.
    npm_mock.join().expect("mock npm registry");
    github_mock.join().expect("mock github api");

    // Fort was already updated before the sink ran, so the new token is live
    // in Fort while the old npm token stays valid for retry/rollback.
    let rotated = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "get",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--key",
            "NPM_PUBLISH_TOKEN",
            "--format",
            "raw",
        ],
    );
    assert_eq!(rotated.trim(), "npm_newtoken000000000000000000000000000000");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_cli_rotates_passwordless_npm_token_through_mock_registry() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let refresh_path = state_dir.join("npm.refresh");
    let access_path = state_dir.join("npm.access");
    let admin_token_path = state_dir.join("admin.token");
    let otp_path = state_dir.join("npm.otp");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    fs::write(&otp_path, b"123456\n").expect("write otp");
    set_0600(&admin_token_path);
    set_0600(&otp_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let fort_agent = std::env::var("CARGO_BIN_EXE_fort-agent").expect("fort-agent path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "create",
            "--id",
            "npm-rotator-passwordless",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "policy",
            "set",
            "--id",
            "npm-rotator-passwordless",
            "--bind",
            "safe:dev:get,set",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "auth",
            "session",
            "open",
            "--agent",
            "npm-rotator-passwordless",
            "--access-ttl",
            "3m",
            "--refresh-ttl",
            "30m",
            "--refresh-token-out",
            refresh_path.to_str().unwrap(),
        ],
    );
    set_0600(&refresh_path);
    run_ok(
        &fort_agent,
        &[
            "--once",
            "--host",
            &host,
            "--refresh-token-file",
            refresh_path.to_str().unwrap(),
            "--token-path",
            access_path.to_str().unwrap(),
        ],
    );
    set_0600(&access_path);

    for (key, value) in [
        (
            "NPM_PUBLISH_TOKEN",
            "npm_oldtoken000000000000000000000000000000",
        ),
        (
            "NPM_MANAGEMENT_TOKEN",
            "npm_management00000000000000000000000000",
        ),
    ] {
        run_ok(
            &fort,
            &[
                "--host",
                &host,
                "--token-file",
                access_path.to_str().unwrap(),
                "set",
                "--repo",
                "safe",
                "--env",
                "dev",
                "--key",
                key,
                "--value",
                value,
            ],
        );
    }

    let (registry_url, npm_mock) = start_mock_npm_registry(
        NpmMockMode::Passwordless,
        "fort-e2e-passwordless".to_string(),
    );
    let output = Command::new(&fort)
        .args([
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "--json",
            "rotate",
            "npm",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--token-key",
            "NPM_PUBLISH_TOKEN",
            "--management-token-key",
            "NPM_MANAGEMENT_TOKEN",
            "--otp-file",
            otp_path.to_str().unwrap(),
            "--name",
            "fort-e2e-passwordless",
            "--all-packages",
            "--revoke-old",
            "--registry",
            &registry_url,
        ])
        .output()
        .expect("run npm rotation");
    assert!(
        output.status.success(),
        "npm rotation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"old_token_revoked\": true"));
    assert!(!stdout.contains("npm_newtoken000000000000000000000000000000"));
    npm_mock.join().expect("mock npm registry");

    let rotated = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "get",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--key",
            "NPM_PUBLISH_TOKEN",
            "--format",
            "raw",
        ],
    );
    assert_eq!(rotated.trim(), "npm_newtoken000000000000000000000000000000");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_cli_rejects_password_required_npm_rotation_without_password_key() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let refresh_path = state_dir.join("npm.refresh");
    let access_path = state_dir.join("npm.access");
    let admin_token_path = state_dir.join("admin.token");
    let otp_path = state_dir.join("npm.otp");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    fs::write(&otp_path, b"123456\n").expect("write otp");
    set_0600(&admin_token_path);
    set_0600(&otp_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let fort_agent = std::env::var("CARGO_BIN_EXE_fort-agent").expect("fort-agent path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "create",
            "--id",
            "npm-rotator-password-required",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "policy",
            "set",
            "--id",
            "npm-rotator-password-required",
            "--bind",
            "safe:dev:get,set",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "auth",
            "session",
            "open",
            "--agent",
            "npm-rotator-password-required",
            "--access-ttl",
            "3m",
            "--refresh-ttl",
            "30m",
            "--refresh-token-out",
            refresh_path.to_str().unwrap(),
        ],
    );
    set_0600(&refresh_path);
    run_ok(
        &fort_agent,
        &[
            "--once",
            "--host",
            &host,
            "--refresh-token-file",
            refresh_path.to_str().unwrap(),
            "--token-path",
            access_path.to_str().unwrap(),
        ],
    );
    set_0600(&access_path);

    for (key, value) in [
        (
            "NPM_PUBLISH_TOKEN",
            "npm_oldtoken000000000000000000000000000000",
        ),
        (
            "NPM_MANAGEMENT_TOKEN",
            "npm_management00000000000000000000000000",
        ),
    ] {
        run_ok(
            &fort,
            &[
                "--host",
                &host,
                "--token-file",
                access_path.to_str().unwrap(),
                "set",
                "--repo",
                "safe",
                "--env",
                "dev",
                "--key",
                key,
                "--value",
                value,
            ],
        );
    }

    let (registry_url, npm_mock) = start_mock_npm_registry(
        NpmMockMode::RejectWithoutPassword,
        "fort-e2e-password-required".to_string(),
    );
    let output = Command::new(&fort)
        .args([
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "--json",
            "rotate",
            "npm",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--token-key",
            "NPM_PUBLISH_TOKEN",
            "--management-token-key",
            "NPM_MANAGEMENT_TOKEN",
            "--otp-file",
            otp_path.to_str().unwrap(),
            "--name",
            "fort-e2e-password-required",
            "--all-packages",
            "--revoke-old",
            "--registry",
            &registry_url,
        ])
        .output()
        .expect("run npm rotation");
    assert!(
        !output.status.success(),
        "npm rotation succeeded unexpectedly: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Provide --password-key for this token-management credential."),
        "command output missing expected password-guidance: combined={combined}",
    );

    npm_mock.join().expect("mock npm registry");

    let rotated = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "get",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--key",
            "NPM_PUBLISH_TOKEN",
            "--format",
            "raw",
        ],
    );
    assert_eq!(rotated.trim(), "npm_oldtoken000000000000000000000000000000");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_cli_reports_missing_password_secret_for_npm_rotation() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let refresh_path = state_dir.join("npm.refresh");
    let access_path = state_dir.join("npm.access");
    let admin_token_path = state_dir.join("admin.token");
    let otp_path = state_dir.join("npm.otp");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    fs::write(&otp_path, b"123456\n").expect("write otp");
    set_0600(&admin_token_path);
    set_0600(&otp_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let fort_agent = std::env::var("CARGO_BIN_EXE_fort-agent").expect("fort-agent path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "create",
            "--id",
            "npm-rotator-password-secret-missing",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "policy",
            "set",
            "--id",
            "npm-rotator-password-secret-missing",
            "--bind",
            "safe:dev:get,set",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "auth",
            "session",
            "open",
            "--agent",
            "npm-rotator-password-secret-missing",
            "--access-ttl",
            "3m",
            "--refresh-ttl",
            "30m",
            "--refresh-token-out",
            refresh_path.to_str().unwrap(),
        ],
    );
    set_0600(&refresh_path);
    run_ok(
        &fort_agent,
        &[
            "--once",
            "--host",
            &host,
            "--refresh-token-file",
            refresh_path.to_str().unwrap(),
            "--token-path",
            access_path.to_str().unwrap(),
        ],
    );
    set_0600(&access_path);

    for (key, value) in [
        (
            "NPM_PUBLISH_TOKEN",
            "npm_oldtoken000000000000000000000000000000",
        ),
        (
            "NPM_MANAGEMENT_TOKEN",
            "npm_management00000000000000000000000000",
        ),
    ] {
        run_ok(
            &fort,
            &[
                "--host",
                &host,
                "--token-file",
                access_path.to_str().unwrap(),
                "set",
                "--repo",
                "safe",
                "--env",
                "dev",
                "--key",
                key,
                "--value",
                value,
            ],
        );
    }

    let output = Command::new(&fort)
        .args([
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "rotate",
            "npm",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--token-key",
            "NPM_PUBLISH_TOKEN",
            "--management-token-key",
            "NPM_MANAGEMENT_TOKEN",
            "--password-key",
            "NPM_PASSWORD",
            "--otp-file",
            otp_path.to_str().unwrap(),
            "--name",
            "fort-e2e-password-missing",
            "--package",
            "@scope/test",
        ])
        .output()
        .expect("run npm rotation");
    assert!(
        !output.status.success(),
        "npm rotation succeeded unexpectedly: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing required secret for npm rotation: safe/dev/NPM_PASSWORD"),
        "unexpected error output: {}",
        stderr
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_backend_fails_fast_when_safe_root_or_keyring_mounts_are_wrong() {
    let temp = TempDir::new().expect("tempdir");
    let safe_root = temp.path().join("safe");
    let keyring_path = temp.path().join("vault-keyring.json");

    let missing_safe = fort::vaultbridge::Backend::new(fort::vaultbridge::Config {
        safe_root: safe_root.display().to_string(),
        keyring_path: keyring_path.display().to_string(),
        extra_priv_keys: Vec::new(),
    });
    assert!(missing_safe.is_err(), "missing safe root must fail");

    fs::create_dir_all(&safe_root).expect("mkdir safe root");
    fs::write(&keyring_path, b"{\"entries\":{}}\n").expect("write keyring");
    set_0600(&keyring_path);

    fort::vaultbridge::Backend::new(fort::vaultbridge::Config {
        safe_root: safe_root.display().to_string(),
        keyring_path: keyring_path.display().to_string(),
        extra_priv_keys: Vec::new(),
    })
    .expect("valid mounts");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&keyring_path)
            .expect("stat keyring")
            .permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&keyring_path, perms).expect("chmod keyring");
    }

    let open_keyring = fort::vaultbridge::Backend::new(fort::vaultbridge::Config {
        safe_root: safe_root.display().to_string(),
        keyring_path: keyring_path.display().to_string(),
        extra_priv_keys: Vec::new(),
    });
    assert!(open_keyring.is_err(), "open keyring permissions must fail");
}

#[test]
fn fort_cli_rejects_managed_refresh_token_rotation_to_detached_path() {
    let temp = TempDir::new().expect("tempdir");
    let refresh_path = temp.path().join(".fort/session/refresh.token");
    fs::create_dir_all(refresh_path.parent().expect("refresh parent")).expect("mkdir fort dir");
    fs::write(&refresh_path, "profile-refresh-token\n").expect("write profile refresh token");
    set_0600(&refresh_path);
    let out_path = temp.path().join("detached-refresh.token");
    let empty_session_dir = temp.path().join("empty-session");
    fs::create_dir_all(&empty_session_dir).expect("mkdir empty session dir");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let output = Command::new(fort)
        .args([
            "--host",
            "http://127.0.0.1:1",
            "auth",
            "session",
            "refresh",
            "--refresh-token-file",
            refresh_path.to_str().expect("refresh path"),
            "--refresh-token-out",
            out_path.to_str().expect("out path"),
        ])
        .env("FORT_SESSION_DIR", &empty_session_dir)
        .env_remove("FORT_HOST")
        .env_remove("FORT_TOKEN_PATH")
        .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
        .output()
        .expect("run fort refresh");

    assert!(
        !output.status.success(),
        "refresh succeeded unexpectedly: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !out_path.exists(),
        "detached refresh token should not be written"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to rotate managed Fort refresh token"));
    assert!(stderr.contains("refreshed in place"));
}

#[test]
fn fort_version_reports_without_host() {
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let missing_settings = std::env::temp_dir().join("fort-missing-settings.toml");
    let _ = fs::remove_file(&missing_settings);
    let output = Command::new(fort)
        .arg("version")
        .env_remove("FORT_HOST")
        .env("FORT_SETTINGS_FILE", &missing_settings)
        .env_remove("FORT_TOKEN_PATH")
        .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
        .output()
        .expect("run fort version");
    assert!(
        output.status.success(),
        "fort version failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn fort_version_flag_agrees_with_subcommand() {
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let missing_settings = std::env::temp_dir().join("fort-missing-settings.toml");
    let _ = fs::remove_file(&missing_settings);
    let expected_flag = format!("fort {}", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        let output = Command::new(&fort)
            .arg(flag)
            .env_remove("FORT_HOST")
            .env("FORT_SETTINGS_FILE", &missing_settings)
            .env_remove("FORT_TOKEN_PATH")
            .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
            .output()
            .expect("run fort version flag");
        assert!(
            output.status.success(),
            "fort {flag} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            expected_flag
        );
    }
    let subcommand = Command::new(&fort)
        .arg("version")
        .env_remove("FORT_HOST")
        .env("FORT_SETTINGS_FILE", &missing_settings)
        .env_remove("FORT_TOKEN_PATH")
        .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
        .output()
        .expect("run fort version");
    assert!(subcommand.status.success());
    let subcommand_version = String::from_utf8_lossy(&subcommand.stdout)
        .trim()
        .to_string();
    assert_eq!(subcommand_version, env!("CARGO_PKG_VERSION"));
    assert!(
        expected_flag.ends_with(&subcommand_version),
        "flag output {expected_flag} does not agree with subcommand output {subcommand_version}"
    );
}

#[test]
fn fortd_version_reports_without_config() {
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let output = Command::new(&fortd)
        .arg("version")
        .output()
        .expect("run fortd version");
    assert!(
        output.status.success(),
        "fortd version failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        env!("CARGO_PKG_VERSION")
    );
    let expected_flag = format!("fortd {}", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        let output = Command::new(&fortd)
            .arg(flag)
            .output()
            .expect("run fortd version flag");
        assert!(
            output.status.success(),
            "fortd {flag} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            expected_flag
        );
    }
}

#[test]
fn cli_errors_print_full_chain() {
    // Top-level mains must print `{error:#}` (full anyhow chain), not
    // `{error}` (outermost context only), so inner details like HTTP
    // statuses and OS errors survive in logs.
    let temp = TempDir::new().expect("tempdir");
    let missing = temp.path().join("does-not-exist");
    let missing_str = missing.to_string_lossy().to_string();

    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let output = Command::new(&fort)
        .args([
            "--host",
            "http://127.0.0.1:1",
            "--token-file",
            &missing_str,
            "doctor",
        ])
        .env_remove("FORT_TOKEN_PATH")
        .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
        .output()
        .expect("run fort doctor with missing token file");
    assert!(
        !output.status.success(),
        "fort doctor unexpectedly succeeded with a missing token file"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("No such file or directory"),
        "fort hid the inner error: {stderr}"
    );

    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let output = Command::new(&fortd)
        .args(["--config-file", &missing_str])
        .output()
        .expect("run fortd with missing config file");
    assert!(
        !output.status.success(),
        "fortd unexpectedly succeeded with a missing config file"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("read config") && stderr.contains("No such file or directory"),
        "fortd hid the inner error: {stderr}"
    );

    let agent = std::env::var("CARGO_BIN_EXE_fort-agent").expect("fort-agent path");
    let output = Command::new(&agent)
        .args([
            "--host",
            "http://127.0.0.1:1",
            "--refresh-token-file",
            &missing_str,
            "--token-path",
            &temp.path().join("access.token").to_string_lossy(),
            "--once",
        ])
        .env_remove("FORT_HOST")
        .env_remove("FORT_REFRESH_TOKEN_FILE")
        .output()
        .expect("run fort-agent with missing refresh token file");
    assert!(
        !output.status.success(),
        "fort-agent unexpectedly succeeded with a missing refresh token file"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("No such file or directory"),
        "fort-agent hid the inner error: {stderr}"
    );

    let seed = std::env::var("CARGO_BIN_EXE_fort-seed").expect("fort-seed path");
    let corrupt = temp.path().join("corrupt-state.json");
    fs::write(&corrupt, "not-json").expect("write corrupt state");
    let output = Command::new(&seed)
        .env("STATE_PATH", &corrupt)
        .env("KEYRING_PATH", temp.path().join("keyring.json"))
        .env("SIGNING_KEY_PATH", temp.path().join("signing.key"))
        .env("PROFILE_IDS", "")
        .output()
        .expect("run fort-seed with corrupt state");
    assert!(
        !output.status.success(),
        "fort-seed unexpectedly succeeded with corrupt state"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("decode state") && stderr.contains("line 1 column"),
        "fort-seed hid the inner error: {stderr}"
    );
}

#[test]
fn remaining_bins_version_flags_agree_with_cargo_toml() {
    for (bin_env, bin_name) in [
        ("CARGO_BIN_EXE_fort-agent", "fort-agent"),
        ("CARGO_BIN_EXE_fort-seed", "fort-seed"),
        ("CARGO_BIN_EXE_fort-breakglass", "fort-breakglass"),
        ("CARGO_BIN_EXE_fort-release", "fort-release"),
    ] {
        let bin = std::env::var(bin_env).expect("bin path");
        let expected = format!("{bin_name} {}", env!("CARGO_PKG_VERSION"));
        for flag in ["--version", "-V"] {
            let output = Command::new(&bin)
                .arg(flag)
                .output()
                .expect("run version flag");
            assert!(
                output.status.success(),
                "{bin_name} {flag} failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&output.stdout).trim(),
                expected,
                "{bin_name} {flag} disagrees with Cargo.toml"
            );
        }
    }
}

#[test]
fn fort_release_version_subcommand_reports_bare_version() {
    let release = std::env::var("CARGO_BIN_EXE_fort-release").expect("fort-release path");
    let output = Command::new(&release)
        .arg("version")
        .output()
        .expect("run fort-release version");
    assert!(
        output.status.success(),
        "fort-release version failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn fort_breakglass_issues_single_active_admin_token() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");
    let first_token_path = state_dir.join("breakglass-1.token");
    let second_token_path = state_dir.join("breakglass-2.token");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let breakglass = std::env::var("CARGO_BIN_EXE_fort-breakglass").expect("fort-breakglass path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "create",
            "--id",
            "fort-breakglass-admin",
            "--type",
            "user",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "policy",
            "set",
            "--id",
            "fort-breakglass-admin",
            "--bind",
            "*:*:*",
        ],
    );

    let first = run_capture(
        &breakglass,
        &[
            "--state-path",
            state_path.to_str().unwrap(),
            "--signing-key-file",
            signing_key_path.to_str().unwrap(),
        ],
    );
    assert!(!first.trim().is_empty(), "breakglass must print a token");
    fs::write(&first_token_path, first.trim().as_bytes()).expect("write first token");
    set_0600(&first_token_path);
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            first_token_path.to_str().unwrap(),
            "doctor",
        ],
    );

    let second = run_capture(
        &breakglass,
        &[
            "--state-path",
            state_path.to_str().unwrap(),
            "--signing-key-file",
            signing_key_path.to_str().unwrap(),
        ],
    );
    assert_ne!(first.trim(), second.trim(), "reissue must mint a new token");
    fs::write(&second_token_path, second.trim().as_bytes()).expect("write second token");
    set_0600(&second_token_path);

    run_fails(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            first_token_path.to_str().unwrap(),
            "doctor",
        ],
        "auth: failed",
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            second_token_path.to_str().unwrap(),
            "doctor",
        ],
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&signing_key_path)
            .expect("stat signing key")
            .permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&signing_key_path, perms).expect("chmod signing key");
    }
    let output = Command::new(&breakglass)
        .args([
            "--state-path",
            state_path.to_str().unwrap(),
            "--signing-key-file",
            signing_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("run breakglass with open key file");
    assert!(
        !output.status.success(),
        "breakglass must reject a too-open signing key file"
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_cli_uses_managed_session_without_flags() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");
    let secret_value_path = state_dir.join("managed-value");
    let missing_settings = state_dir.join("missing-settings.toml");
    let managed_dir = temp.path().join("session");
    fs::create_dir_all(&managed_dir).expect("mkdir managed fort dir");
    let managed_refresh = managed_dir.join("refresh.token");
    let managed_access = managed_dir.join("access.token");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);
    fs::write(&secret_value_path, b"managed-secret\n").expect("write secret value");
    set_0600(&secret_value_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "set",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--key",
            "MANAGED_KEY",
            "--value-file",
            secret_value_path.to_str().unwrap(),
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "create",
            "--id",
            "session-worker",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "policy",
            "set",
            "--id",
            "session-worker",
            "--bind",
            "safe:dev:get",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "auth",
            "session",
            "open",
            "--agent",
            "session-worker",
            "--access-ttl",
            "3m",
            "--refresh-ttl",
            "30m",
            "--refresh-token-out",
            managed_refresh.to_str().unwrap(),
        ],
    );
    let first_refresh = fs::read_to_string(&managed_refresh).expect("read managed refresh");
    assert!(
        !managed_access.exists(),
        "no access token file before first managed use"
    );

    let managed_get = || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "get",
                "--repo",
                "safe",
                "--env",
                "dev",
                "--key",
                "MANAGED_KEY",
                "--format",
                "raw",
            ])
            .env("FORT_SESSION_DIR", &managed_dir)
            .env("FORT_SETTINGS_FILE", &missing_settings)
            .env_remove("FORT_HOST")
            .env_remove("FORT_TOKEN_PATH")
            .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
            .output()
            .expect("run managed fort get")
    };

    let output = managed_get();
    assert!(
        output.status.success(),
        "managed get failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "managed-secret"
    );
    assert!(
        managed_access.exists(),
        "bootstrap must write the managed access token file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&managed_access)
                .expect("stat managed access")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let second_refresh = fs::read_to_string(&managed_refresh).expect("read rotated refresh");
    assert_ne!(
        first_refresh.trim(),
        second_refresh.trim(),
        "bootstrap must rotate the managed refresh token"
    );

    let output = managed_get();
    assert!(
        output.status.success(),
        "second managed get failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&managed_refresh).expect("read refresh again"),
        second_refresh,
        "a fresh managed session must not rotate again"
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_list_survives_early_closed_stdout() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");
    let secret_value_path = state_dir.join("pipe-value");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);
    fs::write(&secret_value_path, b"pipe-secret\n").expect("write secret value");
    set_0600(&secret_value_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    for index in 0..30 {
        run_ok(
            &fort,
            &[
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().unwrap(),
                "set",
                "--repo",
                "safe",
                "--env",
                "dev",
                "--key",
                &format!("PIPE_KEY_{index:02}"),
                "--value-file",
                secret_value_path.to_str().unwrap(),
            ],
        );
    }

    let mut lister = Command::new(&fort)
        .args([
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "list",
            "--repo",
            "safe",
            "--env",
            "dev",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fort list");
    let mut probe = [0u8; 8];
    let _ = lister
        .stdout
        .as_mut()
        .expect("list stdout")
        .read(&mut probe);
    drop(lister.stdout.take());
    let output = lister.wait_with_output().expect("wait for fort list");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(
        output.status.code(),
        Some(101),
        "fort list must not panic on EPIPE: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "fort list must not panic on EPIPE: {stderr}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

fn seed_state(state_path: &PathBuf, keyring_path: &PathBuf, signing_key_path: &PathBuf) -> String {
    let seed = std::env::var("CARGO_BIN_EXE_fort-seed").expect("fort-seed path");
    let output = Command::new(seed)
        .env("STATE_PATH", state_path)
        .env("KEYRING_PATH", keyring_path)
        .env("SIGNING_KEY_PATH", signing_key_path)
        .output()
        .expect("run fort-seed");
    assert!(
        output.status.success(),
        "fort-seed failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8 token")
        .trim()
        .to_string()
}

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr.to_string()
}

fn wait_for(timeout: Duration, check: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("timeout waiting for condition");
}

fn run_ok(bin: &str, args: &[&str]) {
    let output = Command::new(bin).args(args).output().expect("run command");
    assert!(
        output.status.success(),
        "command failed: {} {:?}\nstdout={}\nstderr={}",
        bin,
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_capture(bin: &str, args: &[&str]) -> String {
    let output = Command::new(bin).args(args).output().expect("run command");
    assert!(
        output.status.success(),
        "command failed: {} {:?}\nstdout={}\nstderr={}",
        bin,
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

enum NpmMockMode {
    Password,
    Passwordless,
    RejectWithoutPassword,
}

fn run_fails(bin: &str, args: &[&str], expected_stdout: &str) {
    let output = Command::new(bin).args(args).output().expect("run command");
    assert!(
        !output.status.success(),
        "command succeeded unexpectedly: {} {:?}\nstdout={}\nstderr={}",
        bin,
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(expected_stdout),
        "command stdout missing {:?}: stdout={} stderr={}",
        expected_stdout,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn start_mock_npm_registry(
    mode: NpmMockMode,
    token_name: String,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock npm");
    let url = format!("http://{}", listener.local_addr().expect("mock addr"));
    let handle = thread::spawn(move || {
        let request_count = if matches!(mode, NpmMockMode::RejectWithoutPassword) {
            1
        } else {
            2
        };
        for index in 0..request_count {
            let (mut stream, _) = listener.accept().expect("accept mock npm request");
            let request = read_http_request(&mut stream);
            let request_lower = request.to_ascii_lowercase();
            if index == 0 {
                assert!(request.starts_with("POST /-/npm/v1/tokens "));
                assert!(request_lower.contains("authorization: bearer npm_management"));
                assert!(request_lower.contains("npm-otp: 123456"));
                assert!(request.contains(&format!("\"name\":\"{token_name}\"")));
                assert!(request.contains("\"packages\":[\"*\"]"));
                match mode {
                    NpmMockMode::Password => {
                        assert!(request.contains("\"password\":\"npm-password\""));
                    }
                    NpmMockMode::Passwordless => {
                        assert!(
                            !request.contains("\"password\":"),
                            "passwordless request should not contain password field: {request}"
                        );
                    }
                    NpmMockMode::RejectWithoutPassword => {
                        assert!(
                            !request.contains("\"password\":"),
                            "passwordless request should not contain password field: {request}"
                        );
                        let body = r#"{"error":"password is required"}"#;
                        write!(
                            stream,
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .expect("write create response");
                        continue;
                    }
                }
                let body = r#"{"key":"00000000-0000-4000-8000-000000000000","name":"fort-e2e","token":"npm_newtoken000000000000000000000000000000","expiry":"2026-09-08T00:00:00Z"}"#;
                write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .expect("write create response");
            } else {
                assert!(
                    request.starts_with(
                        "DELETE /-/npm/v1/tokens/token/npm_oldtoken000000000000000000000000000000 "
                    ),
                    "unexpected delete request: {request}"
                );
                assert!(request_lower.contains("authorization: bearer npm_management"));
                assert!(request_lower.contains("npm-otp: 123456"));
                write!(
                    stream,
                    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write delete response");
            }
        }
    });
    (url, handle)
}

fn start_mock_npm_registry_without_revoke(token_name: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock npm");
    let url = format!("http://{}", listener.local_addr().expect("mock addr"));
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept mock npm request");
        let request = read_http_request(&mut stream);
        let request_lower = request.to_ascii_lowercase();
        assert!(request.starts_with("POST /-/npm/v1/tokens "));
        assert!(request_lower.contains("authorization: bearer npm_management"));
        assert!(request_lower.contains("npm-otp: 123456"));
        assert!(request.contains(&format!("\"name\":\"{token_name}\"")));
        assert!(request.contains("\"password\":\"npm-password\""));
        let body = r#"{"key":"00000000-0000-4000-8000-000000000000","name":"fort-e2e","token":"npm_newtoken000000000000000000000000000000","expiry":"2026-09-08T00:00:00Z"}"#;
        write!(
            stream,
            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("write create response");
        // The old token must never be revoked when a downstream sink fails.
        // The CLI under test has already exited by the time this join
        // completes, so any further connection here is a revoke attempt.
        listener
            .set_nonblocking(true)
            .expect("nonblocking mock npm");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok(_) => panic!("npm revoke must not run after a failed sink"),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("unexpected mock npm accept error: {err}"),
            }
        }
    });
    (url, handle)
}

fn start_mock_github_actions_secret_api(
    fail_secret_update: bool,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock github");
    let url = format!(
        "http://{}",
        listener.local_addr().expect("mock github addr")
    );
    let handle = thread::spawn(move || {
        let public_key =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]);
        for index in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept mock github request");
            let request = read_http_request(&mut stream);
            let request_lower = request.to_ascii_lowercase();
            if index == 0 {
                assert!(
                    request
                        .starts_with("GET /repos/Aureuma/svelta-blog/actions/secrets/public-key "),
                    "unexpected public key request: {request}"
                );
                assert!(request_lower.contains("authorization: bearer ghp_mockgithubtoken"));
                let body = format!(r#"{{"key":"{public_key}","key_id":"mock-key-id"}}"#);
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .expect("write github public key response");
            } else {
                assert!(
                    request
                        .starts_with("PUT /repos/Aureuma/svelta-blog/actions/secrets/NPM_TOKEN "),
                    "unexpected secret update request: {request}"
                );
                assert!(request_lower.contains("authorization: bearer ghp_mockgithubtoken"));
                assert!(request.contains("\"key_id\":\"mock-key-id\""));
                assert!(request.contains("\"encrypted_value\":"));
                assert!(!request.contains("npm_newtoken000000000000000000000000000000"));
                if fail_secret_update {
                    let body = r#"{"message":"mock secret update failure"}"#;
                    write!(
                        stream,
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .expect("write github secret failure response");
                } else {
                    write!(
                        stream,
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .expect("write github secret response");
                }
            }
        }
    });
    (url, handle)
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut bytes = Vec::new();
    let mut buf = [0u8; 1024];
    let mut content_length = None;
    loop {
        let read = stream.read(&mut buf).expect("read mock request");
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read]);
        if content_length.is_none()
            && let Some(headers_end) = find_header_end(&bytes)
        {
            let headers = String::from_utf8_lossy(&bytes[..headers_end]);
            content_length = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            });
        }
        if let Some(headers_end) = find_header_end(&bytes) {
            let body_start = headers_end + 4;
            let expected = body_start + content_length.unwrap_or(0);
            if bytes.len() >= expected {
                break;
            }
        }
    }
    String::from_utf8(bytes).expect("request utf8")
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn set_0600(path: &PathBuf) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).expect("stat").permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).expect("chmod");
    }
}

#[test]
fn fort_github_pat_login_roundtrip_through_mock_github() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let pepper_path = state_dir.join("github-pepper");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");
    let pat_path = state_dir.join("machine.pat");
    let bad_pat_path = state_dir.join("bad.pat");
    let session_dir = temp.path().join("session");
    let bad_session_dir = temp.path().join("bad-session");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);
    fs::write(&pepper_path, "test-pepper-that-is-long-enough-32").expect("write pepper");
    set_0600(&pepper_path);
    fs::write(&pat_path, "valid-test-pat\n").expect("write pat");
    set_0600(&pat_path);
    fs::write(&bad_pat_path, "wrong-pat\n").expect("write bad pat");
    set_0600(&bad_pat_path);

    // enroll + login + bad-pat login + post-unenroll login = 4 GitHub calls.
    let (github_base, github_handle) = start_mock_github_user_api(4);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\ngithub_pepper_file = \"{}\"\ngithub_api_base = \"{}\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
            pepper_path.display(),
            github_base,
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    let admin = admin_token_path.to_str().unwrap().to_string();
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "agent",
            "create",
            "--id",
            "machine-test",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "agent",
            "policy",
            "set",
            "--id",
            "machine-test",
            "--bind",
            "safe:dev:get,set,list,batch-get,run",
        ],
    );
    let enroll_out = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "auth",
            "github",
            "enroll",
            "--agent",
            "machine-test",
            "--pat-file",
            pat_path.to_str().unwrap(),
        ],
    );
    assert!(
        enroll_out.contains("enrolled machine-test"),
        "enroll output: {enroll_out}"
    );
    assert!(
        !enroll_out.contains("valid-test-pat"),
        "enroll must not echo the PAT: {enroll_out}"
    );
    let list_out = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "auth",
            "github",
            "list",
        ],
    );
    assert!(
        list_out.contains("machine-test") && list_out.contains("test-machine"),
        "list output: {list_out}"
    );

    let login_out = run_capture_session(
        &fort,
        &[
            "--host",
            &host,
            "auth",
            "github",
            "login",
            "--pat-file",
            pat_path.to_str().unwrap(),
        ],
        &session_dir,
    );
    assert!(
        login_out.contains("logged in as machine-test"),
        "login output: {login_out}"
    );
    assert!(
        !login_out.contains("valid-test-pat"),
        "login must not echo the PAT: {login_out}"
    );
    let managed_access = session_dir.join("access.token");
    let managed_refresh = session_dir.join("refresh.token");
    assert!(managed_access.exists(), "login must write access token");
    assert!(managed_refresh.exists(), "login must write refresh token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&managed_access, &managed_refresh] {
            assert_eq!(
                fs::metadata(path)
                    .expect("stat session file")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "session file must be 0600: {}",
                path.display()
            );
        }
    }

    // The managed session works with no extra flags.
    let whoami_out = run_capture_session(&fort, &["--host", &host, "auth", "whoami"], &session_dir);
    assert!(
        whoami_out.contains("machine-test"),
        "whoami output: {whoami_out}"
    );
    let secret_value_path = state_dir.join("pat-value");
    fs::write(&secret_value_path, b"pat-secret\n").expect("write secret value");
    set_0600(&secret_value_path);
    run_ok_session(
        &fort,
        &[
            "--host",
            &host,
            "set",
            "--repo",
            "safe",
            "--env",
            "dev",
            "--key",
            "PAT_KEY",
            "--value-file",
            secret_value_path.to_str().unwrap(),
        ],
        &session_dir,
    );
    let get_out = run_capture_session(
        &fort,
        &[
            "--host", &host, "get", "--repo", "safe", "--env", "dev", "--key", "PAT_KEY",
            "--format", "raw",
        ],
        &session_dir,
    );
    assert_eq!(get_out.trim(), "pat-secret");

    // A wrong PAT is rejected without touching the session.
    let bad_login = Command::new(&fort)
        .args([
            "--host",
            &host,
            "auth",
            "github",
            "login",
            "--pat-file",
            bad_pat_path.to_str().unwrap(),
        ])
        .env("FORT_SESSION_DIR", &bad_session_dir)
        .output()
        .expect("run bad login");
    assert!(
        !bad_login.status.success(),
        "bad PAT login succeeded unexpectedly"
    );
    assert!(
        String::from_utf8_lossy(&bad_login.stderr).contains("unauthorized"),
        "bad login stderr: {}",
        String::from_utf8_lossy(&bad_login.stderr)
    );

    // Logout closes the server session and removes local files.
    run_ok_session(
        &fort,
        &["--host", &host, "auth", "github", "logout"],
        &session_dir,
    );
    assert!(!managed_access.exists(), "logout must remove access token");
    assert!(
        !managed_refresh.exists(),
        "logout must remove refresh token"
    );

    // After unenroll, the previously valid PAT no longer logs in.
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "auth",
            "github",
            "unenroll",
            "--agent",
            "machine-test",
        ],
    );
    let logged_out_login = Command::new(&fort)
        .args([
            "--host",
            &host,
            "auth",
            "github",
            "login",
            "--pat-file",
            pat_path.to_str().unwrap(),
        ])
        .env("FORT_SESSION_DIR", &bad_session_dir)
        .output()
        .expect("run post-unenroll login");
    assert!(
        !logged_out_login.status.success(),
        "post-unenroll login succeeded unexpectedly"
    );

    github_handle.join().expect("join mock github");
    let _ = child.kill();
    let _ = child.wait();
}

fn start_mock_github_user_api(expected_requests: usize) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock github");
    let url = format!(
        "http://{}",
        listener.local_addr().expect("mock github addr")
    );
    let handle = thread::spawn(move || {
        for _ in 0..expected_requests {
            let (mut stream, _) = listener.accept().expect("accept mock github request");
            let request = read_http_request(&mut stream);
            assert!(
                request.starts_with("GET /user "),
                "unexpected github request: {request}"
            );
            // The request path is asserted above; matching the bare PAT is
            // sufficient for this mock (only Fort knows the PAT).
            let authorized = request.contains("valid-test-pat");
            let (status, body) = if authorized {
                ("200 OK", r#"{"login":"test-machine","id":42}"#)
            } else {
                ("401 Unauthorized", r#"{"message":"Bad credentials"}"#)
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("write mock github response");
        }
    });
    (url, handle)
}

fn run_ok_session(bin: &str, args: &[&str], session_dir: &PathBuf) {
    let output = Command::new(bin)
        .args(args)
        .env("FORT_SESSION_DIR", session_dir)
        .env_remove("FORT_TOKEN_PATH")
        .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
        .output()
        .expect("run command");
    assert!(
        output.status.success(),
        "command failed: {} {:?}\nstdout={}\nstderr={}",
        bin,
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_capture_session(bin: &str, args: &[&str], session_dir: &PathBuf) -> String {
    let output = Command::new(bin)
        .args(args)
        .env("FORT_SESSION_DIR", session_dir)
        .env_remove("FORT_TOKEN_PATH")
        .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
        .output()
        .expect("run command");
    assert!(
        output.status.success(),
        "command failed: {} {:?}\nstdout={}\nstderr={}",
        bin,
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout utf8")
}

fn run_session_with_stdin(
    bin: &str,
    args: &[&str],
    session_dir: &PathBuf,
    stdin_data: &str,
) -> std::process::Output {
    let mut child = Command::new(bin)
        .args(args)
        .env("FORT_SESSION_DIR", session_dir)
        .env_remove("FORT_TOKEN_PATH")
        .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn command");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(stdin_data.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait command")
}

#[test]
fn fort_github_login_prompts_and_stores_pat() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let pepper_path = state_dir.join("github-pepper");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");
    let pat_path = state_dir.join("machine.pat");
    let session_dir = temp.path().join("session");
    let fresh_session_dir = temp.path().join("fresh-home").join("session");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);
    fs::write(&pepper_path, "test-pepper-that-is-long-enough-32").expect("write pepper");
    set_0600(&pepper_path);
    fs::write(&pat_path, "valid-test-pat\n").expect("write pat");
    set_0600(&pat_path);

    // enroll + piped-stdin login + stored-PAT re-login = 3 GitHub calls.
    let (github_base, github_handle) = start_mock_github_user_api(3);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\ngithub_pepper_file = \"{}\"\ngithub_api_base = \"{}\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
            pepper_path.display(),
            github_base,
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    let admin = admin_token_path.to_str().unwrap().to_string();
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "agent",
            "create",
            "--id",
            "prompt-test",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "agent",
            "policy",
            "set",
            "--id",
            "prompt-test",
            "--bind",
            "*:*:*",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "auth",
            "github",
            "enroll",
            "--agent",
            "prompt-test",
            "--pat-file",
            pat_path.to_str().unwrap(),
        ],
    );

    // Login without --pat-file reads the PAT from stdin and stores it.
    let login = run_session_with_stdin(
        &fort,
        &["--host", &host, "auth", "github", "login"],
        &session_dir,
        "valid-test-pat\n",
    );
    let login_stdout = String::from_utf8_lossy(&login.stdout).to_string();
    let login_stderr = String::from_utf8_lossy(&login.stderr).to_string();
    assert!(
        login.status.success(),
        "piped-stdin login failed: stdout={login_stdout} stderr={login_stderr}"
    );
    assert!(
        login_stdout.contains("logged in as prompt-test"),
        "login output: {login_stdout}"
    );
    assert!(
        !login_stdout.contains("valid-test-pat") && !login_stderr.contains("valid-test-pat"),
        "login must not echo the PAT: stdout={login_stdout} stderr={login_stderr}"
    );
    let stored_pat = session_dir
        .parent()
        .expect("session parent")
        .join("github.pat");
    assert!(stored_pat.exists(), "login must store the entered PAT");
    assert_eq!(
        fs::read_to_string(&stored_pat)
            .expect("read stored pat")
            .trim(),
        "valid-test-pat"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&stored_pat)
                .expect("stat stored pat")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "stored PAT must be 0600"
        );
    }

    // Re-login without --pat-file reuses the stored PAT (empty stdin).
    let relogin = run_session_with_stdin(
        &fort,
        &["--host", &host, "auth", "github", "login"],
        &session_dir,
        "",
    );
    let relogin_stdout = String::from_utf8_lossy(&relogin.stdout).to_string();
    let relogin_stderr = String::from_utf8_lossy(&relogin.stderr).to_string();
    assert!(
        relogin.status.success(),
        "stored-PAT re-login failed: stdout={relogin_stdout} stderr={relogin_stderr}"
    );
    assert!(
        relogin_stdout.contains("logged in as prompt-test"),
        "re-login output: {relogin_stdout}"
    );

    // With no stored PAT and no stdin, login fails without contacting GitHub.
    let missing = run_session_with_stdin(
        &fort,
        &["--host", &host, "auth", "github", "login"],
        &fresh_session_dir,
        "",
    );
    assert!(
        !missing.status.success(),
        "login without any PAT succeeded unexpectedly"
    );
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("--pat-file"),
        "missing-PAT error must mention --pat-file: {}",
        String::from_utf8_lossy(&missing.stderr)
    );

    github_handle.join().expect("join mock github");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_help_pages_have_no_blank_rows() {
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let pages: &[&[&str]] = &[
        &["--help"],
        &["version", "--help"],
        &["doctor", "--help"],
        &["auth", "--help"],
        &["auth", "issue", "--help"],
        &["auth", "login", "--help"],
        &["auth", "whoami", "--help"],
        &["auth", "list", "--help"],
        &["auth", "revoke", "--help"],
        &["auth", "session", "--help"],
        &["auth", "session", "open", "--help"],
        &["auth", "session", "refresh", "--help"],
        &["auth", "session", "close", "--help"],
        &["auth", "github", "--help"],
        &["auth", "github", "login", "--help"],
        &["auth", "github", "logout", "--help"],
        &["auth", "github", "enroll", "--help"],
        &["auth", "github", "unenroll", "--help"],
        &["auth", "github", "list", "--help"],
        &["get", "--help"],
        &["set", "--help"],
        &["list", "--help"],
        &["batch-get", "--help"],
        &["scope", "--help"],
        &["scope", "ensure", "--help"],
        &["run", "--help"],
        &["rotate", "--help"],
        &["rotate", "npm", "--help"],
        &["r2", "--help"],
        &["r2", "issue", "--help"],
        &["keys", "--help"],
        &["keys", "issue", "--help"],
        &["keys", "issue", "r2", "--help"],
        &["keys", "create", "--help"],
        &["keys", "create", "r2", "--help"],
        &["keys", "rotate", "--help"],
        &["keys", "rotate", "r2", "--help"],
        &["keys", "rotate", "npm", "--help"],
        &["keys", "revoke", "--help"],
        &["keys", "revoke", "r2", "--help"],
        &["keys", "list", "--help"],
        &["keys", "list", "r2", "--help"],
        &["keys", "audit", "--help"],
        &["keys", "audit", "r2", "--help"],
        &["agent", "--help"],
        &["agent", "create", "--help"],
        &["agent", "get", "--help"],
        &["agent", "list", "--help"],
        &["agent", "set-status", "--help"],
        &["agent", "rotate", "--help"],
        &["agent", "remove", "--help"],
        &["agent", "policy", "--help"],
        &["agent", "policy", "get", "--help"],
        &["agent", "policy", "set", "--help"],
        &["agent", "policy", "add", "--help"],
        &["agent", "policy", "remove", "--help"],
        &["agent", "policy", "check", "--help"],
    ];
    for page in pages {
        let output = Command::new(&fort)
            .args(*page)
            .output()
            .expect("run fort help");
        assert!(
            output.status.success(),
            "help page {:?} failed: {}",
            page,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_help_has_no_blank_rows(&format!("fort {}", page.join(" ")), &output.stdout);
    }

    for bin_env in [
        "CARGO_BIN_EXE_fortd",
        "CARGO_BIN_EXE_fort-agent",
        "CARGO_BIN_EXE_fort-breakglass",
        "CARGO_BIN_EXE_fort-seed",
    ] {
        let bin = std::env::var(bin_env).expect("bin path");
        let output = Command::new(&bin)
            .arg("--help")
            .output()
            .expect("run bin help");
        assert!(
            output.status.success(),
            "{bin_env} --help failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_help_has_no_blank_rows(bin_env, &output.stdout);
    }

    let release = std::env::var("CARGO_BIN_EXE_fort-release").expect("fort-release path");
    let release_pages: &[&[&str]] = &[
        &["--help"],
        &["self", "--help"],
        &["self", "validate-version", "--help"],
        &["self", "assets", "--help"],
        &["self", "verify", "--help"],
        &["installer", "--help"],
        &["installer", "smoke-host", "--help"],
        &["installer", "smoke-homebrew", "--help"],
        &["homebrew", "--help"],
        &["homebrew", "render-tap-formula", "--help"],
    ];
    for page in release_pages {
        let output = Command::new(&release)
            .args(*page)
            .output()
            .expect("run fort-release help");
        assert!(
            output.status.success(),
            "fort-release page {:?} failed: {}",
            page,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_help_has_no_blank_rows(&format!("fort-release {}", page.join(" ")), &output.stdout);
    }
}

fn assert_help_has_no_blank_rows(page: &str, stdout: &[u8]) {
    let text = String::from_utf8_lossy(stdout);
    assert!(
        text.contains("Usage:"),
        "{page} help is missing a Usage line: {text}"
    );
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim_end();
        if line.trim().is_empty() || !line.starts_with(char::is_whitespace) {
            index += 1;
            continue;
        }
        let body = line.trim_start();
        if body.starts_with('-') {
            // Flag row: described inline or by a following indented,
            // non-annotation line.
            let mut described = flag_row_has_inline_help(body);
            if described {
                index += 1;
                continue;
            }
            let mut cursor = index + 1;
            while cursor < lines.len() {
                let next = lines[cursor].trim_end();
                let next_trimmed = next.trim();
                if next_trimmed.is_empty() {
                    cursor += 1;
                    continue;
                }
                if !next.starts_with(char::is_whitespace)
                    || next_trimmed.starts_with('-')
                    || next_trimmed.starts_with('[')
                {
                    break;
                }
                described = true;
                break;
            }
            assert!(
                described,
                "{page} help has an undocumented flag row: {line}\n{text}"
            );
        } else {
            // Command row: name plus description on the same line.
            let mut parts = body.split_whitespace();
            let name = parts.next().unwrap_or_default();
            let described = parts.next().is_some();
            assert!(
                !name.is_empty() && described,
                "{page} help has an undocumented command row: {line}\n{text}"
            );
        }
        index += 1;
    }
}

fn flag_row_has_inline_help(body: &str) -> bool {
    let mut rest = body.trim_start();
    loop {
        let token = rest.split_whitespace().next().unwrap_or_default();
        if token.starts_with('-') || token.starts_with('<') || token.starts_with('[') {
            rest = rest[token.len()..].trim_start();
        } else {
            break;
        }
    }
    !rest.is_empty()
}

#[test]
fn fort_github_login_succeeds_with_dead_managed_session() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let pepper_path = state_dir.join("github-pepper");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");
    let pat_path = state_dir.join("machine.pat");
    let session_dir = temp.path().join("session");
    fs::create_dir_all(&session_dir).expect("mkdir session");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);
    fs::write(&pepper_path, "test-pepper-that-is-long-enough-32").expect("write pepper");
    set_0600(&pepper_path);
    fs::write(&pat_path, "valid-test-pat\n").expect("write pat");
    set_0600(&pat_path);

    // enroll + login = 2 GitHub calls.
    let (github_base, github_handle) = start_mock_github_user_api(2);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\ngithub_pepper_file = \"{}\"\ngithub_api_base = \"{}\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
            pepper_path.display(),
            github_base,
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    let admin = admin_token_path.to_str().unwrap().to_string();
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "agent",
            "create",
            "--id",
            "dead-session-test",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "agent",
            "policy",
            "set",
            "--id",
            "dead-session-test",
            "--bind",
            "*:*:*",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "auth",
            "github",
            "enroll",
            "--agent",
            "dead-session-test",
            "--pat-file",
            pat_path.to_str().unwrap(),
        ],
    );

    // Poison the managed session: an unparseable access token forces a
    // refresh attempt, and the dead refresh token makes the server reject
    // it. Login must not trip over this; it replaces the session.
    let dead_access = session_dir.join("access.token");
    let dead_refresh = session_dir.join("refresh.token");
    fs::write(&dead_access, "invalid-token\n").expect("write dead access");
    set_0600(&dead_access);
    fs::write(&dead_refresh, "dead-refresh-token\n").expect("write dead refresh");
    set_0600(&dead_refresh);

    let login = run_capture_session(
        &fort,
        &[
            "--host",
            &host,
            "auth",
            "github",
            "login",
            "--pat-file",
            pat_path.to_str().unwrap(),
        ],
        &session_dir,
    );
    assert!(
        login.contains("logged in as dead-session-test"),
        "login output: {login}"
    );

    let whoami = run_capture_session(&fort, &["--host", &host, "auth", "whoami"], &session_dir);
    assert!(
        whoami.contains("dead-session-test"),
        "whoami output: {whoami}"
    );

    github_handle.join().expect("join mock github");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn fort_concurrent_managed_bootstrap_keeps_session_alive() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");
    let provisioned_refresh = state_dir.join("provisioned.refresh");
    let managed_dir = temp.path().join("session");
    fs::create_dir_all(&managed_dir).expect("mkdir session");
    let managed_access = managed_dir.join("access.token");
    let managed_refresh = managed_dir.join("refresh.token");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    let admin = admin_token_path.to_str().unwrap().to_string();
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "agent",
            "create",
            "--id",
            "conc-test",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "agent",
            "policy",
            "set",
            "--id",
            "conc-test",
            "--bind",
            "*:*:*",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            &admin,
            "auth",
            "session",
            "open",
            "--agent",
            "conc-test",
            "--refresh-token-out",
            provisioned_refresh.to_str().unwrap(),
        ],
    );
    fs::copy(&provisioned_refresh, &managed_refresh).expect("install refresh");
    set_0600(&managed_refresh);

    // Drop the access token so every worker bootstraps through a refresh.
    // Unserialized refreshes would POST the same refresh token and the
    // server would revoke the session as reuse compromise.
    for _ in 0..3 {
        let _ = fs::remove_file(&managed_access);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let (fort, host, managed) = (fort.clone(), host.clone(), managed_dir.clone());
            handles.push(thread::spawn(move || {
                let output = Command::new(&fort)
                    .args(["--host", host.as_str(), "auth", "whoami"])
                    .env("FORT_SESSION_DIR", &managed)
                    .env_remove("FORT_TOKEN_PATH")
                    .env_remove("FORT_BOOTSTRAP_TOKEN_FILE")
                    .output()
                    .expect("run whoami");
                assert!(
                    output.status.success(),
                    "concurrent whoami failed: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }));
        }
        for handle in handles {
            handle.join().expect("join worker");
        }
    }

    let whoami = run_capture_session(&fort, &["--host", &host, "auth", "whoami"], &managed_dir);
    assert!(whoami.contains("conc-test"), "whoami output: {whoami}");

    let _ = child.kill();
    let _ = child.wait();
}

fn start_mock_r2_issuer() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock r2");
    let url = format!("http://{}", listener.local_addr().expect("mock addr"));
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept mock r2 request");
        let request = read_http_request(&mut stream);
        let request_lower = request.to_ascii_lowercase();
        assert!(
            request.starts_with("POST /accounts/test-account/r2/temp-access-credentials "),
            "unexpected r2 request: {request}"
        );
        assert!(request_lower.contains("authorization: bearer r2_issuer_token"));
        assert!(request.contains("\"bucket\":\"ly-restic\""));
        assert!(request.contains("\"parentAccessKeyId\":\"r2_parent_access_key\""));
        assert!(request.contains("\"permission\":\"object-read-only\""));
        assert!(request.contains("\"ttlSeconds\":600"));
        let body = r#"{"success":true,"errors":[],"messages":[],"result":{"accessKeyId":"r2_temp_access_key","secretAccessKey":"r2_temp_secret","sessionToken":"r2_temp_session"}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("write r2 response");
    });
    (url, handle)
}

#[test]
fn fort_cli_issues_r2_temp_credentials_through_mock_cloudflare() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");
    let refresh_path = state_dir.join("r2.refresh");
    let access_path = state_dir.join("r2.access");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);

    let (r2_base, r2_mock) = start_mock_r2_issuer();

    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let fort_agent = std::env::var("CARGO_BIN_EXE_fort-agent").expect("fort-agent path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\nr2_api_base = \"{r2_base}\"\nr2_account_id = \"test-account\"\nr2_issuer_repo = \"infra\"\nr2_issuer_env = \"prod\"\nr2_issuer_token_key = \"R2_ISSUER_TOKEN\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    for (repo, env) in [("infra", "prod"), ("r2b", "prod")] {
        run_ok(
            &fort,
            &[
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().unwrap(),
                "scope",
                "ensure",
                "--repo",
                repo,
                "--env",
                env,
            ],
        );
    }
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "set",
            "--repo",
            "infra",
            "--env",
            "prod",
            "--key",
            "R2_ISSUER_TOKEN",
            "--value",
            "r2_issuer_token",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "set",
            "--repo",
            "r2b",
            "--env",
            "prod",
            "--key",
            "PARENT_KEY",
            "--value",
            "r2_parent_access_key",
        ],
    );

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "keys",
            "issue",
            "r2",
            "--bucket",
            "ly-restic",
            "--permission",
            "object-read-only",
            "--ttl-seconds",
            "600",
            "--parent-repo",
            "r2b",
            "--parent-env",
            "prod",
            "--parent-key",
            "PARENT_KEY",
            "--dry-run",
        ],
    );

    let legacy = Command::new(&fort)
        .args([
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "r2",
            "issue",
            "--bucket",
            "ly-restic",
            "--permission",
            "object-read-only",
            "--ttl-seconds",
            "600",
            "--parent-repo",
            "r2b",
            "--parent-env",
            "prod",
            "--parent-key",
            "PARENT_KEY",
            "--dry-run",
        ])
        .output()
        .expect("run legacy r2 issue");
    assert!(
        legacy.status.success(),
        "legacy r2 issue failed: {}",
        String::from_utf8_lossy(&legacy.stderr)
    );
    assert!(
        String::from_utf8_lossy(&legacy.stderr).contains("deprecated"),
        "legacy r2 issue missing deprecation pointer"
    );

    let output = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "keys",
            "issue",
            "r2",
            "--bucket",
            "ly-restic",
            "--permission",
            "object-read-only",
            "--ttl-seconds",
            "600",
            "--parent-repo",
            "r2b",
            "--parent-env",
            "prod",
            "--parent-key",
            "PARENT_KEY",
        ],
    );
    assert!(
        output.contains("access_key_id=r2_temp_access_key"),
        "missing access key in output: {output}"
    );
    assert!(
        output.contains("secret_access_key=r2_temp_secret"),
        "missing secret key in output: {output}"
    );
    assert!(
        output.contains("session_token=r2_temp_session"),
        "missing session token in output: {output}"
    );

    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "agent",
            "create",
            "--id",
            "r2-client",
            "--type",
            "workload",
        ],
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "auth",
            "session",
            "open",
            "--agent",
            "r2-client",
            "--access-ttl",
            "3m",
            "--refresh-ttl",
            "30m",
            "--refresh-token-out",
            refresh_path.to_str().unwrap(),
        ],
    );
    set_0600(&refresh_path);
    run_ok(
        &fort_agent,
        &[
            "--once",
            "--host",
            &host,
            "--refresh-token-file",
            refresh_path.to_str().unwrap(),
            "--token-path",
            access_path.to_str().unwrap(),
        ],
    );
    set_0600(&access_path);

    let denied = Command::new(&fort)
        .args([
            "--host",
            &host,
            "--token-file",
            access_path.to_str().unwrap(),
            "keys",
            "issue",
            "r2",
            "--bucket",
            "ly-restic",
            "--permission",
            "object-read-only",
            "--ttl-seconds",
            "600",
            "--parent-repo",
            "r2b",
            "--parent-env",
            "prod",
            "--parent-key",
            "PARENT_KEY",
        ])
        .output()
        .expect("run denied r2 issue");
    assert!(
        !denied.status.success(),
        "r2 issue should be forbidden for an unscoped agent"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&denied.stdout),
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        combined.contains("forbidden"),
        "missing forbidden in denied output: {combined}"
    );

    r2_mock.join().expect("join mock r2");
    child.kill().expect("kill fortd");
    child.wait().expect("wait fortd");
}

struct MockTokensRoute {
    method: &'static str,
    path: &'static str,
    auth: &'static str,
    contains: Vec<&'static str>,
    status: u16,
    body: &'static str,
}

fn start_mock_cloudflare_tokens(routes: Vec<MockTokensRoute>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock tokens");
    let url = format!("http://{}", listener.local_addr().expect("mock addr"));
    let handle = thread::spawn(move || {
        for route in routes {
            let (mut stream, _) = listener.accept().expect("accept mock tokens request");
            let request = read_http_request(&mut stream);
            assert!(
                request.starts_with(&format!("{} {} ", route.method, route.path)),
                "unexpected tokens request: {request}"
            );
            assert!(
                request.to_ascii_lowercase().contains(route.auth),
                "missing auth in tokens request: {request}"
            );
            for needle in &route.contains {
                assert!(
                    request.contains(needle),
                    "missing {needle} in tokens request: {request}"
                );
            }
            let reason = if route.status == 200 {
                "OK"
            } else if route.status == 404 {
                "Not Found"
            } else {
                "Error"
            };
            write!(
                stream,
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                route.status,
                reason,
                route.body.len(),
                route.body
            )
            .expect("write tokens response");
        }
    });
    (url, handle)
}

fn boot_keys_test_fortd(temp: &TempDir) -> (String, String, PathBuf, PathBuf, std::process::Child) {
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");
    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");
    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);
    let addr = free_addr();
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let host = format!("http://{addr}");
    fs::write(
        &config_path,
        format!(
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");
    let child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });
    (host, fort, admin_token_path, state_dir, child)
}

fn keys_set(
    fort: &str,
    host: &str,
    admin_token_path: &Path,
    repo: &str,
    env: &str,
    key: &str,
    value: &str,
) {
    run_ok(
        fort,
        &[
            "--host",
            host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "scope",
            "ensure",
            "--repo",
            repo,
            "--env",
            env,
        ],
    );
    run_ok(
        fort,
        &[
            "--host",
            host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "set",
            "--repo",
            repo,
            "--env",
            env,
            "--key",
            key,
            "--value",
            value,
        ],
    );
}

#[test]
fn fort_keys_create_r2_through_mock_cloudflare() {
    let temp = TempDir::new().expect("tempdir");
    let groups_body = r#"{"success":true,"errors":[],"messages":[],"result":[{"id":"grp_write_id","name":"Workers R2 Storage Bucket Item Write"},{"id":"grp_read_id","name":"Workers R2 Storage Bucket Item Read"}]}"#;
    let (mock_base, mock) = start_mock_cloudflare_tokens(vec![
        MockTokensRoute {
            method: "GET",
            path: "/accounts/test-account/tokens/permission_groups",
            auth: "authorization: bearer test_manager_token",
            contains: vec![],
            status: 200,
            body: groups_body,
        },
        MockTokensRoute {
            method: "POST",
            path: "/accounts/test-account/tokens",
            auth: "authorization: bearer test_manager_token",
            contains: vec![
                "\"name\":\"app-token\"",
                "com.cloudflare.edge.r2.bucket.test-account_default_appb1",
                "com.cloudflare.edge.r2.bucket.test-account_default_appb2",
                "\"id\":\"grp_write_id\"",
            ],
            status: 200,
            body: r#"{"success":true,"errors":[],"messages":[],"result":{"id":"tok_new_id","value":"new_token_value","name":"app-token","status":"active"}}"#,
        },
        MockTokensRoute {
            method: "HEAD",
            path: "/appb1",
            auth: "authorization: aws4-hmac-sha256 credential=tok_new_id/",
            contains: vec![],
            status: 200,
            body: "",
        },
        MockTokensRoute {
            method: "HEAD",
            path: "/appb2",
            auth: "authorization: aws4-hmac-sha256 credential=tok_new_id/",
            contains: vec![],
            status: 200,
            body: "",
        },
    ]);
    let (host, fort, admin_token_path, _, mut child) = boot_keys_test_fortd(&temp);
    keys_set(
        &fort,
        &host,
        &admin_token_path,
        "mgmt",
        "prod",
        "MGR",
        "test_manager_token",
    );
    run_ok(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "scope",
            "ensure",
            "--repo",
            "app",
            "--env",
            "prod",
        ],
    );
    let output = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "keys",
            "create",
            "r2",
            "--name",
            "app-token",
            "--bucket",
            "appb1",
            "--bucket",
            "appb2",
            "--account-id",
            "test-account",
            "--repo",
            "app",
            "--env",
            "prod",
            "--id-key",
            "ID",
            "--secret-key",
            "SEC",
            "--api-base",
            &mock_base,
            "--s3-endpoint",
            &mock_base,
            "--manager-repo",
            "mgmt",
            "--manager-env",
            "prod",
            "--manager-key",
            "MGR",
        ],
    );
    assert!(
        output.contains("token_id=tok_new_id"),
        "missing token id in output: {output}"
    );
    let stored_id = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "get",
            "--repo",
            "app",
            "--env",
            "prod",
            "--key",
            "ID",
            "--format",
            "raw",
        ],
    );
    assert_eq!(stored_id.trim(), "tok_new_id");
    let stored_secret = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "get",
            "--repo",
            "app",
            "--env",
            "prod",
            "--key",
            "SEC",
            "--format",
            "raw",
        ],
    );
    {
        use sha2::Digest;
        let expected = hex::encode(sha2::Sha256::digest(b"new_token_value"));
        assert_eq!(stored_secret.trim(), expected);
    }
    mock.join().expect("join mock tokens");
    child.kill().expect("kill fortd");
    child.wait().expect("wait fortd");
}

#[test]
fn fort_keys_rotate_r2_through_mock_cloudflare() {
    let temp = TempDir::new().expect("tempdir");
    let groups_body = r#"{"success":true,"errors":[],"messages":[],"result":[{"id":"grp_write_id","name":"Workers R2 Storage Bucket Item Write"}]}"#;
    let details_body = r#"{"success":true,"errors":[],"messages":[],"result":{"id":"tok_old_id","name":"app-token","status":"active","policies":[{"effect":"allow","resources":{"com.cloudflare.edge.r2.bucket.test-account_default_appb":"*"},"permission_groups":[{"id":"grp_write_id","name":"Workers R2 Storage Bucket Item Write"}]}],"issued_on":"2026-01-01T00:00:00Z","expires_on":null}}"#;
    let (mock_base, mock) = start_mock_cloudflare_tokens(vec![
        MockTokensRoute {
            method: "GET",
            path: "/accounts/test-account/tokens/tok_old_id",
            auth: "authorization: bearer test_manager_token",
            contains: vec![],
            status: 200,
            body: details_body,
        },
        MockTokensRoute {
            method: "GET",
            path: "/accounts/test-account/tokens/permission_groups",
            auth: "authorization: bearer test_manager_token",
            contains: vec![],
            status: 200,
            body: groups_body,
        },
        MockTokensRoute {
            method: "POST",
            path: "/accounts/test-account/tokens",
            auth: "authorization: bearer test_manager_token",
            contains: vec![
                "\"name\":\"app-token\"",
                "com.cloudflare.edge.r2.bucket.test-account_default_appb",
            ],
            status: 200,
            body: r#"{"success":true,"errors":[],"messages":[],"result":{"id":"tok_new_id","value":"new_token_value","name":"app-token","status":"active"}}"#,
        },
        MockTokensRoute {
            method: "HEAD",
            path: "/appb",
            auth: "authorization: aws4-hmac-sha256 credential=tok_new_id/",
            contains: vec![],
            status: 200,
            body: "",
        },
        MockTokensRoute {
            method: "DELETE",
            path: "/accounts/test-account/tokens/tok_old_id",
            auth: "authorization: bearer test_manager_token",
            contains: vec![],
            status: 200,
            body: r#"{"success":true,"errors":[],"messages":[],"result":{"id":"tok_old_id"}}"#,
        },
    ]);
    let (host, fort, admin_token_path, _, mut child) = boot_keys_test_fortd(&temp);
    keys_set(
        &fort,
        &host,
        &admin_token_path,
        "mgmt",
        "prod",
        "MGR",
        "test_manager_token",
    );
    keys_set(
        &fort,
        &host,
        &admin_token_path,
        "app",
        "prod",
        "ID",
        "tok_old_id",
    );
    keys_set(
        &fort,
        &host,
        &admin_token_path,
        "app",
        "prod",
        "SEC",
        "old_secret_placeholder",
    );
    let output = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "keys",
            "rotate",
            "r2",
            "--repo",
            "app",
            "--env",
            "prod",
            "--id-key",
            "ID",
            "--secret-key",
            "SEC",
            "--account-id",
            "test-account",
            "--api-base",
            &mock_base,
            "--s3-endpoint",
            &mock_base,
            "--manager-repo",
            "mgmt",
            "--manager-env",
            "prod",
            "--manager-key",
            "MGR",
            "--revoke-old",
        ],
    );
    assert!(
        output.contains("token_id=tok_new_id"),
        "missing new token id in output: {output}"
    );
    assert!(
        output.contains("old_token_revoked=true"),
        "missing revoke proof in output: {output}"
    );
    let stored_id = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "get",
            "--repo",
            "app",
            "--env",
            "prod",
            "--key",
            "ID",
            "--format",
            "raw",
        ],
    );
    assert_eq!(stored_id.trim(), "tok_new_id");
    mock.join().expect("join mock tokens");
    child.kill().expect("kill fortd");
    child.wait().expect("wait fortd");
}

#[test]
fn fort_keys_revoke_list_audit_r2_through_mock_cloudflare() {
    let temp = TempDir::new().expect("tempdir");
    let list_body = r#"{"success":true,"errors":[],"messages":[],"result":[{"id":"tok_a","name":"alpha-token","status":"active","policies":[{"effect":"allow","resources":{"com.cloudflare.edge.r2.bucket.test-account_default_appb":"*"},"permission_groups":[{"id":"grp_write_id","name":"Workers R2 Storage Bucket Item Write"}]}],"issued_on":"2026-01-01T00:00:00Z","expires_on":null},{"id":"tok_b","name":"beta-token","status":"active","policies":[],"issued_on":null,"expires_on":null}],"result_info":{"page":1,"per_page":100,"count":2,"total_count":2}}"#;
    let (mock_base, mock) = start_mock_cloudflare_tokens(vec![
        MockTokensRoute {
            method: "DELETE",
            path: "/accounts/test-account/tokens/tok_gone",
            auth: "authorization: bearer test_manager_token",
            contains: vec![],
            status: 200,
            body: r#"{"success":true,"errors":[],"messages":[],"result":{"id":"tok_gone"}}"#,
        },
        MockTokensRoute {
            method: "DELETE",
            path: "/accounts/test-account/tokens/tok_missing",
            auth: "authorization: bearer test_manager_token",
            contains: vec![],
            status: 404,
            body: r#"{"success":false,"errors":[{"code":7003,"message":"Could not find token"}],"messages":[],"result":null}"#,
        },
        MockTokensRoute {
            method: "GET",
            path: "/accounts/test-account/tokens?per_page=100&page=1",
            auth: "authorization: bearer test_manager_token",
            contains: vec![],
            status: 200,
            body: list_body,
        },
        MockTokensRoute {
            method: "GET",
            path: "/accounts/test-account/tokens?per_page=100&page=1",
            auth: "authorization: bearer test_manager_token",
            contains: vec![],
            status: 200,
            body: list_body,
        },
    ]);
    let (host, fort, admin_token_path, _, mut child) = boot_keys_test_fortd(&temp);
    keys_set(
        &fort,
        &host,
        &admin_token_path,
        "mgmt",
        "prod",
        "MGR",
        "test_manager_token",
    );
    keys_set(
        &fort,
        &host,
        &admin_token_path,
        "app",
        "prod",
        "ID",
        "tok_a",
    );
    keys_set(
        &fort,
        &host,
        &admin_token_path,
        "app",
        "prod",
        "ORPHAN",
        "tok_nowhere",
    );
    let revoked = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "keys",
            "revoke",
            "r2",
            "--token-id",
            "tok_gone",
            "--account-id",
            "test-account",
            "--api-base",
            &mock_base,
            "--manager-repo",
            "mgmt",
            "--manager-env",
            "prod",
            "--manager-key",
            "MGR",
        ],
    );
    assert!(
        revoked.contains("deleted_token=tok_gone"),
        "missing delete proof: {revoked}"
    );
    let absent = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "keys",
            "revoke",
            "r2",
            "--token-id",
            "tok_missing",
            "--account-id",
            "test-account",
            "--api-base",
            &mock_base,
            "--manager-repo",
            "mgmt",
            "--manager-env",
            "prod",
            "--manager-key",
            "MGR",
        ],
    );
    assert!(
        absent.contains("already_absent=true"),
        "missing absent note: {absent}"
    );
    let listed = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "keys",
            "list",
            "r2",
            "--account-id",
            "test-account",
            "--api-base",
            &mock_base,
            "--manager-repo",
            "mgmt",
            "--manager-env",
            "prod",
            "--manager-key",
            "MGR",
        ],
    );
    assert!(
        listed.contains("alpha-token") && listed.contains("beta-token"),
        "missing tokens in list: {listed}"
    );
    let audited = run_capture(
        &fort,
        &[
            "--host",
            &host,
            "--token-file",
            admin_token_path.to_str().unwrap(),
            "keys",
            "audit",
            "r2",
            "--account-id",
            "test-account",
            "--api-base",
            &mock_base,
            "--manager-repo",
            "mgmt",
            "--manager-env",
            "prod",
            "--manager-key",
            "MGR",
            "--check",
            "app/prod/ID",
            "--check",
            "app/prod/ORPHAN",
        ],
    );
    assert!(
        audited.contains("tok_a") && audited.contains("app/prod/ID"),
        "missing match in audit: {audited}"
    );
    assert!(
        audited.contains("UNMATCHED"),
        "missing unmatched marker in audit: {audited}"
    );
    assert!(
        audited.contains("ORPHAN_CHECK\tapp/prod/ORPHAN"),
        "missing orphan in audit: {audited}"
    );
    mock.join().expect("join mock tokens");
    child.kill().expect("kill fortd");
    child.wait().expect("wait fortd");
}

#[test]
fn fort_keys_dry_runs_touch_neither_cloudflare_nor_fort() {
    let temp = TempDir::new().expect("tempdir");
    let (host, fort, admin_token_path, _, mut child) = boot_keys_test_fortd(&temp);
    let dead = "http://127.0.0.1:1";
    let token = admin_token_path.to_str().unwrap();
    for args in [
        vec![
            "keys",
            "create",
            "r2",
            "--name",
            "x",
            "--bucket",
            "b",
            "--account-id",
            "a",
            "--repo",
            "r",
            "--env",
            "e",
            "--id-key",
            "i",
            "--secret-key",
            "s",
            "--api-base",
            dead,
            "--manager-key",
            "BOGUS",
            "--dry-run",
        ],
        vec![
            "keys",
            "rotate",
            "r2",
            "--repo",
            "r",
            "--env",
            "e",
            "--id-key",
            "i",
            "--secret-key",
            "s",
            "--account-id",
            "a",
            "--api-base",
            dead,
            "--manager-key",
            "BOGUS",
            "--dry-run",
        ],
        vec![
            "keys",
            "revoke",
            "r2",
            "--token-id",
            "t",
            "--account-id",
            "a",
            "--api-base",
            dead,
            "--manager-key",
            "BOGUS",
            "--dry-run",
        ],
    ] {
        let mut full = vec!["--host", host.as_str(), "--token-file", token];
        full.extend(args);
        run_ok(&fort, &full);
    }
    child.kill().expect("kill fortd");
    child.wait().expect("wait fortd");
}

#[test]
fn fort_gemini_keys_gate_config_and_reject_ttl() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let safe_root = temp.path().join("safe");
    let safe_repo = safe_root.join("safe");
    fs::create_dir_all(&state_dir).expect("mkdir state");
    fs::create_dir_all(&safe_repo).expect("mkdir safe");

    let state_path = state_dir.join("state.json");
    let keyring_path = state_dir.join("vault-keyring.json");
    let signing_key_path = state_dir.join("jwt-signing.key");
    let config_path = state_dir.join("fortd.toml");
    let admin_token_path = state_dir.join("admin.token");

    let admin_token = seed_state(&state_path, &keyring_path, &signing_key_path);
    fs::write(&admin_token_path, admin_token.as_bytes()).expect("write admin token");
    set_0600(&admin_token_path);

    // Gemini issuer configured, but no minter credential is stored: requests
    // must fail before any Google call, and ttl_seconds must be rejected.
    fs::write(
        &config_path,
        format!(
            "addr = \"{}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"30d\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\ngemini_api_base = \"http://127.0.0.1:1\"\ngemini_project_id = \"e2e-probe\"\ngemini_minter_repo = \"fort\"\ngemini_minter_env = \"prod\"\ngemini_minter_key = \"GEMINI_MINTER_SA\"\ngemini_rotation_days = \"7\"\n",
            free_addr_placeholder(),
            state_path.display(),
            signing_key_path.display(),
            safe_root.display(),
            keyring_path.display(),
        ),
    )
    .expect("write fortd config");

    let addr = read_config_addr(&config_path);
    let fortd = std::env::var("CARGO_BIN_EXE_fortd").expect("fortd path");
    let fort = std::env::var("CARGO_BIN_EXE_fort").expect("fort path");
    let host = format!("http://{addr}");
    let mut child = Command::new(&fortd)
        .args(["--config-file", config_path.to_str().expect("config path")])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fortd");
    wait_for(Duration::from_secs(10), || {
        Command::new(&fort)
            .args([
                "--host",
                &host,
                "--token-file",
                admin_token_path.to_str().expect("admin token path"),
                "doctor",
            ])
            .status()
            .ok()
            .is_some_and(|status| status.success())
    });

    // ttl_seconds is rejected with 400 before any policy or provider work.
    let (status, body) = raw_post(
        &addr,
        "/v1/gemini/keys/issue",
        admin_token.trim(),
        r#"{"key_name":"k","store_repo":"safe","store_env":"dev","ttl_seconds":3600}"#,
    );
    assert_eq!(status, 400, "ttl body: {body}");
    assert!(
        body.contains("ttl_seconds is not supported"),
        "ttl body: {body}"
    );
    assert!(
        body.contains("NOT platform-enforced"),
        "advisory label missing: {body}"
    );

    // Without a stored minter credential every surface fails closed (503)
    // without contacting Google (api_base is unroutable by design).
    for args in [
        vec![
            "keys",
            "issue",
            "gemini",
            "--key-name",
            "k",
            "--store-repo",
            "safe",
            "--store-env",
            "dev",
        ],
        vec![
            "keys",
            "rotate",
            "gemini",
            "--key-name",
            "k",
            "--store-repo",
            "safe",
            "--store-env",
            "dev",
        ],
        vec!["keys", "revoke", "gemini", "--key-name", "k"],
        vec!["keys", "list", "gemini"],
        vec!["keys", "validate", "gemini", "--key-name", "k"],
    ] {
        let mut full = vec![
            "--host",
            host.as_str(),
            "--token-file",
            admin_token_path.to_str().unwrap(),
        ];
        full.extend(args);
        let output = Command::new(&fort).args(&full).output().expect("run fort");
        assert!(
            !output.status.success(),
            "gemini without minter credential must fail: {full:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("gemini minter credential is not stored"),
            "expected closed-gate 503, stderr: {stderr}"
        );
    }

    // --dry-run passes policy/shape without a stored minter credential and
    // without contacting Google (regression: dry_run used to read the vault
    // credential first and 503 on these same paths).
    for args in [
        vec![
            "keys",
            "issue",
            "gemini",
            "--key-name",
            "k",
            "--store-repo",
            "safe",
            "--store-env",
            "dev",
            "--dry-run",
        ],
        vec![
            "keys",
            "rotate",
            "gemini",
            "--key-name",
            "k",
            "--store-repo",
            "safe",
            "--store-env",
            "dev",
            "--dry-run",
        ],
        vec!["keys", "revoke", "gemini", "--key-name", "k", "--dry-run"],
        vec!["keys", "list", "gemini", "--dry-run"],
    ] {
        let mut full = vec![
            "--host",
            host.as_str(),
            "--token-file",
            admin_token_path.to_str().unwrap(),
        ];
        full.extend(args);
        let output = Command::new(&fort).args(&full).output().expect("run fort");
        assert!(
            output.status.success(),
            "gemini --dry-run without minter credential must pass: {full:?} stderr: {}",
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let _ = child.kill();
    let _ = child.wait();
}

fn free_addr_placeholder() -> String {
    free_addr()
}

fn read_config_addr(config_path: &PathBuf) -> String {
    let raw = fs::read_to_string(config_path).expect("read fortd config");
    for line in raw.lines() {
        if let Some(addr) = line.strip_prefix("addr = \"")
            && let Some(addr) = addr.strip_suffix('"')
        {
            return addr.to_string();
        }
    }
    panic!("addr missing in fortd config");
}

fn raw_post(host_addr: &str, path: &str, token: &str, body: &str) -> (u16, String) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(host_addr).expect("connect fortd");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let text = String::from_utf8_lossy(&raw).to_string();
    let status: u16 = text
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let body = text.rsplit("\r\n\r\n").next().unwrap_or("").to_string();
    (status, body)
}
