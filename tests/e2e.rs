use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
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
            "--value",
            "from-fort",
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
    let (github_url, github_mock) = start_mock_github_actions_secret_api();
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
fn fort_cli_rejects_codex_profile_refresh_token_rotation_to_detached_path() {
    let temp = TempDir::new().expect("tempdir");
    let refresh_path = temp
        .path()
        .join(".si/codex/profiles/profile-zeta/fort/refresh.token");
    fs::create_dir_all(refresh_path.parent().expect("refresh parent")).expect("mkdir fort dir");
    fs::write(&refresh_path, "profile-refresh-token\n").expect("write profile refresh token");
    set_0600(&refresh_path);
    let out_path = temp.path().join("detached-refresh.token");
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
    assert!(stderr.contains("refusing to rotate Codex profile Fort refresh token"));
    assert!(stderr.contains("refreshed in place"));
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

fn start_mock_github_actions_secret_api() -> (String, thread::JoinHandle<()>) {
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
                write!(
                    stream,
                    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .expect("write github secret response");
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
