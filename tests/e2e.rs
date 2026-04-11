use std::fs;
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
    let keyring_path = state_dir.join("si-vault-keyring.json");
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
            "addr = \"{addr}\"\nstate_path = \"{}\"\njwt_signing_key_file = \"{}\"\nsafe_root = \"{}\"\nvault_keyring_file = \"{}\"\ntoken_ttl = \"15m\"\nrefresh_session_ttl = \"24h\"\nrun_ttl = \"60s\"\nsecret_ttl = \"120s\"\n",
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
            .args(["--host", &host, "doctor"])
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
    assert!(raw.contains("E2E_KEY=encrypted:si-vault:"));

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
fn fort_backend_fails_fast_when_safe_root_or_keyring_mounts_are_wrong() {
    let temp = TempDir::new().expect("tempdir");
    let safe_root = temp.path().join("safe");
    let keyring_path = temp.path().join("si-vault-keyring.json");

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

fn set_0600(path: &PathBuf) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).expect("stat").permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).expect("chmod");
    }
}
