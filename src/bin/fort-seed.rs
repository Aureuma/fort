use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let state_path = env::var("STATE_PATH").unwrap_or_default();
    let keyring_path = env::var("KEYRING_PATH").unwrap_or_default();
    let signing_key_path = env::var("SIGNING_KEY_PATH").unwrap_or_default();
    let profile_ids = env::var("PROFILE_IDS").unwrap_or_default();
    let signing_key = "spawn-matrix-signing-key-012345678901";

    let store = Arc::new(fort::store::Store::new(&state_path)?);
    let now = chrono::Utc::now();
    let admin = store.create_agent(
        "admin",
        Some(fort::model::AgentType::User),
        Some(fort::model::AgentStatus::Active),
        now,
    )?;
    let wildcard = fort::model::Binding {
        repo: "*".to_string(),
        env: "*".to_string(),
        ops: vec![fort::model::Operation::Any],
    };
    let _ = store.set_policy(&admin.id, std::slice::from_ref(&wildcard), now)?;
    for profile_id in profile_ids
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let agent_id = format!("si-worker-{profile_id}");
        let workload = store.create_agent(
            &agent_id,
            Some(fort::model::AgentType::Workload),
            Some(fort::model::AgentStatus::Active),
            now,
        )?;
        let _ = store.set_policy(&workload.id, std::slice::from_ref(&wildcard), now)?;
    }

    let manager = fort::auth::Manager {
        signing_key: signing_key.as_bytes().to_vec(),
        issuer: None,
        store: Arc::clone(&store),
    };
    let (token, _) = manager.issue(&admin, Duration::from_secs(24 * 60 * 60), "fort-api")?;

    let canonical = generate_canonical_keypair()?;
    let mut entries = BTreeMap::new();
    write_entry(
        &mut entries,
        "safe",
        "dev",
        &canonical.public,
        &canonical.private,
    )?;
    write_entry(
        &mut entries,
        "safe",
        "prod",
        &canonical.public,
        &canonical.private,
    )?;
    write_entry(
        &mut entries,
        "core",
        "dev",
        &canonical.public,
        &canonical.private,
    )?;
    let raw = serde_json::to_vec_pretty(&json!({ "entries": entries }))?;
    write_secret_file(&keyring_path, &raw)?;
    write_secret_file(&signing_key_path, signing_key.as_bytes())?;
    print!("{token}");
    Ok(())
}

struct CanonicalKeypair {
    public: String,
    private: String,
}

fn generate_canonical_keypair() -> anyhow::Result<CanonicalKeypair> {
    let (secret, public) = ecies::utils::generate_keypair();
    Ok(CanonicalKeypair {
        public: hex::encode(public.serialize_compressed()),
        private: hex::encode(secret.serialize()),
    })
}

fn write_entry(
    entries: &mut BTreeMap<String, serde_json::Value>,
    repo: &str,
    env: &str,
    public: &str,
    private: &str,
) -> anyhow::Result<()> {
    if public.trim().is_empty() || private.trim().is_empty() {
        anyhow::bail!("public/private key are required");
    }
    entries.insert(
        format!("{repo}/{env}"),
        json!({
            "repo": repo,
            "env": env,
            "public_key": public,
            "private_key": private
        }),
    );
    Ok(())
}

fn write_secret_file(path: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let path = PathBuf::from(path.trim());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
