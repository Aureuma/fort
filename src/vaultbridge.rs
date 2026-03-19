use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ecies::{decrypt, encrypt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::ensure_strict_secret_file;

pub const ENCRYPTED_PREFIX: &str = "encrypted:si-vault:";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("not found")]
    NotFound,
    #[error("invalid")]
    Invalid,
    #[error("key sprawl detected")]
    KeySprawl,
    #[error("io")]
    Io,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub safe_root: String,
    pub keyring_path: String,
    pub extra_priv_keys: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct KeyringDoc {
    #[serde(default)]
    entries: BTreeMap<String, KeyringEntry>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct KeyringEntry {
    #[serde(default)]
    repo: String,
    #[serde(default)]
    env: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    backup_private_keys: Vec<String>,
}

#[derive(Debug)]
pub struct Backend {
    safe_root: PathBuf,
    keyring_path: PathBuf,
    extra_priv_keys: Vec<String>,
    write_lock: Mutex<()>,
}

impl Backend {
    pub fn new(config: Config) -> Result<Self> {
        let safe_root = PathBuf::from(config.safe_root.trim());
        if safe_root.as_os_str().is_empty() {
            bail!("safe root is required");
        }
        let keyring_path = PathBuf::from(config.keyring_path.trim());
        if keyring_path.as_os_str().is_empty() {
            bail!("keyring path is required");
        }
        let backend = Self {
            safe_root,
            keyring_path,
            extra_priv_keys: config
                .extra_priv_keys
                .into_iter()
                .map(|part| normalize_hex(&part))
                .filter(|part| !part.is_empty())
                .collect(),
            write_lock: Mutex::new(()),
        };
        backend.validate_startup()?;
        Ok(backend)
    }

    pub fn get(&self, repo: &str, env: &str, key: &str) -> Result<String, VaultError> {
        let (repo, env) = normalize_target(repo, env)?;
        let key = normalize_secret_key(key)?;
        let values = load_dotenv(&self.env_file_path(&repo, &env), true)?;
        let raw = values.get(&key).ok_or(VaultError::NotFound)?;
        let entry = self.load_keyring_entry(&repo, &env)?;
        decrypt_value(raw, &self.private_key_candidates(&entry))
    }

    pub fn batch_get(
        &self,
        repo: &str,
        env: &str,
        keys: &[String],
    ) -> Result<BTreeMap<String, String>, VaultError> {
        let mut out = BTreeMap::new();
        for key in keys {
            out.insert(key.trim().to_string(), self.get(repo, env, key)?);
        }
        Ok(out)
    }

    pub fn list(&self, repo: &str, env: &str, prefix: &str) -> Result<Vec<String>, VaultError> {
        let (repo, env) = normalize_target(repo, env)?;
        let prefix = prefix.trim();
        let values = load_dotenv(&self.env_file_path(&repo, &env), true)?;
        let _ = self.load_keyring_entry(&repo, &env)?;
        let mut keys = values
            .keys()
            .filter(|key| prefix.is_empty() || key.starts_with(prefix))
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        Ok(keys)
    }

    pub fn set(&self, repo: &str, env: &str, key: &str, value: &str) -> Result<(), VaultError> {
        let (repo, env) = normalize_target(repo, env)?;
        let key = normalize_secret_key(key)?;
        let entry = self.load_keyring_entry(&repo, &env)?;
        if entry.public_key.trim().is_empty() {
            return Err(VaultError::Invalid);
        }
        let cipher = encrypt_value(value, &entry.public_key)?;
        let path = self.env_file_path(&repo, &env);
        let _guard = self.write_lock.lock().expect("vault write lock poisoned");
        let mut values = load_dotenv(&path, false)?;
        values.insert(key, cipher);
        write_dotenv(&path, &values).map_err(|_| VaultError::Io)
    }

    fn env_file_path(&self, repo: &str, env: &str) -> PathBuf {
        self.safe_root.join(repo).join(format!(".env.{env}"))
    }

    fn validate_startup(&self) -> Result<()> {
        let metadata = fs::metadata(&self.safe_root)
            .with_context(|| format!("stat {}", self.safe_root.display()))?;
        if !metadata.is_dir() {
            bail!("safe root must be a directory");
        }
        let doc = self.read_keyring_doc().map_err(map_keyring_error)?;
        self.validate_single_key_material(&doc)
            .map_err(map_keyring_error)?;
        Ok(())
    }

    fn read_keyring_doc(&self) -> Result<KeyringDoc, VaultError> {
        ensure_strict_secret_file(&self.keyring_path).map_err(|_| VaultError::Io)?;
        let raw = fs::read_to_string(&self.keyring_path).map_err(|_| VaultError::Io)?;
        serde_json::from_str(&raw).map_err(|_| VaultError::Io)
    }

    fn load_keyring_entry(&self, repo: &str, env: &str) -> Result<KeyringEntry, VaultError> {
        let doc = self.read_keyring_doc()?;
        self.validate_single_key_material(&doc)?;
        let map_key = format!("{}/{}", repo.to_lowercase(), env.to_lowercase());
        if let Some(entry) = doc.entries.get(&map_key) {
            return Ok(entry.clone());
        }
        doc.entries
            .values()
            .find(|entry| {
                entry.repo.eq_ignore_ascii_case(repo) && entry.env.eq_ignore_ascii_case(env)
            })
            .cloned()
            .ok_or(VaultError::NotFound)
    }

    fn validate_single_key_material(&self, doc: &KeyringDoc) -> Result<(), VaultError> {
        let mut expected_pub = String::new();
        let mut expected_priv = String::new();
        for (scope, entry) in &doc.entries {
            let public = normalize_hex(&entry.public_key);
            let private = normalize_hex(&entry.private_key);
            if public.is_empty() && private.is_empty() {
                continue;
            }
            if public.is_empty() || private.is_empty() {
                let _ = scope;
                return Err(VaultError::Invalid);
            }
            if entry
                .backup_private_keys
                .iter()
                .any(|candidate| !normalize_hex(candidate).is_empty())
            {
                return Err(VaultError::KeySprawl);
            }
            if expected_pub.is_empty() {
                expected_pub = public;
                expected_priv = private;
                continue;
            }
            if public != expected_pub || private != expected_priv {
                return Err(VaultError::KeySprawl);
            }
        }
        if expected_priv.is_empty() {
            return Ok(());
        }
        for extra in &self.extra_priv_keys {
            if !extra.is_empty() && extra != &expected_priv {
                return Err(VaultError::KeySprawl);
            }
        }
        Ok(())
    }

    fn private_key_candidates(&self, entry: &KeyringEntry) -> Vec<String> {
        let mut out = Vec::new();
        for candidate in std::iter::once(&entry.private_key)
            .chain(entry.backup_private_keys.iter())
            .chain(self.extra_priv_keys.iter())
        {
            let normalized = normalize_hex(candidate);
            if !normalized.is_empty() {
                out.push(normalized);
            }
        }
        out
    }
}

fn normalize_target(repo: &str, env: &str) -> Result<(String, String), VaultError> {
    let repo = repo.trim();
    let env = env.trim();
    if !is_safe_path_part(repo) || !is_safe_path_part(env) {
        return Err(VaultError::Invalid);
    }
    Ok((repo.to_string(), env.to_string()))
}

fn normalize_secret_key(key: &str) -> Result<String, VaultError> {
    let key = key.trim();
    if key.is_empty() || key.contains(['\n', '\r']) {
        return Err(VaultError::Invalid);
    }
    Ok(key.to_string())
}

fn is_safe_path_part(value: &str) -> bool {
    !value.trim().is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn load_dotenv(path: &Path, fail_if_missing: bool) -> Result<BTreeMap<String, String>, VaultError> {
    if !path.exists() {
        return if fail_if_missing {
            Err(VaultError::NotFound)
        } else {
            Ok(BTreeMap::new())
        };
    }
    ensure_strict_secret_file(path).map_err(|_| VaultError::Io)?;
    let raw = fs::read_to_string(path).map_err(|_| VaultError::Io)?;
    let mut out = BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        out.insert(key.to_string(), value.trim().to_string());
    }
    Ok(out)
}

fn write_dotenv(path: &Path, values: &BTreeMap<String, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let mut raw = String::new();
    for (key, value) in values {
        raw.push_str(key);
        raw.push('=');
        raw.push_str(value);
        raw.push('\n');
    }
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp, raw.as_bytes()).with_context(|| format!("write {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    if let Some((uid, gid)) = target_owner(path) {
        #[cfg(unix)]
        {
            let _ = nixless_chown(&tmp, uid, gid);
        }
    }
    fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn target_owner(path: &Path) -> Option<(u32, u32)> {
    if let Ok(meta) = fs::metadata(path) {
        return Some((meta.uid(), meta.gid()));
    }
    path.parent()
        .and_then(|parent| fs::metadata(parent).ok())
        .map(|meta| (meta.uid(), meta.gid()))
}

#[cfg(unix)]
fn nixless_chown(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("invalid path"))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn normalize_hex(raw: &str) -> String {
    raw.trim().to_lowercase()
}

fn map_keyring_error(error: VaultError) -> anyhow::Error {
    match error {
        VaultError::NotFound => anyhow::anyhow!("keyring entry not found"),
        VaultError::Invalid => anyhow::anyhow!("vault keyring is invalid"),
        VaultError::KeySprawl => {
            anyhow::anyhow!("vault keyring violates single-key-material invariant")
        }
        VaultError::Io => anyhow::anyhow!(
            "vault keyring file is missing, unreadable, or permissions are too open"
        ),
    }
}

fn encrypt_value(plain: &str, public_key_hex: &str) -> Result<String, VaultError> {
    let public_key_hex = public_key_hex.trim();
    if public_key_hex.is_empty() {
        return Err(VaultError::Invalid);
    }
    if plain.is_empty() {
        return Ok(ENCRYPTED_PREFIX.to_string());
    }
    let public = hex::decode(public_key_hex).map_err(|_| VaultError::Invalid)?;
    let blob = encrypt(&public, plain.as_bytes()).map_err(|_| VaultError::Invalid)?;
    Ok(format!("{ENCRYPTED_PREFIX}{}", STANDARD.encode(blob)))
}

fn decrypt_value(raw: &str, candidates: &[String]) -> Result<String, VaultError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(String::new());
    }
    if !raw.starts_with(ENCRYPTED_PREFIX) {
        return Ok(raw.to_string());
    }
    let encoded = raw.trim_start_matches(ENCRYPTED_PREFIX).trim();
    if encoded.is_empty() {
        return Ok(String::new());
    }
    let blob = STANDARD.decode(encoded).map_err(|_| VaultError::Invalid)?;
    for candidate in candidates {
        let private = hex::decode(candidate).map_err(|_| VaultError::Invalid)?;
        if let Ok(plain) = decrypt(&private, &blob) {
            return String::from_utf8(plain).map_err(|_| VaultError::Invalid);
        }
    }
    Err(VaultError::Invalid)
}
