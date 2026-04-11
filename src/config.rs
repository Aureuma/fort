use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);
pub const DEFAULT_REFRESH_SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const DEFAULT_RUN_TTL: Duration = Duration::from_secs(60);
pub const DEFAULT_SECRET_TTL: Duration = Duration::from_secs(120);

#[derive(Clone, Debug)]
pub struct Config {
    pub addr: String,
    pub state_path: String,
    pub signing_key_file: String,
    pub signing_key: String,
    pub safe_root: String,
    pub keyring_path: String,
    pub extra_private_keys: Vec<String>,
    pub token_ttl: Duration,
    pub refresh_session_ttl: Duration,
    pub run_ttl: Duration,
    pub secret_ttl: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let signing_key_raw = env_trim("FORT_JWT_SIGNING_KEY");
        let signing_key_file = env_trim("FORT_JWT_SIGNING_KEY_FILE");
        if !signing_key_raw.is_empty() {
            bail!("FORT_JWT_SIGNING_KEY is disallowed; use FORT_JWT_SIGNING_KEY_FILE");
        }
        if signing_key_file.is_empty() {
            bail!("FORT_JWT_SIGNING_KEY_FILE is required");
        }
        let signing_key = read_secret_file(&signing_key_file)?;
        if signing_key.len() < 32 {
            bail!("JWT signing key must be at least 32 characters");
        }
        match signing_key.to_lowercase().as_str() {
            "change-me" | "dev-only-change-me" => {
                bail!("JWT signing key uses an insecure placeholder value")
            }
            _ => {}
        }
        Ok(Self {
            addr: env_or("FORT_ADDR", ":8088"),
            state_path: env_or("FORT_STATE_PATH", "./fort-state.json"),
            signing_key_file,
            signing_key,
            safe_root: env_or("FORT_SAFE_ROOT", "/safe"),
            keyring_path: env_or("FORT_VAULT_KEYRING_FILE", &default_vault_keyring_path()),
            extra_private_keys: split_csv(&env_or("FORT_VAULT_PRIVATE_KEYS", "")),
            token_ttl: parse_duration_env("FORT_TOKEN_TTL", DEFAULT_TOKEN_TTL),
            refresh_session_ttl: parse_duration_env(
                "FORT_REFRESH_SESSION_TTL",
                DEFAULT_REFRESH_SESSION_TTL,
            ),
            run_ttl: parse_duration_env("FORT_RUN_TTL", DEFAULT_RUN_TTL),
            secret_ttl: parse_duration_env("FORT_SECRET_TTL", DEFAULT_SECRET_TTL),
        })
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let source =
            fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
        let parsed: FileConfig =
            toml::from_str(&source).with_context(|| format!("parse config {}", path.display()))?;
        let signing_key_file = parsed.jwt_signing_key_file.trim().to_string();
        if signing_key_file.is_empty() {
            bail!("jwt_signing_key_file is required in {}", path.display());
        }
        let signing_key = read_secret_file(&signing_key_file)?;
        if signing_key.len() < 32 {
            bail!("JWT signing key must be at least 32 characters");
        }
        match signing_key.to_lowercase().as_str() {
            "change-me" | "dev-only-change-me" => {
                bail!("JWT signing key uses an insecure placeholder value")
            }
            _ => {}
        }
        Ok(Self {
            addr: normalize_value(parsed.addr, ":8088"),
            state_path: normalize_value(parsed.state_path, "./fort-state.json"),
            signing_key_file,
            signing_key,
            safe_root: normalize_value(parsed.safe_root, "/safe"),
            keyring_path: normalize_value(parsed.vault_keyring_file, &default_vault_keyring_path()),
            extra_private_keys: parsed
                .vault_private_keys
                .into_iter()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .collect(),
            token_ttl: parse_duration_value(parsed.token_ttl.as_deref(), DEFAULT_TOKEN_TTL),
            refresh_session_ttl: parse_duration_value(
                parsed.refresh_session_ttl.as_deref(),
                DEFAULT_REFRESH_SESSION_TTL,
            ),
            run_ttl: parse_duration_value(parsed.run_ttl.as_deref(), DEFAULT_RUN_TTL),
            secret_ttl: parse_duration_value(parsed.secret_ttl.as_deref(), DEFAULT_SECRET_TTL),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    addr: String,
    #[serde(default)]
    state_path: String,
    #[serde(default)]
    jwt_signing_key_file: String,
    #[serde(default)]
    safe_root: String,
    #[serde(default)]
    vault_keyring_file: String,
    #[serde(default)]
    vault_private_keys: Vec<String>,
    #[serde(default)]
    token_ttl: Option<String>,
    #[serde(default)]
    refresh_session_ttl: Option<String>,
    #[serde(default)]
    run_ttl: Option<String>,
    #[serde(default)]
    secret_ttl: Option<String>,
}

pub fn env_trim(name: &str) -> String {
    env::var(name).unwrap_or_default().trim().to_string()
}

pub fn env_or(name: &str, fallback: &str) -> String {
    let value = env_trim(name);
    if value.is_empty() {
        fallback.trim().to_string()
    } else {
        value
    }
}

pub fn parse_duration_env(name: &str, fallback: Duration) -> Duration {
    let value = env_trim(name);
    if value.is_empty() {
        return fallback;
    }
    humantime_compat::parse_duration(&value).unwrap_or(fallback)
}

pub fn parse_duration_value(value: Option<&str>, fallback: Duration) -> Duration {
    let value = value.unwrap_or_default().trim();
    if value.is_empty() {
        return fallback;
    }
    humantime_compat::parse_duration(value).unwrap_or(fallback)
}

fn normalize_value(value: String, fallback: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        fallback.trim().to_string()
    } else {
        value.to_string()
    }
}

pub fn read_secret_file(path: &str) -> Result<String> {
    let path = PathBuf::from(path.trim());
    if path.as_os_str().is_empty() {
        bail!("secret path is empty");
    }
    ensure_strict_secret_file(&path)?;
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let value = raw.trim().to_string();
    if value.is_empty() {
        bail!("secret file is empty");
    }
    Ok(value)
}

pub fn ensure_strict_secret_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("secret path is not a regular file");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("secret file permissions must be 0600 or stricter");
    }
    Ok(())
}

pub fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn default_vault_keyring_path() -> String {
    let home = env::var("HOME").unwrap_or_default();
    if home.trim().is_empty() {
        String::new()
    } else {
        format!("{}/.si/vault/si-vault-keyring.json", home.trim())
    }
}

mod humantime_compat {
    use std::time::Duration;

    pub fn parse_duration(raw: &str) -> Option<Duration> {
        if let Ok(seconds) = raw.trim().parse::<u64>() {
            return Some(Duration::from_secs(seconds));
        }
        let mut number = String::new();
        let mut total = Duration::from_secs(0);
        for ch in raw.trim().chars() {
            if ch.is_ascii_digit() {
                number.push(ch);
                continue;
            }
            let value = number.parse::<u64>().ok()?;
            number.clear();
            let part = match ch {
                's' => Duration::from_secs(value),
                'm' => Duration::from_secs(value * 60),
                'h' => Duration::from_secs(value * 60 * 60),
                'd' => Duration::from_secs(value * 60 * 60 * 24),
                _ => return None,
            };
            total += part;
        }
        if !number.is_empty() {
            return None;
        }
        Some(total)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn file_config_defaults_normal_refresh_sessions_to_thirty_days() {
        let dir = tempfile::tempdir().expect("tempdir");
        let signing_key = dir.path().join("fort-jwt-signing.key");
        fs::write(&signing_key, "test-signing-key-that-is-long-enough").expect("write key");
        fs::set_permissions(&signing_key, fs::Permissions::from_mode(0o600))
            .expect("set key permissions");

        let config_path = dir.path().join("fort.toml");
        fs::write(
            &config_path,
            format!("jwt_signing_key_file = \"{}\"\n", signing_key.display()),
        )
        .expect("write config");

        let config = Config::from_file(&config_path).expect("load config");
        assert_eq!(config.refresh_session_ttl, DEFAULT_REFRESH_SESSION_TTL);
        assert_eq!(
            config.refresh_session_ttl,
            Duration::from_secs(30 * 24 * 60 * 60)
        );
    }

    #[test]
    fn file_config_accepts_explicit_refresh_session_ttl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let signing_key = dir.path().join("fort-jwt-signing.key");
        fs::write(&signing_key, "test-signing-key-that-is-long-enough").expect("write key");
        fs::set_permissions(&signing_key, fs::Permissions::from_mode(0o600))
            .expect("set key permissions");

        let config_path = dir.path().join("fort.toml");
        fs::write(
            &config_path,
            format!(
                "jwt_signing_key_file = \"{}\"\nrefresh_session_ttl = \"12h\"\n",
                signing_key.display()
            ),
        )
        .expect("write config");

        let config = Config::from_file(&config_path).expect("load config");
        assert_eq!(
            config.refresh_session_ttl,
            Duration::from_secs(12 * 60 * 60)
        );
    }
}
