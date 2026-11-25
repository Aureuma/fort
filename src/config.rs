use std::collections::HashMap;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);
pub const DEFAULT_REFRESH_SESSION_TTL: Duration = Duration::from_secs(90 * 24 * 60 * 60);
pub const DEFAULT_RUN_TTL: Duration = Duration::from_secs(60);
pub const DEFAULT_SECRET_TTL: Duration = Duration::from_secs(120);
pub const DEFAULT_GEMINI_ROTATION_DAYS: u64 = 7;

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
    pub github_pepper_file: Option<String>,
    pub github_pepper: Vec<u8>,
    pub github_api_base: String,
    pub r2: R2Config,
    pub gemini: GeminiConfig,
}

/// Issuer configuration for Gemini (Google AI Studio) API key minting.
///
/// `rotation_days` is advisory only: Google Cloud API keys do not expire on a
/// schedule, so Fort reports the rotation recommendation to callers but the
/// platform does NOT enforce it.
///
/// Multi-project: the top-level `project_id`/`minter_*` fields are the
/// default (single-project) binding; `minters` holds extra per-project
/// bindings keyed by GCP project id.
#[derive(Clone, Debug)]
pub struct GeminiConfig {
    pub api_base: String,
    pub project_id: String,
    pub minter_repo: String,
    pub minter_env: String,
    pub minter_key: String,
    pub rotation_days: u64,
    /// Extra per-project minter bindings, keyed by GCP project id. The
    /// top-level `project_id`/`minter_*` fields stay the default binding
    /// so single-project deployments keep working unchanged.
    pub minters: HashMap<String, GeminiMinter>,
}

/// Per-project minter pointer for the Gemini issuer: which GCP project a
/// minted key lives in, and which safe scope holds the minter bearer that
/// funds the mint.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct GeminiMinter {
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub minter_repo: String,
    #[serde(default)]
    pub minter_env: String,
    #[serde(default)]
    pub minter_key: String,
}

impl GeminiMinter {
    /// A binding is usable once it names a project and a minter key.
    pub fn enabled(&self) -> bool {
        !self.project_id.trim().is_empty() && !self.minter_key.trim().is_empty()
    }

    fn normalized(&self) -> Self {
        Self {
            project_id: self.project_id.trim().to_owned(),
            minter_repo: self.minter_repo.trim().to_owned(),
            minter_env: self.minter_env.trim().to_owned(),
            minter_key: self.minter_key.trim().to_owned(),
        }
    }
}

impl GeminiConfig {
    /// The issuer is active once the default binding or any per-project
    /// binding names a project and a minter key.
    pub fn enabled(&self) -> bool {
        (!self.project_id.trim().is_empty() && !self.minter_key.trim().is_empty())
            || self.minters.values().any(GeminiMinter::enabled)
    }

    /// Default (single-project) binding built from the top-level fields.
    pub fn default_minter(&self) -> GeminiMinter {
        GeminiMinter {
            project_id: self.project_id.trim().to_owned(),
            minter_repo: self.minter_repo.trim().to_owned(),
            minter_env: self.minter_env.trim().to_owned(),
            minter_key: self.minter_key.trim().to_owned(),
        }
    }

    /// Resolve which GCP project and minter pointer serves a request.
    /// An explicit `project` wins; otherwise `gcp-{store_repo}` is used
    /// when bound; otherwise the single-project default applies. Returns
    /// the effective project id with its minter binding.
    pub fn resolve_minter(
        &self,
        project: &str,
        store_repo: &str,
    ) -> Result<(String, GeminiMinter), String> {
        let explicit = project.trim();
        if !explicit.is_empty() {
            if let Some(minter) = self.minters.get(explicit) {
                return Ok((explicit.to_owned(), minter.normalized()));
            }
            if explicit == self.project_id.trim() && !self.project_id.trim().is_empty() {
                return Ok((self.project_id.trim().to_owned(), self.default_minter()));
            }
            return Err(format!(
                "unknown gemini project '{explicit}': no minter binding configured"
            ));
        }
        let derived = format!("gcp-{}", store_repo.trim());
        if let Some(minter) = self.minters.get(&derived) {
            return Ok((derived, minter.normalized()));
        }
        if !self.project_id.trim().is_empty() {
            return Ok((self.project_id.trim().to_owned(), self.default_minter()));
        }
        Err("gemini issuer is not configured".to_string())
    }

    /// Advisory rotation note returned to callers. Labeled clearly as NOT
    /// platform-enforced: API keys stay valid until deleted or rotated.
    pub fn rotation_advisory(&self) -> String {
        format!(
            "advisory only: rotate every {} days; NOT platform-enforced, keys stay valid until deleted",
            self.rotation_days
        )
    }
}

#[derive(Clone, Debug)]
pub struct R2Config {
    pub api_base: String,
    pub account_id: String,
    pub issuer_repo: String,
    pub issuer_env: String,
    pub issuer_token_key: String,
}

impl R2Config {
    /// The issuer is only active once an account id and issuer token key are set.
    pub fn enabled(&self) -> bool {
        !self.account_id.trim().is_empty() && !self.issuer_token_key.trim().is_empty()
    }
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
        let (github_pepper_file, github_pepper) =
            load_optional_pepper(&env_trim("FORT_GITHUB_PEPPER_FILE"))?;
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
            github_pepper_file,
            github_pepper,
            github_api_base: env_or(
                "FORT_GITHUB_API_BASE",
                crate::github_auth::DEFAULT_GITHUB_API_BASE,
            ),
            r2: R2Config {
                api_base: env_or("FORT_R2_API_BASE", crate::r2::DEFAULT_R2_API_BASE),
                account_id: env_or("FORT_R2_ACCOUNT_ID", ""),
                issuer_repo: env_or("FORT_R2_ISSUER_REPO", ""),
                issuer_env: env_or("FORT_R2_ISSUER_ENV", ""),
                issuer_token_key: env_or("FORT_R2_ISSUER_TOKEN_KEY", ""),
            },
            gemini: GeminiConfig {
                api_base: env_or(
                    "FORT_GEMINI_API_BASE",
                    crate::gemini::DEFAULT_GEMINI_API_BASE,
                ),
                project_id: env_or("FORT_GEMINI_PROJECT_ID", ""),
                minter_repo: env_or("FORT_GEMINI_MINTER_REPO", ""),
                minter_env: env_or("FORT_GEMINI_MINTER_ENV", ""),
                minter_key: env_or("FORT_GEMINI_MINTER_KEY", ""),
                rotation_days: parse_days_env(
                    "FORT_GEMINI_ROTATION_DAYS",
                    DEFAULT_GEMINI_ROTATION_DAYS,
                ),
                minters: parse_gemini_minters_env()?,
            },
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
        let (github_pepper_file, github_pepper) = load_optional_pepper(&parsed.github_pepper_file)?;
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
            github_pepper_file,
            github_pepper,
            github_api_base: normalize_value(
                parsed.github_api_base,
                crate::github_auth::DEFAULT_GITHUB_API_BASE,
            ),
            r2: R2Config {
                api_base: normalize_value(parsed.r2_api_base, crate::r2::DEFAULT_R2_API_BASE),
                account_id: normalize_value(parsed.r2_account_id, ""),
                issuer_repo: normalize_value(parsed.r2_issuer_repo, ""),
                issuer_env: normalize_value(parsed.r2_issuer_env, ""),
                issuer_token_key: normalize_value(parsed.r2_issuer_token_key, ""),
            },
            gemini: GeminiConfig {
                api_base: normalize_value(
                    parsed.gemini_api_base,
                    crate::gemini::DEFAULT_GEMINI_API_BASE,
                ),
                project_id: normalize_value(parsed.gemini_project_id, ""),
                minter_repo: normalize_value(parsed.gemini_minter_repo, ""),
                minter_env: normalize_value(parsed.gemini_minter_env, ""),
                minter_key: normalize_value(parsed.gemini_minter_key, ""),
                rotation_days: parse_days_value(
                    parsed.gemini_rotation_days.as_deref(),
                    DEFAULT_GEMINI_ROTATION_DAYS,
                ),
                minters: parsed
                    .gemini_minters
                    .into_iter()
                    .map(|(name, minter)| (name.trim().to_owned(), minter.normalized()))
                    .filter(|(name, _)| !name.is_empty())
                    .collect(),
            },
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
    #[serde(default)]
    github_pepper_file: String,
    #[serde(default)]
    github_api_base: String,
    #[serde(default)]
    r2_api_base: String,
    #[serde(default)]
    r2_account_id: String,
    #[serde(default)]
    r2_issuer_repo: String,
    #[serde(default)]
    r2_issuer_env: String,
    #[serde(default)]
    r2_issuer_token_key: String,
    #[serde(default)]
    gemini_api_base: String,
    #[serde(default)]
    gemini_project_id: String,
    #[serde(default)]
    gemini_minter_repo: String,
    #[serde(default)]
    gemini_minter_env: String,
    #[serde(default)]
    gemini_minter_key: String,
    #[serde(default)]
    gemini_rotation_days: Option<String>,
    /// Extra per-project minter bindings:
    /// `[gemini_minters."gcp-example"]` with `project_id`, `minter_repo`,
    /// `minter_env`, and `minter_key` keys.
    #[serde(default)]
    gemini_minters: HashMap<String, GeminiMinter>,
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

/// Optional `FORT_GEMINI_MINTERS` JSON object mapping GCP project ids to
/// minter bindings, e.g.
/// `{"gcp-lingospeak":{"project_id":"gcp-lingospeak","minter_repo":"infra",
/// "minter_env":"prod","minter_key":"GEMINI_MINTER_ACCESS_TOKEN_LINGOSPEAK"}}`.
/// Empty or unset means no extra bindings.
pub fn parse_gemini_minters_env() -> Result<HashMap<String, GeminiMinter>> {
    let raw = env_trim("FORT_GEMINI_MINTERS");
    if raw.is_empty() {
        return Ok(HashMap::new());
    }
    let parsed: HashMap<String, GeminiMinter> = serde_json::from_str(&raw)
        .with_context(|| "parse FORT_GEMINI_MINTERS as a JSON object of minter bindings")?;
    Ok(parsed
        .into_iter()
        .map(|(name, minter)| (name.trim().to_owned(), minter.normalized()))
        .filter(|(name, _)| !name.is_empty())
        .collect())
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
pub fn parse_days_env(name: &str, fallback: u64) -> u64 {
    parse_days_value(Some(env_trim(name).as_str()), fallback)
}

pub fn parse_days_value(value: Option<&str>, fallback: u64) -> u64 {
    let value = value.unwrap_or_default().trim();
    if value.is_empty() {
        return fallback;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|days| *days > 0)
        .unwrap_or(fallback)
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

fn load_optional_pepper(path: &str) -> Result<(Option<String>, Vec<u8>)> {
    let path = path.trim();
    if path.is_empty() {
        return Ok((None, Vec::new()));
    }
    let pepper = read_secret_file(path)?;
    if pepper.len() < 32 {
        bail!("GitHub pepper must be at least 32 characters");
    }
    Ok((Some(path.to_string()), pepper.into_bytes()))
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
        format!("{}/.vault/keyring.json", home.trim())
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
    fn file_config_defaults_normal_refresh_sessions_to_ninety_days() {
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
            Duration::from_secs(90 * 24 * 60 * 60)
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

    fn gemini_test_config() -> GeminiConfig {
        let mut minters = HashMap::new();
        minters.insert(
            "gcp-lingospeak".to_string(),
            GeminiMinter {
                project_id: "gcp-lingospeak".to_string(),
                minter_repo: "infra".to_string(),
                minter_env: "prod".to_string(),
                minter_key: "GEMINI_MINTER_ACCESS_TOKEN_LINGOSPEAK".to_string(),
            },
        );
        minters.insert(
            "gcp-releasemind".to_string(),
            GeminiMinter {
                project_id: "gcp-releasemind".to_string(),
                minter_repo: "infra".to_string(),
                minter_env: "prod".to_string(),
                minter_key: "GEMINI_MINTER_ACCESS_TOKEN_RELEASEMIND".to_string(),
            },
        );
        GeminiConfig {
            api_base: crate::gemini::DEFAULT_GEMINI_API_BASE.to_string(),
            project_id: "gcp-terra-terrabillion".to_string(),
            minter_repo: "infra".to_string(),
            minter_env: "prod".to_string(),
            minter_key: "GEMINI_MINTER_ACCESS_TOKEN_TERRA".to_string(),
            rotation_days: DEFAULT_GEMINI_ROTATION_DAYS,
            minters,
        }
    }

    #[test]
    fn gemini_resolve_explicit_project_wins() {
        let config = gemini_test_config();
        let (project, minter) = config
            .resolve_minter("gcp-lingospeak", "terrabillion")
            .expect("resolve explicit");
        assert_eq!(project, "gcp-lingospeak");
        assert_eq!(minter.minter_key, "GEMINI_MINTER_ACCESS_TOKEN_LINGOSPEAK");
    }

    #[test]
    fn gemini_resolve_explicit_default_project_uses_default_binding() {
        let config = gemini_test_config();
        let (project, minter) = config
            .resolve_minter("gcp-terra-terrabillion", "lingospeak")
            .expect("resolve default");
        assert_eq!(project, "gcp-terra-terrabillion");
        assert_eq!(minter.minter_key, "GEMINI_MINTER_ACCESS_TOKEN_TERRA");
    }

    #[test]
    fn gemini_resolve_rejects_removed_legacy_project() {
        let config = gemini_test_config();
        let error = config
            .resolve_minter("gcp-terrabillion", "lingospeak")
            .expect_err("removed project must fail");
        assert!(error.contains("gcp-terrabillion"), "error: {error}");
    }

    #[test]
    fn gemini_resolve_derives_project_from_store_scope() {
        let config = gemini_test_config();
        let (project, minter) = config
            .resolve_minter("", "releasemind")
            .expect("resolve derived");
        assert_eq!(project, "gcp-releasemind");
        assert_eq!(minter.minter_key, "GEMINI_MINTER_ACCESS_TOKEN_RELEASEMIND");
    }

    #[test]
    fn gemini_resolve_falls_back_to_default_binding() {
        let config = gemini_test_config();
        let (project, minter) = config
            .resolve_minter("", "unknown-repo")
            .expect("resolve fallback");
        assert_eq!(project, "gcp-terra-terrabillion");
        assert_eq!(minter.minter_key, "GEMINI_MINTER_ACCESS_TOKEN_TERRA");
    }

    #[test]
    fn gemini_resolve_rejects_unknown_explicit_project() {
        let config = gemini_test_config();
        let error = config
            .resolve_minter("gcp-nope", "lingospeak")
            .expect_err("unknown project must fail");
        assert!(error.contains("gcp-nope"), "error: {error}");
    }

    #[test]
    fn gemini_enabled_with_minters_only_and_no_default() {
        let mut config = gemini_test_config();
        config.project_id.clear();
        config.minter_key.clear();
        assert!(config.enabled());
        // No store-scope derivation and no default: resolution fails.
        assert!(config.resolve_minter("", "unknown-repo").is_err());
        // But the bound per-project binding still resolves explicitly.
        let (project, _) = config
            .resolve_minter("gcp-lingospeak", "")
            .expect("resolve bound project");
        assert_eq!(project, "gcp-lingospeak");
    }

    #[test]
    fn gemini_disabled_without_any_binding() {
        let config = GeminiConfig {
            api_base: crate::gemini::DEFAULT_GEMINI_API_BASE.to_string(),
            project_id: String::new(),
            minter_repo: String::new(),
            minter_env: String::new(),
            minter_key: String::new(),
            rotation_days: DEFAULT_GEMINI_ROTATION_DAYS,
            minters: HashMap::new(),
        };
        assert!(!config.enabled());
        assert!(config.resolve_minter("", "terrabillion").is_err());
    }

    #[test]
    fn file_config_parses_gemini_minter_bindings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let signing_key = dir.path().join("fort-jwt-signing.key");
        fs::write(&signing_key, "test-signing-key-that-is-long-enough").expect("write key");
        fs::set_permissions(&signing_key, fs::Permissions::from_mode(0o600))
            .expect("set key permissions");

        let config_path = dir.path().join("fort.toml");
        fs::write(
            &config_path,
            format!(
                "jwt_signing_key_file = \"{}\"\ngemini_project_id = \"gcp-terra-terrabillion\"\ngemini_minter_key = \"GEMINI_MINTER_ACCESS_TOKEN_TERRA\"\n[gemini_minters.\"gcp-lingospeak\"]\nproject_id = \"gcp-lingospeak\"\nminter_repo = \"infra\"\nminter_env = \"prod\"\nminter_key = \"GEMINI_MINTER_ACCESS_TOKEN_LINGOSPEAK\"\n",
                signing_key.display()
            ),
        )
        .expect("write config");

        let config = Config::from_file(&config_path).expect("load config");
        assert!(config.gemini.enabled());
        let (project, minter) = config
            .gemini
            .resolve_minter("gcp-lingospeak", "terrabillion")
            .expect("resolve bound project");
        assert_eq!(project, "gcp-lingospeak");
        assert_eq!(minter.minter_key, "GEMINI_MINTER_ACCESS_TOKEN_LINGOSPEAK");
        // Single-project default still resolves for unbound scopes.
        let (project, minter) = config
            .gemini
            .resolve_minter("", "unknown-repo")
            .expect("resolve default");
        assert_eq!(project, "gcp-terra-terrabillion");
        assert_eq!(minter.minter_key, "GEMINI_MINTER_ACCESS_TOKEN_TERRA");
        // Removed legacy project rejects cleanly (unknown project, not a 502).
        let error = config
            .gemini
            .resolve_minter("gcp-terrabillion", "")
            .expect_err("removed project must fail");
        assert!(error.contains("gcp-terrabillion"), "error: {error}");
    }
}
