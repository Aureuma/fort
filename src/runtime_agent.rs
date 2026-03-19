use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rand::Rng;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub refresh_token_file: String,
    pub token_path: String,
    pub refresh_ratio: f64,
    pub jitter: Duration,
    pub min_sleep: Duration,
    pub max_backoff: Duration,
    pub http_timeout: Duration,
    pub once: bool,
}

pub struct Runtime {
    config: Config,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    access_expires_at: String,
}

impl Runtime {
    pub fn new(mut config: Config) -> Result<Self> {
        config.host = config.host.trim().trim_end_matches('/').to_string();
        config.refresh_token_file = config.refresh_token_file.trim().to_string();
        config.token_path = config.token_path.trim().to_string();
        if config.host.is_empty() {
            bail!("host is required");
        }
        if config.refresh_token_file.is_empty() {
            bail!("refresh token file is required");
        }
        if config.token_path.is_empty() {
            bail!("token path is required");
        }
        if !(0.0..1.0).contains(&config.refresh_ratio) {
            config.refresh_ratio = 0.70;
        }
        if config.min_sleep.is_zero() {
            config.min_sleep = Duration::from_secs(5);
        }
        if config.max_backoff.is_zero() {
            config.max_backoff = Duration::from_secs(30);
        }
        if config.http_timeout.is_zero() {
            config.http_timeout = Duration::from_secs(10);
        }
        let client = Client::builder()
            .timeout(config.http_timeout)
            .build()
            .context("build http client")?;
        Ok(Self { config, client })
    }

    pub fn run(&self) -> Result<()> {
        let mut refresh_token = read_secret_token_file(&self.config.refresh_token_file)?;
        let mut backoff = Duration::from_secs(1);
        loop {
            let response = self.refresh(&refresh_token);
            match response {
                Ok(payload) => {
                    write_secret_token_file(
                        &self.config.refresh_token_file,
                        &payload.refresh_token,
                    )?;
                    write_token_atomic(&self.config.token_path, &payload.access_token)?;
                    refresh_token = payload.refresh_token.trim().to_string();
                    if self.config.once {
                        return Ok(());
                    }
                    let expires_at =
                        chrono::DateTime::parse_from_rfc3339(&payload.access_expires_at)
                            .context("parse access_expires_at")?
                            .with_timezone(&chrono::Utc);
                    let next_sleep = compute_next_sleep(
                        chrono::Utc::now(),
                        expires_at,
                        self.config.refresh_ratio,
                        self.config.jitter,
                        self.config.min_sleep,
                    );
                    backoff = Duration::from_secs(1);
                    thread::sleep(next_sleep);
                }
                Err(error) => {
                    let rendered = error.to_string();
                    if rendered.contains("status=401") || rendered.contains("status=403") {
                        bail!("{error}");
                    }
                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(self.config.max_backoff);
                }
            }
        }
    }

    fn refresh(&self, refresh_token: &str) -> Result<RefreshResponse> {
        let response = self
            .client
            .post(format!("{}/v1/auth/session/refresh", self.config.host))
            .json(&json!({ "refresh_token": refresh_token.trim() }))
            .send()
            .context("send refresh request")?;
        if !response.status().is_success() {
            bail!("refresh rejected (status={})", response.status());
        }
        let payload: RefreshResponse = response.json().context("decode refresh response")?;
        if payload.access_token.trim().is_empty()
            || payload.refresh_token.trim().is_empty()
            || payload.access_expires_at.trim().is_empty()
        {
            bail!("invalid refresh response payload");
        }
        Ok(payload)
    }
}

pub fn compute_next_sleep(
    now: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    ratio: f64,
    jitter: Duration,
    min_sleep: Duration,
) -> Duration {
    let ttl = expires_at.signed_duration_since(now);
    if ttl.num_milliseconds() <= 0 {
        return min_sleep;
    }
    let ttl_std = ttl.to_std().unwrap_or(min_sleep);
    let mut base = ttl_std.mul_f64(ratio);
    if base < min_sleep {
        base = min_sleep;
    }
    if !jitter.is_zero() {
        let max = jitter.as_nanos() as i128;
        let jitter_ns = rand::thread_rng().gen_range(-max..=max);
        if jitter_ns >= 0 {
            base += Duration::from_nanos(jitter_ns as u64);
        } else {
            base = base.saturating_sub(Duration::from_nanos((-jitter_ns) as u64));
        }
    }
    let ceiling = ttl_std.saturating_sub(min_sleep).max(min_sleep);
    base.clamp(min_sleep, ceiling)
}

pub fn read_secret_token_file(path: &str) -> Result<String> {
    let path = PathBuf::from(path.trim());
    if path.as_os_str().is_empty() {
        bail!("refresh token path is empty");
    }
    let metadata = fs::metadata(&path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("refresh token path is not a regular file");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("refresh token file permissions must be 0600 or stricter");
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        bail!("refresh token file is empty");
    }
    Ok(token)
}

pub fn write_secret_token_file(path: &str, value: &str) -> Result<()> {
    let path = PathBuf::from(path.trim());
    let value = value.trim();
    if path.as_os_str().is_empty() {
        bail!("refresh token path is empty");
    }
    if value.is_empty() {
        bail!("refresh token value is empty");
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", parent.display()))?;
    }
    if path.exists() {
        let metadata = fs::metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        if !metadata.is_file() {
            bail!("refresh token path is not a regular file");
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("refresh token file permissions must be 0600 or stricter");
        }
    }
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp, value.as_bytes()).with_context(|| format!("write {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

pub fn write_token_atomic(path: &str, value: &str) -> Result<()> {
    let path = PathBuf::from(path.trim());
    if path.as_os_str().is_empty() {
        bail!("token path is empty");
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", parent.display()))?;
    }
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&tmp, value.as_bytes()).with_context(|| format!("write {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}
