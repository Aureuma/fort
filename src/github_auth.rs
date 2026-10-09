//! GitHub fine-grained PAT authentication.
//!
//! Remote machines authenticate with a GitHub fine-grained PAT that Fort
//! verifies live against the GitHub API (`GET /user`). Fort never stores the
//! PAT itself: the stable machine identity is an HMAC-SHA256 fingerprint keyed
//! by a server-side pepper, and only that fingerprint is persisted.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

pub const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";
const GITHUB_API_VERSION: &str = "2022-11-28";
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

type HmacSha256 = Hmac<Sha256>;

/// Stable, non-reversible machine identity for a PAT.
///
/// Keyed by the server pepper so fingerprints from one Fort instance are
/// meaningless elsewhere and cannot be brute-forced without the pepper.
pub fn fingerprint_pat(pepper: &[u8], pat: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(pepper).expect("hmac accepts any key length");
    mac.update(pat.trim().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Short prefix for logs and listings; never the full fingerprint.
pub fn fingerprint_prefix(fingerprint: &str) -> &str {
    let end = fingerprint.len().min(12);
    &fingerprint[..end]
}

#[derive(Clone, Debug)]
pub struct GithubUser {
    pub login: String,
    pub id: i64,
}

#[derive(Debug, Deserialize)]
struct GithubUserResponse {
    #[serde(default)]
    login: String,
    #[serde(default)]
    id: i64,
}

pub enum VerifyOutcome {
    Valid(GithubUser),
    Invalid,
    Unavailable(String),
}

/// Verify a PAT against `GET {api_base}/user`.
///
/// Blocking with a fixed timeout; callers on an async runtime must run this
/// inside `spawn_blocking`. Any valid token (including a fine-grained PAT with
/// no permissions) yields the authenticated user.
pub fn verify_pat(api_base: &str, pat: &str) -> VerifyOutcome {
    let pat = pat.trim();
    if pat.is_empty() {
        return VerifyOutcome::Invalid;
    }
    match verify_pat_inner(api_base, pat) {
        Ok(outcome) => outcome,
        Err(error) => VerifyOutcome::Unavailable(error.to_string()),
    }
}

fn verify_pat_inner(api_base: &str, pat: &str) -> Result<VerifyOutcome> {
    let base = api_base.trim();
    if base.is_empty() {
        bail!("github api base is empty");
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(VERIFY_TIMEOUT)
        .build()
        .context("build github client")?;
    let url = format!("{}/user", base.trim_end_matches('/'));
    let response = client
        .get(&url)
        .bearer_auth(pat)
        .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
        .header(
            "User-Agent",
            format!("fort/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .context("call github api")?;
    let status = response.status().as_u16();
    match status {
        200 => {
            let user: GithubUserResponse =
                response.json().context("decode github user")?;
            if user.login.trim().is_empty() {
                return Ok(VerifyOutcome::Unavailable(
                    "github user response missing login".to_string(),
                ));
            }
            Ok(VerifyOutcome::Valid(GithubUser {
                login: user.login,
                id: user.id,
            }))
        }
        401 | 404 => Ok(VerifyOutcome::Invalid),
        403 => {
            let rate_limited = response
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.trim() == "0");
            if rate_limited {
                Ok(VerifyOutcome::Unavailable(
                    "github api rate limited".to_string(),
                ))
            } else {
                Ok(VerifyOutcome::Invalid)
            }
        }
        _ => Ok(VerifyOutcome::Unavailable(format!(
            "github api status {status}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_hex() {
        let pepper = b"test-pepper-that-is-long-enough-32";
        let first = fingerprint_pat(pepper, "github_pat_test");
        let second = fingerprint_pat(pepper, "  github_pat_test\n");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_changes_with_pepper_or_pat() {
        let base = fingerprint_pat(b"pepper-one-that-is-long-enough-32!", "pat-a");
        assert_ne!(
            base,
            fingerprint_pat(b"pepper-two-that-is-long-enough-32!", "pat-a")
        );
        assert_ne!(
            base,
            fingerprint_pat(b"pepper-one-that-is-long-enough-32!", "pat-b")
        );
    }

    #[test]
    fn fingerprint_prefix_truncates() {
        assert_eq!(fingerprint_prefix("abcdef0123456789"), "abcdef012345");
        assert_eq!(fingerprint_prefix("short"), "short");
    }

    #[test]
    fn empty_pat_is_invalid_without_network() {
        assert!(matches!(
            verify_pat("http://127.0.0.1:1", ""),
            VerifyOutcome::Invalid
        ));
        assert!(matches!(
            verify_pat("http://127.0.0.1:1", "   "),
            VerifyOutcome::Invalid
        ));
    }
}
