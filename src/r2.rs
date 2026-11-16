//! Cloudflare R2 temporary-credential issuance.
//!
//! Fort holds a long-lived "issuer" Cloudflare API token in the safe (under a
//! policy scope) and uses it to mint short-lived, bucket-scoped R2 S3
//! credentials through the Cloudflare API. Temporary credentials cannot
//! exceed the permissions of the parent R2 API token they derive from, so
//! callers select the parent by its fort-safe key.

use serde::Deserialize;

pub const DEFAULT_R2_API_BASE: &str = "https://api.cloudflare.com/client/v4";
pub const MAX_TEMP_CREDENTIAL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

const PERMISSIONS: [&str; 4] = [
    "admin-read-write",
    "admin-read-only",
    "object-read-write",
    "object-read-only",
];

#[derive(Debug, Clone, Copy)]
pub struct TempCredentialsRequest<'a> {
    pub issuer_token: &'a str,
    pub account_id: &'a str,
    pub parent_access_key_id: &'a str,
    pub bucket: &'a str,
    pub permission: &'a str,
    pub ttl_seconds: u64,
    pub prefixes: &'a [String],
    pub objects: &'a [String],
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempCredentialsResult {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

#[derive(Debug)]
pub struct TempCredentialsError {
    pub status: u16,
    pub detail: String,
}

pub fn is_valid_permission(permission: &str) -> bool {
    PERMISSIONS.contains(&permission.trim())
}

/// Blocking call: POST /accounts/{account_id}/r2/temp-access-credentials
pub fn issue_temp_credentials(
    api_base: &str,
    request: &TempCredentialsRequest,
) -> Result<TempCredentialsResult, TempCredentialsError> {
    let base = api_base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(TempCredentialsError {
            status: 500,
            detail: "r2 api base is empty".to_string(),
        });
    }
    let url = format!(
        "{}/accounts/{}/r2/temp-access-credentials",
        base,
        request.account_id.trim()
    );
    let mut body = serde_json::json!({
        "bucket": request.bucket,
        "parentAccessKeyId": request.parent_access_key_id,
        "permission": request.permission,
        "ttlSeconds": request.ttl_seconds,
    });
    if !request.prefixes.is_empty() {
        body["prefixes"] = serde_json::json!(request.prefixes);
    }
    if !request.objects.is_empty() {
        body["objects"] = serde_json::json!(request.objects);
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| TempCredentialsError {
            status: 500,
            detail: error.to_string(),
        })?;
    let response = client
        .post(&url)
        .bearer_auth(request.issuer_token)
        .json(&body)
        .send()
        .map_err(|error| TempCredentialsError {
            status: 502,
            detail: format!("cloudflare request failed: {error}"),
        })?;
    let status = response.status().as_u16();
    let payload: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    if status != 200 || payload["success"].as_bool() != Some(true) {
        let detail = payload
            .get("errors")
            .and_then(|errors| errors.get(0))
            .and_then(|error| error.get("message"))
            .and_then(|message| message.as_str())
            .unwrap_or("cloudflare rejected the request")
            .to_string();
        return Err(TempCredentialsError { status, detail });
    }
    let result: TempCredentialsResult =
        serde_json::from_value(payload["result"].clone()).map_err(|error| {
            TempCredentialsError {
                status: 502,
                detail: format!("unexpected cloudflare response: {error}"),
            }
        })?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_are_validated() {
        assert!(is_valid_permission("object-read-only"));
        assert!(is_valid_permission(" admin-read-write "));
        assert!(!is_valid_permission("root"));
        assert!(!is_valid_permission(""));
    }

    #[test]
    fn temp_credential_ttl_cap_is_seven_days() {
        assert_eq!(MAX_TEMP_CREDENTIAL_TTL_SECONDS, 604800);
    }
}
