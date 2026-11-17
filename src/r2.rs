//! Cloudflare R2 credential issuance.
//!
//! Fort holds long-lived Cloudflare API tokens in the safe (under policy
//! scopes) and mints two credential shapes through the Cloudflare API:
//! short-lived bucket-scoped temporary S3 credentials (derived from a parent
//! R2 token, capped at seven days), and long-lived least-privilege R2 API
//! tokens whose S3 pairs are stored back in Fort. Temporary credentials
//! cannot exceed the permissions of the parent R2 API token they derive
//! from, so callers select the parent by its fort-safe key.

use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const DEFAULT_R2_API_BASE: &str = "https://api.cloudflare.com/client/v4";
pub const MAX_TEMP_CREDENTIAL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const R2_GROUP_ITEM_WRITE_NAME: &str = "Workers R2 Storage Bucket Item Write";
pub const R2_GROUP_ITEM_READ_NAME: &str = "Workers R2 Storage Bucket Item Read";

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
pub struct R2Error {
    pub status: u16,
    pub detail: String,
}

#[derive(Debug, Clone, Copy)]
pub struct R2BucketGrant<'a> {
    pub bucket: &'a str,
    pub permission: &'a str,
}

#[derive(Debug)]
pub struct CreatedAccountToken {
    pub id: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenPolicyGroup {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenPolicy {
    #[serde(default)]
    pub resources: serde_json::Value,
    #[serde(default)]
    pub permission_groups: Vec<TokenPolicyGroup>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AccountTokenDetails {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub policies: Vec<TokenPolicy>,
    pub issued_on: Option<String>,
    pub expires_on: Option<String>,
}

pub fn is_valid_permission(permission: &str) -> bool {
    PERMISSIONS.contains(&permission.trim())
}

pub fn is_object_permission(permission: &str) -> bool {
    matches!(permission.trim(), "object-read-write" | "object-read-only")
}

fn api_client() -> Result<reqwest::blocking::Client, R2Error> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| R2Error {
            status: 500,
            detail: error.to_string(),
        })
}

fn api_base_url(api_base: &str) -> Result<String, R2Error> {
    let base = api_base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(R2Error {
            status: 500,
            detail: "r2 api base is empty".to_string(),
        });
    }
    Ok(base.to_string())
}

fn cloudflare_error(status: u16, payload: &serde_json::Value) -> R2Error {
    let detail = payload
        .get("errors")
        .and_then(|errors| errors.get(0))
        .and_then(|error| error.get("message"))
        .and_then(|message| message.as_str())
        .unwrap_or("cloudflare rejected the request")
        .to_string();
    R2Error { status, detail }
}

fn cf_post(
    api_base: &str,
    bearer: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, R2Error> {
    let base = api_base_url(api_base)?;
    let client = api_client()?;
    let response = client
        .post(format!("{base}{path}"))
        .bearer_auth(bearer)
        .json(body)
        .send()
        .map_err(|error| R2Error {
            status: 502,
            detail: format!("cloudflare request failed: {error}"),
        })?;
    let status = response.status().as_u16();
    let payload: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    if status != 200 || payload["success"].as_bool() != Some(true) {
        return Err(cloudflare_error(status, &payload));
    }
    Ok(payload["result"].clone())
}

fn cf_get(api_base: &str, bearer: &str, path: &str) -> Result<serde_json::Value, R2Error> {
    let base = api_base_url(api_base)?;
    let client = api_client()?;
    let response = client
        .get(format!("{base}{path}"))
        .bearer_auth(bearer)
        .send()
        .map_err(|error| R2Error {
            status: 502,
            detail: format!("cloudflare request failed: {error}"),
        })?;
    let status = response.status().as_u16();
    let payload: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    if status != 200 || payload["success"].as_bool() != Some(true) {
        return Err(cloudflare_error(status, &payload));
    }
    Ok(payload.clone())
}

fn cf_delete(api_base: &str, bearer: &str, path: &str) -> Result<(), R2Error> {
    let base = api_base_url(api_base)?;
    let client = api_client()?;
    let response = client
        .delete(format!("{base}{path}"))
        .bearer_auth(bearer)
        .send()
        .map_err(|error| R2Error {
            status: 502,
            detail: format!("cloudflare request failed: {error}"),
        })?;
    let status = response.status().as_u16();
    let payload: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    if status != 200 || payload["success"].as_bool() != Some(true) {
        return Err(cloudflare_error(status, &payload));
    }
    Ok(())
}

/// Blocking call: POST /accounts/{account_id}/r2/temp-access-credentials
pub fn issue_temp_credentials(
    api_base: &str,
    request: &TempCredentialsRequest,
) -> Result<TempCredentialsResult, R2Error> {
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
    let path = format!(
        "/accounts/{}/r2/temp-access-credentials",
        request.account_id.trim()
    );
    let result = cf_post(api_base, request.issuer_token, &path, &body)?;
    serde_json::from_value(result).map_err(|error| R2Error {
        status: 502,
        detail: format!("unexpected cloudflare response: {error}"),
    })
}

/// Resolves a permission-group id by name (group ids are stable but undocumented).
pub fn permission_group_id(
    api_base: &str,
    bearer: &str,
    account_id: &str,
    name: &str,
) -> Result<String, R2Error> {
    let path = format!("/accounts/{}/tokens/permission_groups", account_id.trim());
    let payload = cf_get(api_base, bearer, &path)?;
    payload["result"]
        .as_array()
        .and_then(|groups| {
            groups.iter().find_map(|group| {
                if group["name"].as_str() == Some(name) {
                    group["id"].as_str().map(str::to_string)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| R2Error {
            status: 502,
            detail: format!("cloudflare permission group not found: {name}"),
        })
}

/// Blocking call: POST /accounts/{account_id}/tokens with an R2 object policy.
pub fn create_r2_token(
    api_base: &str,
    bearer: &str,
    account_id: &str,
    name: &str,
    grants: &[R2BucketGrant],
) -> Result<CreatedAccountToken, R2Error> {
    if name.trim().is_empty() {
        return Err(R2Error {
            status: 400,
            detail: "token name is required".to_string(),
        });
    }
    if grants.is_empty() {
        return Err(R2Error {
            status: 400,
            detail: "at least one bucket grant is required".to_string(),
        });
    }
    for grant in grants {
        if grant.bucket.trim().is_empty() {
            return Err(R2Error {
                status: 400,
                detail: "bucket name is required".to_string(),
            });
        }
        if !is_object_permission(grant.permission) {
            return Err(R2Error {
                status: 400,
                detail: "create supports object-read-write and object-read-only only".to_string(),
            });
        }
    }
    let account_id = account_id.trim();
    let mut need_write = false;
    let mut need_read = false;
    for grant in grants {
        match grant.permission.trim() {
            "object-read-write" => need_write = true,
            _ => need_read = true,
        }
    }
    let mut groups = Vec::new();
    if need_write {
        groups.push(serde_json::json!({"id": permission_group_id(api_base, bearer, account_id, R2_GROUP_ITEM_WRITE_NAME)?}));
    }
    if need_read {
        groups.push(serde_json::json!({"id": permission_group_id(api_base, bearer, account_id, R2_GROUP_ITEM_READ_NAME)?}));
    }
    let mut resources = serde_json::Map::new();
    for grant in grants {
        resources.insert(
            format!(
                "com.cloudflare.edge.r2.bucket.{account_id}_default_{}",
                grant.bucket.trim()
            ),
            serde_json::Value::String("*".to_string()),
        );
    }
    let body = serde_json::json!({
        "name": name.trim(),
        "policies": [{"effect": "allow", "resources": resources, "permission_groups": groups}],
    });
    let result = cf_post(
        api_base,
        bearer,
        &format!("/accounts/{account_id}/tokens"),
        &body,
    )?;
    let id = result["id"].as_str().unwrap_or_default().trim().to_string();
    let value = result["value"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_string();
    if id.is_empty() || value.is_empty() {
        return Err(R2Error {
            status: 502,
            detail: "cloudflare token create response missing id or value".to_string(),
        });
    }
    Ok(CreatedAccountToken { id, value })
}

/// Derives the S3 secret access key from an API-created token value.
pub fn s3_secret_from_token_value(value: &str) -> String {
    hex::encode(Sha256::digest(value.trim().as_bytes()))
}

/// Blocking call: GET /accounts/{account_id}/tokens/{token_id}
pub fn get_account_token(
    api_base: &str,
    bearer: &str,
    account_id: &str,
    token_id: &str,
) -> Result<AccountTokenDetails, R2Error> {
    let result = cf_get(
        api_base,
        bearer,
        &format!("/accounts/{}/tokens/{}", account_id.trim(), token_id.trim()),
    )?;
    serde_json::from_value(result["result"].clone()).map_err(|error| R2Error {
        status: 502,
        detail: format!("unexpected cloudflare response: {error}"),
    })
}

/// Blocking call: GET /accounts/{account_id}/tokens (all pages).
pub fn list_account_tokens(
    api_base: &str,
    bearer: &str,
    account_id: &str,
) -> Result<Vec<AccountTokenDetails>, R2Error> {
    let mut tokens = Vec::new();
    let mut page = 1;
    loop {
        let payload = cf_get(
            api_base,
            bearer,
            &format!(
                "/accounts/{}/tokens?per_page=100&page={page}",
                account_id.trim()
            ),
        )?;
        let items = payload["result"].as_array().cloned().unwrap_or_default();
        let total = payload["result_info"]["total_count"].as_u64();
        for item in &items {
            tokens.push(
                serde_json::from_value(item.clone()).map_err(|error| R2Error {
                    status: 502,
                    detail: format!("unexpected cloudflare response: {error}"),
                })?,
            );
        }
        match total {
            Some(total) if tokens.len() as u64 >= total => break,
            _ if items.len() < 100 => break,
            _ => page += 1,
        }
    }
    Ok(tokens)
}

/// Extracts (bucket, permission) grants from a token's live policies.
/// Only R2 bucket-item policies qualify; anything else must rotate by hand.
pub fn object_grants_from_token(
    token: &AccountTokenDetails,
) -> Result<Vec<(String, String)>, R2Error> {
    let unsupported = || R2Error {
        status: 400,
        detail: "token policy is not object-scoped R2; rotate it manually".to_string(),
    };
    let mut grants = Vec::new();
    for policy in &token.policies {
        let mut write = false;
        let mut read = false;
        for group in &policy.permission_groups {
            match group.name.as_str() {
                "Workers R2 Storage Bucket Item Write" => write = true,
                "Workers R2 Storage Bucket Item Read" => read = true,
                _ => return Err(unsupported()),
            }
        }
        if !write && !read {
            return Err(unsupported());
        }
        let permission = if write {
            "object-read-write"
        } else {
            "object-read-only"
        };
        let resources = policy.resources.as_object().ok_or_else(unsupported)?;
        if resources.is_empty() {
            return Err(unsupported());
        }
        for resource in resources.keys() {
            let mut parts = resource.rsplit('_');
            let bucket = parts.next().unwrap_or_default();
            let jurisdiction = parts.next().unwrap_or_default();
            let account = parts.next().unwrap_or_default();
            if parts.next().is_some()
                || bucket.is_empty()
                || jurisdiction.is_empty()
                || account.is_empty()
                || !account.starts_with("com.cloudflare.edge.r2.bucket.")
            {
                return Err(unsupported());
            }
            grants.push((bucket.to_string(), permission.to_string()));
        }
    }
    if grants.is_empty() {
        return Err(unsupported());
    }
    Ok(grants)
}

/// Blocking call: DELETE /accounts/{account_id}/tokens/{token_id}
pub fn delete_account_token(
    api_base: &str,
    bearer: &str,
    account_id: &str,
    token_id: &str,
) -> Result<(), R2Error> {
    cf_delete(
        api_base,
        bearer,
        &format!("/accounts/{}/tokens/{}", account_id.trim(), token_id.trim()),
    )
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn s3_signing_key(secret: &str, date: &str, region: &str) -> Vec<u8> {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"s3");
    hmac_sha256(&service_key, b"aws4_request")
}

struct S3SignRequest<'a> {
    method: &'a str,
    uri_path: &'a str,
    host: &'a str,
    amz_date: &'a str,
    date: &'a str,
    region: &'a str,
    access_key: &'a str,
    secret: &'a str,
}

/// Builds the SigV4 Authorization header for an S3 request with an empty body.
/// Bucket names are DNS-safe by Cloudflare rule, so the path needs no encoding.
fn s3_authorization(request: &S3SignRequest) -> (String, String) {
    let payload_hash = hex::encode(Sha256::digest(b""));
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{}\n",
        request.host, request.amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "{}\n{}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        request.method, request.uri_path
    );
    let scope = format!("{}/{}/s3/aws4_request", request.date, request.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        request.amz_date,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let signature = hex::encode(hmac_sha256(
        &s3_signing_key(request.secret, request.date, request.region),
        string_to_sign.as_bytes(),
    ));
    (
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            request.access_key
        ),
        payload_hash,
    )
}

/// Blocking SigV4 HEAD Bucket against an S3-compatible endpoint.
pub fn head_bucket(
    endpoint: &str,
    access_key: &str,
    secret: &str,
    bucket: &str,
) -> Result<(), R2Error> {
    let endpoint = endpoint.trim().trim_end_matches('/');
    if endpoint.is_empty() || bucket.trim().is_empty() {
        return Err(R2Error {
            status: 400,
            detail: "s3 endpoint and bucket are required".to_string(),
        });
    }
    let host = url::Url::parse(endpoint)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .filter(|host| !host.is_empty())
        .ok_or_else(|| R2Error {
            status: 400,
            detail: "s3 endpoint is not a valid URL".to_string(),
        })?;
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let (authorization, payload_hash) = s3_authorization(&S3SignRequest {
        method: "HEAD",
        uri_path: &format!("/{}", bucket.trim()),
        host: &host,
        amz_date: &amz_date,
        date: &date,
        region: "auto",
        access_key: access_key.trim(),
        secret: secret.trim(),
    });
    let client = api_client()?;
    let response = client
        .head(format!("{endpoint}/{}", bucket.trim()))
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-date", amz_date)
        .header("authorization", authorization)
        .send()
        .map_err(|error| R2Error {
            status: 502,
            detail: format!("s3 request failed: {error}"),
        })?;
    match response.status().as_u16() {
        200 => Ok(()),
        403 => Err(R2Error {
            status: 403,
            detail: "s3 signature or permission rejected".to_string(),
        }),
        404 => Err(R2Error {
            status: 404,
            detail: "s3 bucket not found".to_string(),
        }),
        status => Err(R2Error {
            status,
            detail: format!("s3 head bucket failed with status {status}"),
        }),
    }
}

/// HeadBucket with retries: fresh Cloudflare tokens need about a minute
/// before the S3 data plane accepts them.
pub fn head_bucket_with_retry(
    endpoint: &str,
    access_key: &str,
    secret: &str,
    bucket: &str,
    attempts: u32,
    delay_secs: u64,
) -> Result<(), R2Error> {
    let attempts = attempts.max(1);
    let mut last = R2Error {
        status: 500,
        detail: "s3 verification never ran".to_string(),
    };
    for attempt in 1..=attempts {
        match head_bucket(endpoint, access_key, secret, bucket) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last = error;
                if attempt < attempts {
                    std::thread::sleep(std::time::Duration::from_secs(delay_secs));
                }
            }
        }
    }
    Err(last)
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
    fn object_permissions_are_restricted() {
        assert!(is_object_permission("object-read-write"));
        assert!(is_object_permission("object-read-only"));
        assert!(!is_object_permission("admin-read-write"));
        assert!(!is_object_permission("root"));
    }

    #[test]
    fn temp_credential_ttl_cap_is_seven_days() {
        assert_eq!(MAX_TEMP_CREDENTIAL_TTL_SECONDS, 604800);
    }

    #[test]
    fn grants_parse_from_object_policies() {
        let token: AccountTokenDetails = serde_json::from_value(serde_json::json!({
            "id": "tid",
            "name": "t",
            "status": "active",
            "policies": [{
                "resources": {
                    "com.cloudflare.edge.r2.bucket.acct_default_b-one": "*",
                    "com.cloudflare.edge.r2.bucket.acct_eu_b-two": "*"
                },
                "permission_groups": [
                    {"id": "w", "name": "Workers R2 Storage Bucket Item Write"}
                ]
            }]
        }))
        .expect("fixture parses");
        let mut grants = object_grants_from_token(&token).expect("grants parse");
        grants.sort();
        assert_eq!(
            grants,
            vec![
                ("b-one".to_string(), "object-read-write".to_string()),
                ("b-two".to_string(), "object-read-write".to_string()),
            ]
        );
    }

    #[test]
    fn grants_reject_non_object_policies() {
        let token: AccountTokenDetails = serde_json::from_value(serde_json::json!({
            "id": "tid",
            "name": "t",
            "status": "active",
            "policies": [{
                "resources": {"com.cloudflare.api.account.acct": "*"},
                "permission_groups": [{"id": "w", "name": "Workers R2 Storage Write"}]
            }]
        }))
        .expect("fixture parses");
        assert!(object_grants_from_token(&token).is_err());
    }

    #[test]
    fn s3_secret_derivation_matches_sha256() {
        assert_eq!(
            s3_secret_from_token_value("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            s3_secret_from_token_value("  abc  "),
            s3_secret_from_token_value("abc")
        );
    }

    #[test]
    fn s3_signing_is_deterministic_and_keyed() {
        let base = S3SignRequest {
            method: "HEAD",
            uri_path: "/example-bucket",
            host: "example.r2.cloudflarestorage.com",
            amz_date: "20261116T000000Z",
            date: "20261116",
            region: "auto",
            access_key: "AKID",
            secret: "secret",
        };
        let (first, payload) = s3_authorization(&base);
        let (second, _) = s3_authorization(&base);
        let (other_key, _) = s3_authorization(&S3SignRequest {
            secret: "other",
            ..base
        });
        assert_eq!(first, second);
        assert_ne!(first, other_key);
        assert!(
            first.starts_with("AWS4-HMAC-SHA256 Credential=AKID/20261116/auto/s3/aws4_request")
        );
        assert_eq!(
            payload,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
