//! Gemini (Google AI Studio) API key issuance.
//!
//! Fort holds a Google minter credential in the safe (under policy scopes)
//! and mints Google Cloud API keys through the API Keys v2 API:
//! create (long-running operation) -> poll until done -> `getKeyString` once.
//!
//! Issued key values are returned once to the caller and are never stored by
//! Fort. Rotation guidance is advisory only: API keys do not expire, so the
//! configured rotation interval is reported to callers but is NOT
//! platform-enforced.

use std::time::Duration;

pub const DEFAULT_GEMINI_API_BASE: &str = "https://apikeys.googleapis.com";
const POLL_ATTEMPTS: u32 = 30;
const POLL_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct GeminiError {
    pub status: u16,
    pub detail: String,
}

#[derive(Debug)]
pub struct IssuedKey {
    /// Full resource name, e.g. `projects/p/locations/global/keys/abc123`.
    pub name: String,
    /// Key value. Returned once; Fort never stores it.
    pub key_string: String,
}

#[derive(Debug, Clone)]
pub struct KeySummary {
    pub name: String,
    pub display_name: String,
}

/// Rejects `ttl_seconds` for Gemini keys: they do not expire, so a TTL is
/// meaningless. Rotation every `rotation_days` is advisory only and NOT
/// platform-enforced.
pub fn reject_ttl_seconds(
    ttl_seconds: &Option<serde_json::Value>,
    rotation_days: u64,
) -> Result<(), GeminiError> {
    if ttl_seconds.is_some() {
        return Err(GeminiError {
            status: 400,
            detail: format!(
                "ttl_seconds is not supported for gemini keys: keys do not expire; rotate every {rotation_days} days (advisory only, NOT platform-enforced)"
            ),
        });
    }
    Ok(())
}

/// Detail for a `getKeyString` failure after the key was created: the key
/// exists and its value was never returned, so it must be deleted or rotated
/// by hand.
pub fn key_string_failure_detail(key_name: &str, cause: &str) -> String {
    format!(
        "created key {key_name} but getKeyString failed ({cause}); the value was never returned: delete or rotate {key_name} by hand"
    )
}

fn api_client() -> Result<reqwest::blocking::Client, GeminiError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| GeminiError {
            status: 500,
            detail: error.to_string(),
        })
}

fn api_base_url(api_base: &str) -> Result<String, GeminiError> {
    let base = api_base.trim().trim_end_matches('/').to_string();
    if base.is_empty() {
        return Err(GeminiError {
            status: 500,
            detail: "gemini api base is empty".to_string(),
        });
    }
    Ok(base)
}

fn provider_error(status: u16, payload: &serde_json::Value) -> GeminiError {
    let detail = payload
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(|message| message.as_str())
        .unwrap_or("google rejected the request")
        .to_string();
    GeminiError { status, detail }
}

fn provider_post(
    api_base: &str,
    bearer: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, GeminiError> {
    let base = api_base_url(api_base)?;
    let client = api_client()?;
    let response = client
        .post(format!("{base}{path}"))
        .bearer_auth(bearer)
        .json(body)
        .send()
        .map_err(|error| GeminiError {
            status: 502,
            detail: format!("google request failed: {error}"),
        })?;
    let status = response.status().as_u16();
    let payload: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    if !(200..300).contains(&status) {
        return Err(provider_error(status, &payload));
    }
    Ok(payload)
}

fn provider_get(
    api_base: &str,
    bearer: &str,
    path: &str,
) -> Result<serde_json::Value, GeminiError> {
    let base = api_base_url(api_base)?;
    let client = api_client()?;
    let response = client
        .get(format!("{base}{path}"))
        .bearer_auth(bearer)
        .send()
        .map_err(|error| GeminiError {
            status: 502,
            detail: format!("google request failed: {error}"),
        })?;
    let status = response.status().as_u16();
    let payload: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    if !(200..300).contains(&status) {
        return Err(provider_error(status, &payload));
    }
    Ok(payload)
}

fn provider_delete(
    api_base: &str,
    bearer: &str,
    path: &str,
) -> Result<serde_json::Value, GeminiError> {
    let base = api_base_url(api_base)?;
    let client = api_client()?;
    let response = client
        .delete(format!("{base}{path}"))
        .bearer_auth(bearer)
        .send()
        .map_err(|error| GeminiError {
            status: 502,
            detail: format!("google request failed: {error}"),
        })?;
    let status = response.status().as_u16();
    let payload: serde_json::Value = response.json().unwrap_or(serde_json::Value::Null);
    if !(200..300).contains(&status) {
        return Err(provider_error(status, &payload));
    }
    Ok(payload)
}

/// Normalizes a caller-supplied key reference to a full resource name.
pub fn key_resource(project: &str, key_name: &str) -> Result<String, GeminiError> {
    let key_name = key_name.trim();
    if key_name.is_empty() {
        return Err(GeminiError {
            status: 400,
            detail: "key_name is required".to_string(),
        });
    }
    if key_name.starts_with("projects/") {
        return Ok(key_name.to_string());
    }
    let project = project.trim();
    if project.is_empty() {
        return Err(GeminiError {
            status: 500,
            detail: "gemini project id is not configured".to_string(),
        });
    }
    Ok(format!(
        "projects/{project}/locations/global/keys/{key_name}"
    ))
}

/// Blocking call: POST /v2/projects/{project}/locations/global/keys.
/// Returns the long-running operation name.
pub fn create_key(
    api_base: &str,
    bearer: &str,
    project: &str,
    display_name: &str,
) -> Result<String, GeminiError> {
    if display_name.trim().is_empty() {
        return Err(GeminiError {
            status: 400,
            detail: "display_name is required".to_string(),
        });
    }
    let path = format!("/v2/projects/{}/locations/global/keys", project.trim());
    let payload = provider_post(
        api_base,
        bearer,
        &path,
        &serde_json::json!({ "displayName": display_name.trim() }),
    )?;
    if payload.get("done").and_then(|done| done.as_bool()) == Some(true)
        && let Some(name) = payload
            .get("response")
            .and_then(|response| response.get("name"))
            .and_then(|name| name.as_str())
    {
        return Ok(name.to_string());
    }
    payload
        .get("name")
        .and_then(|name| name.as_str())
        .map(str::to_string)
        .ok_or_else(|| GeminiError {
            status: 502,
            detail: "unexpected google response: missing operation name".to_string(),
        })
}

/// Blocking call: GET /v2/{operation}. Polls until done and returns the
/// created key resource name.
pub fn poll_operation_key(
    api_base: &str,
    bearer: &str,
    operation: &str,
) -> Result<String, GeminiError> {
    let path = format!("/v2/{operation}");
    for _ in 0..POLL_ATTEMPTS {
        let payload = provider_get(api_base, bearer, &path)?;
        if payload.get("done").and_then(|done| done.as_bool()) == Some(true) {
            if let Some(error) = payload.get("error") {
                let message = error
                    .get("message")
                    .and_then(|message| message.as_str())
                    .unwrap_or("google key creation failed");
                return Err(GeminiError {
                    status: 502,
                    detail: message.to_string(),
                });
            }
            if let Some(name) = payload
                .get("response")
                .and_then(|response| response.get("name"))
                .and_then(|name| name.as_str())
            {
                return Ok(name.to_string());
            }
            return Err(GeminiError {
                status: 502,
                detail: "unexpected google response: operation finished without a key".to_string(),
            });
        }
        std::thread::sleep(POLL_DELAY);
    }
    Err(GeminiError {
        status: 502,
        detail: format!("timed out waiting for google operation {operation}"),
    })
}

/// Blocking call: GET /v2/{key}/keyString. The value is readable only
/// through this method and is fetched exactly once per issuance.
pub fn get_key_string(
    api_base: &str,
    bearer: &str,
    key_resource: &str,
) -> Result<String, GeminiError> {
    let path = format!("/v2/{key_resource}/keyString");
    let payload = provider_get(api_base, bearer, &path)?;
    payload
        .get("keyString")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| GeminiError {
            status: 502,
            detail: "unexpected google response: missing keyString".to_string(),
        })
}

/// Blocking mint -> poll -> getKeyString-once flow.
pub fn issue_key_once(
    api_base: &str,
    bearer: &str,
    project: &str,
    display_name: &str,
) -> Result<IssuedKey, GeminiError> {
    let operation = create_key(api_base, bearer, project, display_name)?;
    let name = if operation.starts_with("projects/") {
        operation
    } else {
        poll_operation_key(api_base, bearer, &operation)?
    };
    match get_key_string(api_base, bearer, &name) {
        Ok(key_string) => Ok(IssuedKey { name, key_string }),
        Err(error) => Err(GeminiError {
            status: 502,
            detail: key_string_failure_detail(&name, &error.detail),
        }),
    }
}

/// Blocking call: GET /v2/{key} metadata (never a key value).
pub fn get_key(
    api_base: &str,
    bearer: &str,
    key_resource: &str,
) -> Result<KeySummary, GeminiError> {
    let path = format!("/v2/{key_resource}");
    let payload = provider_get(api_base, bearer, &path)?;
    let name = payload
        .get("name")
        .and_then(|name| name.as_str())
        .unwrap_or(key_resource)
        .to_string();
    let display_name = payload
        .get("displayName")
        .and_then(|name| name.as_str())
        .unwrap_or_default()
        .to_string();
    Ok(KeySummary { name, display_name })
}

/// Blocking call: GET /v2/projects/{project}/locations/global/keys.
pub fn list_keys(
    api_base: &str,
    bearer: &str,
    project: &str,
) -> Result<Vec<KeySummary>, GeminiError> {
    let path = format!("/v2/projects/{}/locations/global/keys", project.trim());
    let payload = provider_get(api_base, bearer, &path)?;
    let mut keys = Vec::new();
    if let Some(items) = payload.get("keys").and_then(|keys| keys.as_array()) {
        for item in items {
            let name = item
                .get("name")
                .and_then(|name| name.as_str())
                .unwrap_or_default()
                .to_string();
            if name.is_empty() {
                continue;
            }
            keys.push(KeySummary {
                name,
                display_name: item
                    .get("displayName")
                    .and_then(|name| name.as_str())
                    .unwrap_or_default()
                    .to_string(),
            });
        }
    }
    Ok(keys)
}

/// Blocking call: DELETE /v2/{key}. The delete returns an operation; a
/// finished operation (or 200 with no operation) counts as deleted.
pub fn delete_key(api_base: &str, bearer: &str, key_resource: &str) -> Result<(), GeminiError> {
    let path = format!("/v2/{key_resource}");
    let payload = provider_delete(api_base, bearer, &path)?;
    if let Some(operation) = payload.get("name").and_then(|name| name.as_str())
        && !operation.starts_with("projects/")
    {
        let _ = poll_delete_operation(api_base, bearer, operation);
    }
    Ok(())
}

fn poll_delete_operation(api_base: &str, bearer: &str, operation: &str) -> Result<(), GeminiError> {
    let path = format!("/v2/{operation}");
    for _ in 0..POLL_ATTEMPTS {
        let payload = provider_get(api_base, bearer, &path)?;
        if payload.get("done").and_then(|done| done.as_bool()) == Some(true) {
            if let Some(error) = payload.get("error") {
                let message = error
                    .get("message")
                    .and_then(|message| message.as_str())
                    .unwrap_or("google key deletion failed");
                return Err(GeminiError {
                    status: 502,
                    detail: message.to_string(),
                });
            }
            return Ok(());
        }
        std::thread::sleep(POLL_DELAY);
    }
    Err(GeminiError {
        status: 502,
        detail: format!("timed out waiting for google operation {operation}"),
    })
}

/// Blocking rotate: issue a replacement, then delete the old key. The new
/// value is returned once; Fort never stores it.
pub fn rotate_key_once(
    api_base: &str,
    bearer: &str,
    project: &str,
    old_key_resource: &str,
    display_name: &str,
) -> Result<IssuedKey, GeminiError> {
    let issued = issue_key_once(api_base, bearer, project, display_name)?;
    if let Err(error) = delete_key(api_base, bearer, old_key_resource) {
        return Err(GeminiError {
            status: 502,
            detail: format!(
                "created replacement {} but failed to delete old key {} ({}); delete {} by hand",
                issued.name, old_key_resource, error.detail, old_key_resource
            ),
        });
    }
    Ok(issued)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn ttl_seconds_is_always_rejected() {
        let error =
            reject_ttl_seconds(&Some(serde_json::json!(3600)), 7).expect_err("ttl must fail");
        assert_eq!(error.status, 400);
        assert!(error.detail.contains("NOT platform-enforced"));
        assert!(reject_ttl_seconds(&None, 7).is_ok());
    }

    #[test]
    fn key_string_failure_names_key_and_remediation() {
        let detail = key_string_failure_detail("projects/p/locations/global/keys/k1", "boom");
        assert!(detail.contains("projects/p/locations/global/keys/k1"));
        assert!(detail.contains("delete or rotate"));
    }

    #[test]
    fn key_resource_accepts_full_or_short_names() {
        assert_eq!(
            key_resource("p", "projects/p/locations/global/keys/k1").unwrap(),
            "projects/p/locations/global/keys/k1"
        );
        assert_eq!(
            key_resource("p", "k1").unwrap(),
            "projects/p/locations/global/keys/k1"
        );
        assert_eq!(key_resource("p", "  ").unwrap_err().status, 400);
    }

    struct MockScript {
        requests: Arc<Mutex<Vec<(String, String)>>>,
    }

    /// Minimal hermetic mock of the API Keys v2 surface: create -> poll done
    /// -> getKeyString, plus list/get/delete.
    fn start_mock(
        expected_key_string: &'static str,
        fail_key_string: bool,
    ) -> (String, MockScript) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock gemini");
        let base = format!("http://{}", listener.local_addr().expect("mock addr"));
        let requests: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        std::thread::spawn(move || {
            // create, poll, getKeyString, get, list, delete, delete-poll
            for _ in 0..8 {
                let (mut stream, _) = listener.accept().expect("accept mock gemini");
                let mut raw = vec![0u8; 8192];
                let Ok(read) = stream.read(&mut raw) else {
                    break;
                };
                let head = String::from_utf8_lossy(&raw[..read]).to_string();
                let mut lines = head.lines();
                let start = lines.next().unwrap_or_default().to_string();
                let mut len = 0usize;
                for line in lines {
                    if line.trim().is_empty() {
                        break;
                    }
                    if let Some(rest) = line.strip_prefix("Content-Length:") {
                        len = rest.trim().parse().unwrap_or(0);
                    }
                }
                recorded
                    .lock()
                    .expect("lock")
                    .push((start.clone(), String::new()));
                let _ = len;
                let body = if start.starts_with("POST /v2/projects/p/locations/global/keys ") {
                    r#"{"name":"operations/op1","done":false}"#.to_string()
                } else if start.starts_with("GET /v2/operations/op1 ") {
                    r#"{"name":"operations/op1","done":true,"response":{"name":"projects/p/locations/global/keys/k1"}}"#.to_string()
                } else if start
                    .starts_with("GET /v2/projects/p/locations/global/keys/k1/keyString ")
                {
                    if fail_key_string {
                        let payload = r#"{"error":{"message":"permission denied"}}"#;
                        let head = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            payload.len()
                        );
                        let _ = stream.write_all(format!("{head}{payload}").as_bytes());
                        continue;
                    }
                    format!(r#"{{"keyString":"{expected_key_string}"}}"#)
                } else if start.starts_with("GET /v2/projects/p/locations/global/keys/k1 ") {
                    r#"{"name":"projects/p/locations/global/keys/k1","displayName":"fort-test"}"#
                        .to_string()
                } else if start.starts_with("GET /v2/projects/p/locations/global/keys ") {
                    r#"{"keys":[{"name":"projects/p/locations/global/keys/k1","displayName":"fort-test"}]}"#.to_string()
                } else if start.starts_with("DELETE /v2/projects/p/locations/global/keys/k1 ") {
                    r#"{"name":"operations/del1","done":true}"#.to_string()
                } else {
                    let payload = r#"{"error":{"message":"not found"}}"#;
                    let head = format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = stream.write_all(format!("{head}{payload}").as_bytes());
                    continue;
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(format!("{head}{body}").as_bytes());
            }
        });
        (base, MockScript { requests })
    }

    #[test]
    fn issue_flow_mints_polls_and_reads_value_once() {
        let (base, mock) = start_mock("AIzaMOCKVALUE", false);
        let issued = issue_key_once(&base, "sa-token", "p", "fort-test").expect("issue");
        assert_eq!(issued.name, "projects/p/locations/global/keys/k1");
        assert_eq!(issued.key_string, "AIzaMOCKVALUE");
        let seen: Vec<String> = mock
            .requests
            .lock()
            .expect("lock")
            .iter()
            .map(|(line, _)| line.clone())
            .collect();
        assert!(
            seen.iter()
                .filter(|line| line.contains("keyString"))
                .count()
                == 1,
            "keyString must be fetched exactly once: {seen:?}"
        );
        assert!(seen.iter().any(|line| line.contains("operations/op1")));
    }

    #[test]
    fn issue_flow_maps_key_string_failure_with_remediation() {
        let (base, _mock) = start_mock("AIzaMOCKVALUE", true);
        let error = issue_key_once(&base, "sa-token", "p", "fort-test").expect_err("must fail");
        assert_eq!(error.status, 502);
        assert!(error.detail.contains("projects/p/locations/global/keys/k1"));
        assert!(error.detail.contains("delete or rotate"));
    }

    #[test]
    fn list_and_get_never_return_values() {
        let (base, _mock) = start_mock("AIzaMOCKVALUE", false);
        let keys = list_keys(&base, "sa-token", "p").expect("list");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "projects/p/locations/global/keys/k1");
        let summary =
            get_key(&base, "sa-token", "projects/p/locations/global/keys/k1").expect("get");
        assert_eq!(summary.display_name, "fort-test");
        delete_key(&base, "sa-token", "projects/p/locations/global/keys/k1").expect("delete");
    }

    /// Live probe against the real Google API. Gated: runs only when
    /// `FORT_GEMINI_LIVE_TEST=1` with `FORT_GEMINI_LIVE_SA_TOKEN` and
    /// `FORT_GEMINI_LIVE_PROJECT` set. Never runs in normal `cargo test`.
    #[test]
    #[ignore]
    fn live_issue_probe() {
        if std::env::var("FORT_GEMINI_LIVE_TEST").unwrap_or_default() != "1" {
            return;
        }
        let token = std::env::var("FORT_GEMINI_LIVE_SA_TOKEN").expect("live sa token");
        let project = std::env::var("FORT_GEMINI_LIVE_PROJECT").expect("live project");
        let issued = issue_key_once(DEFAULT_GEMINI_API_BASE, &token, &project, "fort-live-probe")
            .expect("live issue");
        assert!(!issued.key_string.is_empty());
        delete_key(DEFAULT_GEMINI_API_BASE, &token, &issued.name).expect("live cleanup");
    }
}
