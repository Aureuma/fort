use std::env;
use std::fs;
use std::path::PathBuf;

pub fn host_from_settings() -> String {
    for path in settings_paths() {
        if let Some(host) = parse_host_from_file(&path) {
            return host;
        }
    }
    String::new()
}

fn settings_paths() -> Vec<PathBuf> {
    let explicit = env::var("FORT_SETTINGS_FILE").unwrap_or_default();
    if !explicit.trim().is_empty() {
        return vec![PathBuf::from(explicit.trim())];
    }
    let home = env::var("HOME").unwrap_or_default();
    if home.trim().is_empty() {
        return Vec::new();
    }
    vec![
        PathBuf::from(format!("{}/.si/fort/settings.toml", home.trim())),
        PathBuf::from(format!("{}/.si/settings.toml", home.trim())),
    ]
}

fn parse_host_from_file(path: &PathBuf) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    let parsed = raw.parse::<toml::Value>().ok()?;
    let fort = parsed.get("fort")?;
    fort.get("host")
        .or_else(|| fort.get("host_url"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
