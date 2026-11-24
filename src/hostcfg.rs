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
    vec![PathBuf::from(format!(
        "{}/.fort/settings.toml",
        home.trim()
    ))]
}

fn parse_host_from_file(path: &PathBuf) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    let parsed: toml::Value = toml::from_str(&raw).ok()?;
    let fort = parsed.get("fort")?;
    fort.get("host")
        .or_else(|| fort.get("host_url"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::parse_host_from_file;
    use std::io::Write;
    use std::path::PathBuf;

    fn write_settings(name: &str, contents: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fort-hostcfg-test-{}-{}.toml",
            std::process::id(),
            name
        ));
        let mut file = std::fs::File::create(&path).expect("create temp settings");
        file.write_all(contents.as_bytes())
            .expect("write temp settings");
        path
    }

    #[test]
    fn parses_table_host_from_settings_document() {
        // Regression test for fort#38: `[fort] host = ...` is a TOML document,
        // not a bare value, and must resolve without --host/FORT_HOST.
        let path = write_settings("host", "[fort]\nhost = \"https://fort.aureuma.ai\"\n");
        let host = parse_host_from_file(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(host.as_deref(), Some("https://fort.aureuma.ai"));
    }

    #[test]
    fn falls_back_to_host_url_key() {
        let path = write_settings(
            "host-url",
            "[fort]\nhost_url = \"https://example.invalid\"\n",
        );
        let host = parse_host_from_file(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(host.as_deref(), Some("https://example.invalid"));
    }

    #[test]
    fn returns_none_without_fort_host() {
        let path = write_settings("no-host", "[fort]\naddr = \":8088\"\n");
        let host = parse_host_from_file(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(host, None);
    }
}
