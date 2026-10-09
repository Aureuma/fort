use std::env;
use std::time::Duration;

use clap::Parser;

#[derive(Parser)]
#[command(name = "fort-agent")]
struct Cli {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    refresh_token_file: Option<String>,
    #[arg(long, default_value = "/run/fort/access.token")]
    token_path: String,
    #[arg(long, default_value_t = 0.70)]
    refresh_ratio: f64,
    #[arg(long, default_value = "10s")]
    jitter: String,
    #[arg(long, default_value = "5s")]
    min_sleep: String,
    #[arg(long, default_value = "30s")]
    max_backoff: String,
    #[arg(long, default_value = "10s")]
    http_timeout: String,
    #[arg(long, default_value_t = false)]
    once: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let host = cli
        .host
        .or_else(|| env::var("FORT_HOST").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(fort::hostcfg::host_from_settings);
    if host.trim().is_empty() {
        anyhow::bail!(
            "fort host is required (set FORT_HOST or ~/.fort/settings.toml [fort].host)"
        );
    }
    let refresh_token_file = cli
        .refresh_token_file
        .or_else(|| env::var("FORT_REFRESH_TOKEN_FILE").ok())
        .unwrap_or_default();
    let runtime = fort::runtime_agent::Runtime::new(fort::runtime_agent::Config {
        host,
        refresh_token_file,
        token_path: cli.token_path,
        refresh_ratio: cli.refresh_ratio,
        jitter: parse_duration(&cli.jitter)?,
        min_sleep: parse_duration(&cli.min_sleep)?,
        max_backoff: parse_duration(&cli.max_backoff)?,
        http_timeout: parse_duration(&cli.http_timeout)?,
        once: cli.once,
    })?;
    runtime.run()
}

fn parse_duration(raw: &str) -> anyhow::Result<Duration> {
    if let Ok(seconds) = raw.trim().parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }
    let mut number = String::new();
    let mut total = Duration::from_secs(0);
    for ch in raw.trim().chars() {
        if ch.is_ascii_digit() {
            number.push(ch);
            continue;
        }
        let value = number.parse::<u64>()?;
        number.clear();
        total += match ch {
            's' => Duration::from_secs(value),
            'm' => Duration::from_secs(value * 60),
            'h' => Duration::from_secs(value * 60 * 60),
            'd' => Duration::from_secs(value * 60 * 60 * 24),
            _ => anyhow::bail!("invalid duration {}", raw),
        };
    }
    if !number.is_empty() {
        anyhow::bail!("invalid duration {}", raw);
    }
    Ok(total)
}
