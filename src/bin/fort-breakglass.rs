use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use fort::auth::{BREAKGLASS_ADMIN_AGENT_ID, Manager};
use fort::store::Store;

#[derive(Debug, Parser)]
#[command(name = "fort-breakglass")]
struct Cli {
    #[arg(long)]
    state_path: PathBuf,
    #[arg(long)]
    signing_key_file: PathBuf,
    #[arg(long, default_value = BREAKGLASS_ADMIN_AGENT_ID)]
    agent: String,
    #[arg(long, default_value_t = 900)]
    ttl_secs: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let state_path = cli.state_path.display().to_string();
    let signing_key = fs::read_to_string(&cli.signing_key_file)
        .with_context(|| format!("read signing key {}", cli.signing_key_file.display()))?;
    let signing_key = signing_key.trim().as_bytes().to_vec();
    let store =
        Arc::new(Store::new(&state_path).with_context(|| format!("open state {state_path}"))?);
    let agent = store
        .get_agent(&cli.agent)
        .with_context(|| format!("load agent {}", cli.agent.trim()))?;
    let manager = Manager {
        signing_key,
        issuer: None,
        store,
    };
    let (token, _) = manager
        .issue(&agent, Duration::from_secs(cli.ttl_secs), "fort-api")
        .context("issue breakglass token")?;
    println!("{token}");
    Ok(())
}
