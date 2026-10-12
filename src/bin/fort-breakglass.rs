use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use fort::auth::{BREAKGLASS_ADMIN_AGENT_ID, Manager};
use fort::store::Store;

#[derive(Debug, Parser)]
#[command(
    name = "fort-breakglass",
    about = "Mint an emergency break-glass admin token from local state",
    long_about = "Direct-to-state recovery tool for operators locked out of the API: issues a short-lived admin token using the Fort state file and JWT signing key on disk. Requires local access to both files; reissue revokes prior break-glass tokens."
)]
struct Cli {
    #[arg(long, help = "Fort state file (fort-state.json)")]
    state_path: PathBuf,
    #[arg(long, help = "0600 file holding the JWT signing key")]
    signing_key_file: PathBuf,
    #[arg(long, default_value = BREAKGLASS_ADMIN_AGENT_ID, help = "Agent id to mint the token for")]
    agent: String,
    #[arg(long, default_value_t = 900, help = "Token lifetime in seconds")]
    ttl_secs: u64,
}

fn main() {
    fort::sigpipe::restore_default();
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let state_path = cli.state_path.display().to_string();
    let signing_key_file = cli.signing_key_file.display().to_string();
    let signing_key = fort::config::read_secret_file(&signing_key_file)?;
    let signing_key = signing_key.as_bytes().to_vec();
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
