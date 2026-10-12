use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "fortd",
    about = "Run the Fort policy/authentication API server",
    long_about = "Serve the Fort v1 API: bearer-token auth, repo/env/op policy checks, and Vault-backed secret operations. Configuration comes from --config-file or the environment."
)]
struct FortdCli {
    #[arg(
        long,
        help = "TOML config file (else read configuration from the environment)"
    )]
    config_file: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = FortdCli::parse();
    let config = match cli.config_file.as_deref() {
        Some(path) => fort::config::Config::from_file(path)?,
        None => fort::config::Config::from_env()?,
    };
    let store = Arc::new(fort::store::Store::new(&config.state_path)?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(fort::server::run(config, store))
}
