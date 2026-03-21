use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "fortd")]
struct FortdCli {}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let _ = FortdCli::parse();
    let config = fort::config::Config::from_env()?;
    let store = Arc::new(fort::store::Store::new(&config.state_path)?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(fort::server::run(config, store))
}
