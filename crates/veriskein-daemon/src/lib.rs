//! Phase 1 daemon entrypoint and runtime orchestration.

mod driver;
mod enrich;
mod output;
mod preflight;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::error;

pub use driver::run;
pub use preflight::{PreflightError, check_btf_path, check_kernel_release, preflight};

#[derive(Debug, Clone, Parser)]
#[command(name = "veriskein-daemon")]
#[command(about = "Veriskein daemon")]
pub struct Cli {
    #[arg(long = "workspace", value_name = "PATH")]
    pub workspaces: Vec<PathBuf>,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long = "alert-output", value_name = "PATH")]
    pub alert_output: Option<PathBuf>,
}

pub fn install_tracing() {
    let filter = std::env::var("VERISKEIN_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

pub async fn main_entry() -> Result<()> {
    install_tracing();
    let cli = Cli::parse();
    if let Err(err) = run(cli).await {
        if let Some(preflight) = err.downcast_ref::<PreflightError>() {
            error!("{preflight}");
            std::process::exit(preflight.exit_code());
        }
        return Err(err);
    }
    Ok(())
}
