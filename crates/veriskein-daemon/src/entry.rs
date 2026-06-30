use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::error;

use crate::driver::run;
use crate::preflight::PreflightError;

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
    #[arg(long = "ringbuf-size", value_name = "BYTES")]
    pub ringbuf_size: Option<usize>,
    #[arg(long = "ipc-sock", value_name = "PATH")]
    pub ipc_sock: Option<PathBuf>,
    #[arg(long = "no-ipc")]
    pub no_ipc: bool,
    /// Skip OpenSSL TLS uprobe attachment. Used to measure the syscall-only
    /// capture path independently of TLS plaintext interception.
    #[arg(long = "disable-tls")]
    pub disable_tls: bool,
    /// Force stdio/MCP content capture on regardless of config. Used to measure
    /// the fully enabled capture path.
    #[arg(long = "enable-content-capture")]
    pub enable_content_capture: bool,
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
            // Preflight failures are operational guidance, not crash reports, so
            // they get a deterministic exit code for scenario harnesses.
            error!("{preflight}");
            std::process::exit(preflight.exit_code());
        }
        return Err(err);
    }
    Ok(())
}
