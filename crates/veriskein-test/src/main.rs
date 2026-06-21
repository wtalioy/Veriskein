use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod assert_cmd;
mod replay;

#[derive(Debug, Parser)]
#[command(name = "veriskein-test")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Assert {
        #[arg(long)]
        expect: PathBuf,
        #[arg(long)]
        actual: PathBuf,
        #[arg(long)]
        timeout: Option<String>,
    },
    Replay {
        #[arg(long)]
        fixture: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long = "config-root", default_value = ".")]
        config_root: PathBuf,
        #[arg(long = "workspace")]
        workspaces: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Assert {
            expect,
            actual,
            timeout,
        } => assert_cmd::assert_files(&expect, &actual, timeout.as_deref())?,
        Command::Replay {
            fixture,
            output,
            config_root,
            workspaces,
        } => replay::replay_fixture(&fixture, &output, &config_root, &workspaces)?,
    }
    Ok(())
}
