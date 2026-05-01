use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;

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
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Assert { expect, actual } => {
            let expectations: Vec<veriskein_test::Expectation> = std::fs::read_to_string(expect)?
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<std::result::Result<_, _>>()?;
            let actual_values: Vec<Value> = std::fs::read_to_string(actual)?
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<std::result::Result<_, _>>()?;
            veriskein_test::assert_expectations(&expectations, &actual_values)?;
        }
    }
    Ok(())
}
