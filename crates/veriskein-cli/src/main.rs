use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use veriskein_ipc::{
    HelloFrame, IpcFrame, Topic, decode_ndjson_frame, default_socket_path, encode_ndjson_frame,
    validate_versions,
};

const CLIENT_NAME: &str = "veriskein-cli";

#[derive(Debug, Parser)]
#[command(name = "veriskein-cli")]
#[command(about = "Veriskein operator CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Tail {
        #[arg(long)]
        ipc: bool,
        #[arg(long = "ipc-sock", value_name = "PATH")]
        ipc_sock: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Tail { ipc, ipc_sock } => {
            if !ipc {
                bail!("tail currently supports only --ipc");
            }
            tail_ipc(ipc_sock.unwrap_or_else(default_socket_path)).await?;
        }
    }
    Ok(())
}

async fn tail_ipc(path: PathBuf) -> Result<()> {
    let stream = UnixStream::connect(&path)
        .await
        .with_context(|| format!("connect IPC socket {}", path.display()))?;
    let mut reader = BufReader::new(stream);
    let mut hello = HelloFrame::new(CLIENT_NAME);
    hello.subscriptions = vec![Topic::Alert, Topic::Metrics];
    let line = encode_ndjson_frame(&IpcFrame::Hello(hello)).context("encode IPC hello")?;
    reader
        .get_mut()
        .write_all(line.as_bytes())
        .await
        .context("write IPC hello")?;

    let mut welcome = String::new();
    reader
        .read_line(&mut welcome)
        .await
        .context("read IPC welcome")?;
    match decode_ndjson_frame(&welcome).context("decode IPC welcome")? {
        IpcFrame::Welcome(frame) => {
            validate_versions(frame.ipc_version, frame.schema_version)
                .context("validate IPC welcome")?;
        }
        IpcFrame::Error(frame) => bail!("IPC server error: {:?}: {}", frame.code, frame.message),
        frame => bail!("expected IPC welcome, received {:?}", frame.topic()),
    }

    let mut stdout = tokio::io::stdout();
    loop {
        let mut line = String::new();
        if reader
            .read_line(&mut line)
            .await
            .context("read IPC frame")?
            == 0
        {
            return Ok(());
        }
        match decode_ndjson_frame(&line).context("decode IPC frame")? {
            IpcFrame::Alert(frame) => {
                let mut alert_line =
                    serde_json::to_string(&frame.alert).context("serialize alert payload")?;
                alert_line.push('\n');
                stdout
                    .write_all(alert_line.as_bytes())
                    .await
                    .context("write alert")?;
            }
            IpcFrame::Metrics(_) => {}
            IpcFrame::Error(frame) => {
                bail!("IPC server error: {:?}: {}", frame.code, frame.message)
            }
            _ => {}
        }
    }
}
