use std::io::Write;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;
use tracing::info;
use veriskein_alert::{emit_ndjson_line, validate};
use veriskein_bpf::ProcExecSource;
use veriskein_collector::CollectorCore;

use crate::Cli;
use crate::enrich::enrich_event_from_procfs;
use crate::output::{event_to_alert, open_sink};
use crate::preflight::preflight;

pub async fn run(cli: Cli) -> Result<()> {
    preflight(&cli)?;
    let workspace = cli
        .workspaces
        .first()
        .context("workspace should be present after preflight")?
        .display()
        .to_string();

    let source = ProcExecSource::start().context("start proc exec source")?;
    let sink = open_sink(cli.alert_output.as_deref()).context("open alert sink")?;
    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // Keep the hot path in a dedicated task so shutdown stays simple: signal
    // handling only has to notify the driver and wait for a clean flush.
    let driver = tokio::spawn(async move {
        run_with_source_and_sink(source, sink, &workspace, shutdown_rx).await
    });
    tokio::select! {
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
        }
    }
    let _ = shutdown_tx.send(());
    driver.await.context("join daemon driver task")??;
    Ok(())
}

pub trait EventSource {
    fn try_recv(&self) -> Result<Option<Vec<u8>>>;
    fn shutdown(&mut self) -> Result<()>;
}

impl EventSource for ProcExecSource {
    fn try_recv(&self) -> Result<Option<Vec<u8>>> {
        ProcExecSource::try_recv(self)
    }

    fn shutdown(&mut self) -> Result<()> {
        ProcExecSource::shutdown(self)
    }
}

pub async fn run_with_source_and_sink<S>(
    mut source: S,
    mut sink: Box<dyn Write + Send>,
    workspace: &str,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<()>
where
    S: EventSource + Send + 'static,
{
    let mut collector = CollectorCore::new();
    info!("veriskein Phase 0 dry-run started");
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                while let Some(raw) = source.try_recv()? {
                    let events = collector.process_bytes(&raw).context("process raw BPF event")?;
                    for mut collected in events {
                        // The BPF side emits the thinnest viable exec payload; user space can
                        // opportunistically improve fidelity from /proc without changing the wire ABI.
                        enrich_event_from_procfs(&mut collected.event);
                        if let Some(alert) = event_to_alert(&collected.event, collected.ingest_seq, workspace)? {
                            let value = alert.as_value()?;
                            validate(&value).context("validate alert against schema")?;
                            emit_ndjson_line(&mut sink, &value)?;
                        }
                    }
                }
            }
        }
    }
    source.shutdown().context("stop event source")?;
    sink.flush().context("flush alert sink")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::Value;
    use tempfile::NamedTempFile;
    use tokio::sync::oneshot;
    use veriskein_proto::build_exec_event_bytes;

    use super::{EventSource, Result, run_with_source_and_sink};
    use crate::output::open_sink;

    struct FakeSource {
        events: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    impl FakeSource {
        fn new(events: Vec<Vec<u8>>) -> Self {
            Self {
                events: Arc::new(Mutex::new(events.into())),
            }
        }
    }

    impl EventSource for FakeSource {
        fn try_recv(&self) -> Result<Option<Vec<u8>>> {
            Ok(self.events.lock().expect("fake source lock").pop_front())
        }

        fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn driver_emits_schema_valid_ndjson_from_exec_bytes() {
        let source = FakeSource::new(vec![build_exec_event_bytes(
            0,
            1,
            4242,
            "bash",
            "/bin/bash",
            &["bash", "-lc", "true"],
        )]);
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_path_buf();
        let sink = open_sink(Some(&path)).expect("open sink");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            run_with_source_and_sink(source, sink, "/tmp/ws", shutdown_rx).await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = shutdown_tx.send(());
        handle.await.expect("join").expect("driver ok");

        let text = std::fs::read_to_string(path).expect("read output");
        let line = text.lines().next().expect("one alert line");
        let value: Value = serde_json::from_str(line).expect("json line");
        veriskein_alert::validate(&value).expect("schema valid");
        assert_eq!(value["type"], "exec_observed");
        assert_eq!(value["process"]["binary"], "/bin/bash");
        assert_eq!(value["objects"]["argv"][0], "bash");
    }
}
