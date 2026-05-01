use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;
use tracing::info;
use veriskein_alert::{AlertRecord, emit_ndjson_line, validate};
use veriskein_bpf::RuntimeEventSource;
use veriskein_collector::CollectorCore;
use veriskein_detectors::detect;
use veriskein_graph::{AgentConfig, GraphState};
use veriskein_normalizer::{Normalizer, SensitiveConfig, load_workspaces};

use crate::Cli;
use crate::enrich::enrich_event_from_procfs;
use crate::output::open_sink;
use crate::preflight::preflight;

pub async fn run(cli: Cli) -> Result<()> {
    preflight(&cli)?;
    let source = RuntimeEventSource::start().context("start BPF event source")?;
    let sink = open_sink(cli.alert_output.as_deref()).context("open alert sink")?;
    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let config_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .context("repo root")?
        .to_path_buf();

    let driver_cli = cli.clone();
    let driver = tokio::spawn(async move {
        run_with_source_and_sink(source, sink, driver_cli, &config_root, shutdown_rx).await
    });

    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM, shutting down"),
    }
    let _ = shutdown_tx.send(());
    driver.await.context("join daemon driver task")??;
    Ok(())
}

pub trait EventSource {
    fn try_recv(&self) -> Result<Option<Vec<u8>>>;
    fn shutdown(&mut self) -> Result<()>;
}

impl EventSource for RuntimeEventSource {
    fn try_recv(&self) -> Result<Option<Vec<u8>>> {
        RuntimeEventSource::try_recv(self)
    }

    fn shutdown(&mut self) -> Result<()> {
        RuntimeEventSource::shutdown(self)
    }
}

pub async fn run_with_source_and_sink<S>(
    mut source: S,
    mut sink: Box<dyn Write + Send>,
    cli: Cli,
    config_root: &Path,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<()>
where
    S: EventSource + Send + 'static,
{
    let mut collector = CollectorCore::new();
    let sensitive = SensitiveConfig::load(&config_root.join("config/sensitive.toml"))?;
    let agent_config = AgentConfig::load(&config_root.join("config/agents.toml"))?;
    let mut workspace_inputs = cli.workspaces.clone();
    if workspace_inputs.is_empty() && !agent_config.default_workspace.is_empty() {
        workspace_inputs.push(agent_config.default_workspace.clone().into());
    }
    let workspaces = load_workspaces(&workspace_inputs)?;
    let mut normalizer = Normalizer::new(sensitive, workspaces);
    let mut graph = GraphState::new(agent_config, normalizer.workspaces().to_vec())?;

    info!("veriskein runtime started");
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                while let Some(raw) = source.try_recv()? {
                    let events = collector.process_bytes(&raw).context("process raw BPF event")?;
                    for mut collected in events {
                        enrich_event_from_procfs(&mut collected.event);
                        for normalized in normalizer.apply(collected.ingest_seq, &collected.event) {
                            graph.apply(&normalized);
                            for finding in detect(&normalized, &graph, cli.dry_run) {
                                let alert = AlertRecord::from_finding(&finding);
                                let value = alert.as_value()?;
                                validate(&value).context("validate alert against schema")?;
                                emit_ndjson_line(&mut sink, &value)?;
                            }
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
    use veriskein_proto::{
        build_exec_event_bytes, build_file_open_event_bytes, build_file_unlink_event_bytes,
        build_proc_fork_event_bytes,
    };

    use super::{EventSource, Result, run_with_source_and_sink};
    use crate::Cli;
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

    fn config_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("repo root")
            .to_path_buf()
    }

    #[tokio::test]
    async fn driver_emits_schema_valid_exec_observed_alert() {
        let source = FakeSource::new(vec![build_exec_event_bytes(
            0,
            1,
            4242,
            4242,
            1,
            "claude",
            "/usr/bin/claude",
            &["claude"],
        )]);
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_path_buf();
        let sink = open_sink(Some(&path)).expect("open sink");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            run_with_source_and_sink(
                source,
                sink,
                Cli {
                    workspaces: vec!["/tmp/ws".into()],
                    dry_run: true,
                    alert_output: None,
                },
                &config_root(),
                shutdown_rx,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = shutdown_tx.send(());
        handle.await.expect("join").expect("driver ok");

        let text = std::fs::read_to_string(path).expect("read output");
        let line = text.lines().next().expect("one alert line");
        let value: Value = serde_json::from_str(line).expect("json line");
        veriskein_alert::validate(&value).expect("schema valid");
        assert_eq!(value["type"], "exec_observed");
        assert_eq!(value["objects"]["argv"][0], "claude");
    }

    #[tokio::test]
    async fn driver_emits_unexpected_shell_alert() {
        let source = FakeSource::new(vec![
            build_exec_event_bytes(0, 1, 100, 100, 1, "claude", "/usr/bin/claude", &["claude"]),
            build_proc_fork_event_bytes(0, 2, 100, 100, 1, "claude", 101, 101),
            build_exec_event_bytes(0, 3, 101, 101, 100, "sh", "/bin/sh", &["sh", "-lc", "echo"]),
        ]);
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_path_buf();
        let sink = open_sink(Some(&path)).expect("open sink");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            run_with_source_and_sink(
                source,
                sink,
                Cli {
                    workspaces: vec!["/tmp/ws".into()],
                    dry_run: false,
                    alert_output: None,
                },
                &config_root(),
                shutdown_rx,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = shutdown_tx.send(());
        handle.await.expect("join").expect("driver ok");

        let text = std::fs::read_to_string(path).expect("read output");
        assert!(text.lines().any(|line| {
            serde_json::from_str::<Value>(line)
                .map(|value| value["type"] == "unexpected_shell")
                .unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn driver_emits_sensitive_and_outside_workspace_alerts() {
        let source = FakeSource::new(vec![
            build_exec_event_bytes(0, 1, 100, 100, 1, "claude", "/usr/bin/claude", &["claude"]),
            build_file_open_event_bytes(0, 2, 100, 100, 1, "claude", -100, 3, "/etc/shadow"),
            build_file_unlink_event_bytes(0, 3, 100, 100, 1, "claude", -100, 0, "/tmp/outside.txt"),
        ]);
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_path_buf();
        let sink = open_sink(Some(&path)).expect("open sink");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            run_with_source_and_sink(
                source,
                sink,
                Cli {
                    workspaces: vec!["/tmp/ws".into()],
                    dry_run: false,
                    alert_output: None,
                },
                &config_root(),
                shutdown_rx,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = shutdown_tx.send(());
        handle.await.expect("join").expect("driver ok");

        let text = std::fs::read_to_string(path).expect("read output");
        let kinds: Vec<String> = text
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter_map(|value| value["type"].as_str().map(ToOwned::to_owned))
            .collect();
        assert!(kinds.contains(&"sensitive_file_access".to_string()));
        assert!(kinds.contains(&"out_of_workspace_deletion".to_string()));
    }
}
