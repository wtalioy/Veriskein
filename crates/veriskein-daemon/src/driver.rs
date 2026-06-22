use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::signal::unix::{Signal, SignalKind, signal};
#[cfg(test)]
use tokio::sync::oneshot::{self, error::TryRecvError};
use tracing::info;
use veriskein_bpf::{BpfRuntimeConfig, RuntimeEventSource};

use crate::Cli;
use crate::metrics::MetricsTick;
use crate::output::open_sink;
use crate::pipeline::RuntimePipeline;
use crate::preflight::preflight;

pub async fn run(cli: Cli) -> Result<()> {
    preflight(&cli)?;
    let config_root = resolve_config_root()?;
    let bpf_config = load_bpf_runtime_config(&config_root)?;
    let source =
        RuntimeEventSource::start_with_config(bpf_config).context("start BPF event source")?;
    let sink = open_sink(cli.alert_output.as_deref()).context("open alert sink")?;
    let sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;

    run_with_source_and_sink(source, sink, cli, &config_root, Shutdown::Signal(sigterm)).await
}

pub(crate) fn resolve_config_root() -> Result<std::path::PathBuf> {
    if let Some(root) = std::env::var_os("VERISKEIN_CONFIG_ROOT") {
        return Ok(root.into());
    }
    // Tests and scenario harnesses override the config root so the daemon can
    // run against per-run config snapshots instead of mutating the repo copy.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .context("repo root")
        .map(|path| path.to_path_buf())
}

#[derive(Debug, Default, Deserialize)]
struct DefaultsConfig {
    #[serde(default)]
    tls: TlsConfig,
}

#[derive(Debug, Default, Deserialize)]
struct TlsConfig {
    #[serde(default)]
    openssl: OpensslConfig,
}

#[derive(Debug, Default, Deserialize)]
struct OpensslConfig {
    #[serde(default)]
    library_paths: Vec<std::path::PathBuf>,
    #[serde(default)]
    soname_allowlist: Vec<String>,
}

fn load_bpf_runtime_config(config_root: &Path) -> Result<BpfRuntimeConfig> {
    let path = config_root.join("config/defaults.toml");
    if !path.exists() {
        return Ok(BpfRuntimeConfig::default());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read defaults config {}", path.display()))?;
    let defaults: DefaultsConfig = toml::from_str(&text)
        .with_context(|| format!("parse defaults config {}", path.display()))?;
    let mut config = BpfRuntimeConfig {
        openssl_library_paths: defaults.tls.openssl.library_paths,
        openssl_soname_allowlist: defaults.tls.openssl.soname_allowlist,
    };
    if config.openssl_soname_allowlist.is_empty() {
        config.openssl_soname_allowlist = BpfRuntimeConfig::default().openssl_soname_allowlist;
    }
    Ok(config)
}

trait EventSource {
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>>;
    fn shutdown(&mut self) -> Result<()>;
}

impl EventSource for RuntimeEventSource {
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
        RuntimeEventSource::try_recv(self)
    }

    fn shutdown(&mut self) -> Result<()> {
        RuntimeEventSource::shutdown(self)
    }
}

enum Shutdown {
    Signal(Signal),
    #[cfg(test)]
    Oneshot(oneshot::Receiver<()>),
}

impl Shutdown {
    async fn recv(&mut self) {
        match self {
            Self::Signal(signal) => {
                let _ = signal.recv().await;
                info!("received SIGTERM, shutting down");
            }
            #[cfg(test)]
            Self::Oneshot(receiver) => {
                let _ = receiver.await;
            }
        }
    }

    fn requested(&mut self) -> bool {
        match self {
            Self::Signal(_) => false,
            #[cfg(test)]
            Self::Oneshot(receiver) => shutdown_requested(receiver),
        }
    }
}

async fn run_with_source_and_sink<S>(
    mut source: S,
    mut sink: Box<dyn Write + Send>,
    cli: Cli,
    config_root: &Path,
    mut shutdown: Shutdown,
) -> Result<()>
where
    S: EventSource + Send + 'static,
{
    let mut pipeline = RuntimePipeline::new(config_root, &cli.workspaces)?;
    let mut metrics = MetricsTick::new();

    info!("veriskein runtime started");
    info!("using config root {}", config_root.display());
    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if shutdown.requested() {
                    break;
                }
                // RuntimeEventSource is a non-blocking poll surface. Drain
                // everything currently buffered before sleeping again so graph
                // state and detector ordering stay aligned with ingest order.
                loop {
                    match source.try_recv() {
                        Ok(Some(raw)) => {
                            let emitted =
                                pipeline.process_raw_event_bytes(&raw, &mut *sink, cli.dry_run)?;
                            metrics.add_detector_fires(emitted);
                        }
                        Ok(None) => break,
                        Err(err) => return Err(err),
                    }
                }
                metrics.maybe_log(pipeline.collector_counters());
                pipeline.maybe_refresh_endpoint_ips();
            }
        }
    }
    source.shutdown().context("stop event source")?;
    sink.flush().context("flush alert sink")?;
    Ok(())
}

#[cfg(test)]
fn shutdown_requested(shutdown_rx: &mut oneshot::Receiver<()>) -> bool {
    match shutdown_rx.try_recv() {
        Ok(()) | Err(TryRecvError::Closed) => true,
        Err(TryRecvError::Empty) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::Value;
    use tempfile::NamedTempFile;
    use tokio::sync::oneshot;
    use veriskein_proto::{ContentChannel, ContentDirection, EventFixture};

    use super::{EventSource, Result, Shutdown, run_with_source_and_sink};
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
        fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
            Ok(self.events.lock().expect("fake source lock").pop_front())
        }

        fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    fn config_root() -> std::path::PathBuf {
        super::resolve_config_root().expect("repo root")
    }

    const TEST_ROOT_PID: u32 = 900_100;
    const TEST_CHILD_PID: u32 = 900_101;

    fn seeded_exec_bytes() -> Vec<u8> {
        EventFixture::for_pid(1, TEST_ROOT_PID, 1, "claude").exec("/usr/bin/claude", &["claude"])
    }

    async fn drive_alerts(events: Vec<Vec<u8>>, dry_run: bool) -> Vec<Value> {
        let file = NamedTempFile::new().expect("temp file");
        let path: PathBuf = file.path().to_path_buf();
        let source = FakeSource::new(events);
        let sink = open_sink(Some(&path)).expect("open sink");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // The driver loop owns its own pacing, so tests let it run briefly and
        // then trigger shutdown rather than trying to synchronize each poll.
        let handle = tokio::spawn(async move {
            run_with_source_and_sink(
                source,
                sink,
                Cli {
                    workspaces: vec!["/tmp/ws".into()],
                    dry_run,
                    alert_output: None,
                },
                &config_root(),
                Shutdown::Oneshot(shutdown_rx),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(350)).await;
        let _ = shutdown_tx.send(());
        handle.await.expect("join").expect("driver ok");

        std::fs::read_to_string(path)
            .expect("read output")
            .lines()
            .map(|line| {
                let value: Value = serde_json::from_str(line).expect("json line");
                veriskein_alert::validate(&value).expect("schema valid");
                value
            })
            .collect()
    }

    #[tokio::test]
    async fn driver_emits_schema_valid_exec_observed_alert() {
        let values = drive_alerts(vec![seeded_exec_bytes()], true).await;
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["type"], "exec_observed");
        assert_eq!(values[0]["objects"]["argv"][0], "claude");
    }

    #[tokio::test]
    async fn driver_emits_unexpected_shell_alert() {
        let values = drive_alerts(
            vec![
                seeded_exec_bytes(),
                EventFixture::for_pid(2, TEST_ROOT_PID, 1, "claude")
                    .fork(TEST_CHILD_PID, TEST_CHILD_PID),
                EventFixture::for_pid(3, TEST_CHILD_PID, TEST_ROOT_PID, "sh")
                    .exec("/bin/sh", &["sh", "-lc", "echo"]),
            ],
            false,
        )
        .await;
        assert!(
            values
                .iter()
                .any(|value| value["type"] == "unexpected_shell")
        );
    }

    #[tokio::test]
    async fn driver_emits_sensitive_and_outside_workspace_alerts() {
        let values = drive_alerts(
            vec![
                seeded_exec_bytes(),
                EventFixture::for_pid(2, TEST_ROOT_PID, 1, "claude").open(-100, 3, "/etc/shadow"),
                EventFixture::for_pid(3, TEST_ROOT_PID, 1, "claude").unlink(
                    -100,
                    0,
                    "/tmp/outside.txt",
                ),
            ],
            false,
        )
        .await;
        let kinds: Vec<String> = values
            .iter()
            .filter_map(|value| value["type"].as_str().map(ToOwned::to_owned))
            .collect();
        assert!(kinds.contains(&"sensitive_file_access".to_string()));
        assert!(kinds.contains(&"out_of_workspace_deletion".to_string()));
    }

    #[tokio::test]
    async fn driver_links_tls_prompt_to_later_risky_event() {
        let prompt = br#"{"prompt":"please inspect /etc/shadow"}"#;
        let values = drive_alerts(
            vec![
                seeded_exec_bytes(),
                EventFixture::for_pid(2, TEST_ROOT_PID, 1, "claude").connect(3, 443, true),
                EventFixture::for_pid(3, TEST_ROOT_PID, 1, "claude").tls_assoc(
                    0xabc,
                    3,
                    ContentDirection::Write,
                    1,
                ),
                EventFixture::for_pid(4, TEST_ROOT_PID, 1, "claude").content_frag(
                    0xabc,
                    0,
                    ContentChannel::Tls,
                    ContentDirection::Write,
                    prompt,
                    false,
                ),
                EventFixture::for_pid(5, TEST_ROOT_PID, 1, "claude").open(-100, 3, "/etc/shadow"),
            ],
            false,
        )
        .await;

        let alert = values
            .iter()
            .find(|value| value["type"] == "sensitive_file_access")
            .expect("sensitive alert");
        assert!(
            alert["evidence"]
                .as_array()
                .expect("evidence array")
                .iter()
                .any(|evidence| evidence["kind"] == "prompt_ref")
        );
    }

    #[tokio::test]
    async fn driver_links_tls_prompt_that_arrives_before_exec_attribution() {
        let prompt = br#"{"prompt":"please inspect /etc/shadow"}"#;
        let values = drive_alerts(
            vec![
                EventFixture::for_pid(1, TEST_ROOT_PID, 1, "claude").connect(3, 443, true),
                EventFixture::for_pid(2, TEST_ROOT_PID, 1, "claude").tls_assoc(
                    0xabc,
                    3,
                    ContentDirection::Write,
                    1,
                ),
                EventFixture::for_pid(3, TEST_ROOT_PID, 1, "claude").content_frag(
                    0xabc,
                    0,
                    ContentChannel::Tls,
                    ContentDirection::Write,
                    prompt,
                    false,
                ),
                EventFixture::for_pid(4, TEST_ROOT_PID, 1, "claude")
                    .exec("/usr/bin/claude", &["claude"]),
                EventFixture::for_pid(5, TEST_ROOT_PID, 1, "claude").open(-100, 3, "/etc/shadow"),
            ],
            false,
        )
        .await;

        let alert = values
            .iter()
            .find(|value| value["type"] == "sensitive_file_access")
            .expect("sensitive alert");
        assert!(
            alert["evidence"]
                .as_array()
                .expect("evidence array")
                .iter()
                .any(|evidence| evidence["kind"] == "prompt_ref")
        );
    }
}
