use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::signal::unix::{Signal, SignalKind, signal};
#[cfg(test)]
use tokio::sync::oneshot::{self, error::TryRecvError};
use tracing::info;
use veriskein_alert::{
    DEGRADATION_SOURCE_CONFIGURED_SMALL_RINGBUF, DEGRADATION_SOURCE_RETENTION_EVICTION,
    DEGRADATION_SOURCE_RINGBUF_DROP_RATE, PressureLevel, RuntimeHealth, stdout_sink,
};
use veriskein_bpf::{BpfRuntimeConfig, RuntimeEventSource};
use veriskein_collector::CollectorCounters;
use veriskein_ipc::{EventFrame, GraphFrame, QueuePolicy, default_socket_path};

use crate::Cli;
use crate::ipc::{IpcServer, IpcSettings};
use crate::pipeline::{ContentCaptureSettings, ContentCaptureUpdate, RuntimePipeline};
use crate::preflight::preflight;

const METRICS_EMIT_INTERVAL: Duration = Duration::from_secs(1);
const HEALTH_UPDATE_INTERVAL: Duration = Duration::from_secs(10);
const EVENT_LOOP_POLL_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(test)]
const TEST_DRIVER_DRAIN_DELAY: Duration = Duration::from_millis(750);

pub async fn run(cli: Cli) -> Result<()> {
    preflight(&cli)?;
    let config_root = resolve_config_root()?;
    let bpf_config = load_bpf_runtime_config(&config_root, &cli)?;
    let content_capture = load_content_capture_settings(&config_root, &cli)?;
    let source = RuntimeEventSource::start_with_config(bpf_config.clone())
        .context("start BPF event source")?;
    let sink = open_sink(cli.alert_output.as_deref()).context("open alert sink")?;
    let sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let ipc = if cli.no_ipc {
        None
    } else {
        let config = load_ipc_config(&config_root)?;
        let path = cli.ipc_sock.clone().unwrap_or_else(default_socket_path);
        Some(IpcServer::start(path, config).await?)
    };

    run_with_source_and_sink(
        source,
        sink,
        RuntimeRunConfig {
            cli,
            config_root,
            content_capture,
            initial_health: initial_runtime_health(&bpf_config),
            ipc,
        },
        Shutdown::Signal(sigterm),
    )
    .await
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
    #[serde(default)]
    ipc: IpcConfig,
    #[serde(default)]
    limits: LimitsConfig,
    #[serde(default)]
    content_capture: ContentCaptureConfig,
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

#[derive(Debug, Default, Deserialize)]
pub(crate) struct IpcConfig {
    #[serde(default)]
    pub allow_uids: Vec<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct LimitsConfig {
    ringbuf_size: Option<usize>,
    ipc_alerts_queue: Option<usize>,
    ipc_events_queue: Option<usize>,
    ipc_graph_queue: Option<usize>,
    ipc_client_slow_timeout_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct ContentCaptureConfig {
    #[serde(default)]
    stdio: bool,
    #[serde(default)]
    mcp_stdio: bool,
}

fn load_bpf_runtime_config(config_root: &Path, cli: &Cli) -> Result<BpfRuntimeConfig> {
    let mut config = BpfRuntimeConfig::default();
    if let Some(defaults) = load_defaults_config(config_root)? {
        config.openssl_library_paths = defaults.tls.openssl.library_paths;
        config.openssl_soname_allowlist = defaults.tls.openssl.soname_allowlist;
        if let Some(ringbuf_size) = defaults.limits.ringbuf_size {
            config.ringbuf_size = ringbuf_size;
        }
    }
    if config.openssl_soname_allowlist.is_empty() {
        config.openssl_soname_allowlist = BpfRuntimeConfig::default().openssl_soname_allowlist;
    }
    if let Some(ringbuf_size) = cli.ringbuf_size {
        config.ringbuf_size = ringbuf_size;
    }
    config.tls_enabled = !cli.disable_tls;
    Ok(config)
}

fn load_ipc_config(config_root: &Path) -> Result<IpcSettings> {
    let Some(defaults) = load_defaults_config(config_root)? else {
        return Ok(IpcSettings::default());
    };
    Ok(ipc_settings_from_defaults(defaults))
}

fn load_content_capture_settings(config_root: &Path, cli: &Cli) -> Result<ContentCaptureSettings> {
    let mut settings = match load_defaults_config(config_root)? {
        Some(defaults) => ContentCaptureSettings {
            stdio_enabled: defaults.content_capture.stdio,
            mcp_stdio_enabled: defaults.content_capture.mcp_stdio,
        },
        None => ContentCaptureSettings::default(),
    };
    if cli.enable_content_capture {
        settings.stdio_enabled = true;
        settings.mcp_stdio_enabled = true;
    }
    Ok(settings)
}

fn load_defaults_config(config_root: &Path) -> Result<Option<DefaultsConfig>> {
    let path = config_root.join("config/defaults.toml");
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read defaults config {}", path.display()))?;
    let defaults: DefaultsConfig = toml::from_str(&text)
        .with_context(|| format!("parse defaults config {}", path.display()))?;
    Ok(Some(defaults))
}

fn ipc_settings_from_defaults(defaults: DefaultsConfig) -> IpcSettings {
    let default_policy = QueuePolicy::default();
    IpcSettings {
        allow_uids: defaults.ipc.allow_uids,
        queue_policy: QueuePolicy {
            alerts_capacity: defaults
                .limits
                .ipc_alerts_queue
                .unwrap_or(default_policy.alerts_capacity),
            events_capacity: defaults
                .limits
                .ipc_events_queue
                .unwrap_or(default_policy.events_capacity),
            graph_capacity: defaults
                .limits
                .ipc_graph_queue
                .unwrap_or(default_policy.graph_capacity),
            client_slow_timeout_ms: defaults
                .limits
                .ipc_client_slow_timeout_ms
                .unwrap_or(default_policy.client_slow_timeout_ms),
            alerts_overflow: default_policy.alerts_overflow,
            events_overflow: default_policy.events_overflow,
            graph_overflow: default_policy.graph_overflow,
        },
    }
}

fn open_sink(path: Option<&Path>) -> Result<Box<dyn Write + Send>> {
    match path {
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("create alert output file {}", path.display()))?;
            Ok(Box::new(BufWriter::new(file)))
        }
        None => Ok(stdout_sink()),
    }
}

#[derive(Debug, Clone)]
struct CounterWindow {
    last_raw_events: u64,
    last_drops: u64,
    last_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct CounterDelta {
    elapsed_secs: f64,
    raw_events: u64,
    drops: u64,
}

impl CounterWindow {
    fn new() -> Self {
        Self {
            last_raw_events: 0,
            last_drops: 0,
            last_at: Instant::now(),
        }
    }

    fn snapshot_if_due(
        &mut self,
        counters: &CollectorCounters,
        interval: Duration,
    ) -> Option<CounterDelta> {
        let elapsed = self.last_at.elapsed();
        if elapsed < interval {
            return None;
        }
        let delta = CounterDelta {
            elapsed_secs: elapsed.as_secs_f64(),
            raw_events: counters
                .raw_events_total
                .saturating_sub(self.last_raw_events),
            drops: counters
                .reorder_or_drop_total
                .saturating_sub(self.last_drops),
        };
        self.last_at = Instant::now();
        self.last_raw_events = counters.raw_events_total;
        self.last_drops = counters.reorder_or_drop_total;
        Some(delta)
    }
}

struct MetricsTick {
    counters: CounterWindow,
    last_detector_fires: u64,
    detector_fires_total: u64,
}

#[derive(Debug, Clone, Copy)]
struct MetricsSample {
    events_per_s: f64,
    drops_per_s: f64,
    detector_fires_per_s: f64,
    detector_fires_total: u64,
}

impl MetricsTick {
    fn new() -> Self {
        Self {
            counters: CounterWindow::new(),
            last_detector_fires: 0,
            detector_fires_total: 0,
        }
    }

    fn add_detector_fires(&mut self, count: usize) {
        self.detector_fires_total += count as u64;
    }

    fn maybe_log(&mut self, counters: &CollectorCounters) -> Option<MetricsSample> {
        let delta = self
            .counters
            .snapshot_if_due(counters, METRICS_EMIT_INTERVAL)?;
        let fire_delta = self
            .detector_fires_total
            .saturating_sub(self.last_detector_fires);
        let sample = MetricsSample {
            events_per_s: delta.raw_events as f64 / delta.elapsed_secs,
            drops_per_s: delta.drops as f64 / delta.elapsed_secs,
            detector_fires_per_s: fire_delta as f64 / delta.elapsed_secs,
            detector_fires_total: self.detector_fires_total,
        };
        info!(
            events_per_s = sample.events_per_s,
            drops_per_s = sample.drops_per_s,
            detector_fires_per_s = sample.detector_fires_per_s,
            "veriskein metrics"
        );
        self.last_detector_fires = self.detector_fires_total;
        Some(sample)
    }
}

#[derive(Debug, Clone)]
struct RuntimeHealthTracker {
    health: RuntimeHealth,
    counters: CounterWindow,
    last_detail_evictions_total: u64,
}

impl RuntimeHealthTracker {
    fn new(initial: RuntimeHealth) -> Self {
        Self {
            health: initial,
            counters: CounterWindow::new(),
            last_detail_evictions_total: 0,
        }
    }

    fn current(&self) -> &RuntimeHealth {
        &self.health
    }

    fn maybe_update(&mut self, counters: &CollectorCounters, detail_evictions_total: u64) {
        let Some(delta) = self
            .counters
            .snapshot_if_due(counters, HEALTH_UPDATE_INTERVAL)
        else {
            return;
        };
        let drop_rate = if delta.raw_events == 0 {
            0.0
        } else {
            delta.drops as f32 / delta.raw_events as f32
        };
        let mut sources = Vec::new();
        if self
            .health
            .degradation_sources
            .iter()
            .any(|source| source == DEGRADATION_SOURCE_CONFIGURED_SMALL_RINGBUF)
        {
            sources.push(DEGRADATION_SOURCE_CONFIGURED_SMALL_RINGBUF.to_string());
        }
        if drop_rate >= veriskein_proto::defaults::DROP_RATE_DEGRADE_THRESHOLD {
            sources.push(DEGRADATION_SOURCE_RINGBUF_DROP_RATE.to_string());
        }
        let detail_eviction_delta =
            detail_evictions_total.saturating_sub(self.last_detail_evictions_total);
        self.last_detail_evictions_total = detail_evictions_total;
        if detail_eviction_delta > 0 {
            sources.push(DEGRADATION_SOURCE_RETENTION_EVICTION.to_string());
        }
        if sources.is_empty() {
            self.health = RuntimeHealth::full();
        } else {
            self.health = RuntimeHealth {
                pressure: if drop_rate >= veriskein_proto::defaults::DROP_RATE_CRITICAL_THRESHOLD {
                    PressureLevel::Critical
                } else {
                    PressureLevel::Degraded
                },
                drop_rate,
                degradation_sources: sources,
            };
        }
        if self.health.degradation_sources == [DEGRADATION_SOURCE_CONFIGURED_SMALL_RINGBUF] {
            self.health.drop_rate = drop_rate;
        }
    }
}

fn initial_runtime_health(config: &BpfRuntimeConfig) -> RuntimeHealth {
    if config.ringbuf_size < veriskein_proto::defaults::RINGBUF_SIZE_TOTAL {
        RuntimeHealth {
            pressure: PressureLevel::Degraded,
            drop_rate: 0.0,
            degradation_sources: vec![DEGRADATION_SOURCE_CONFIGURED_SMALL_RINGBUF.to_string()],
        }
    } else {
        RuntimeHealth::full()
    }
}

trait EventSource {
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>>;
    fn upsert_content_capture(
        &mut self,
        _pid: u32,
        _fd: i32,
        _channel: veriskein_proto::ContentChannel,
        _expires_at_ns: u64,
    ) -> Result<()> {
        Ok(())
    }
    fn delete_content_capture(&mut self, _pid: u32, _fd: i32) -> Result<()> {
        Ok(())
    }
    fn shutdown(&mut self) -> Result<()>;
}

impl EventSource for RuntimeEventSource {
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
        RuntimeEventSource::try_recv(self)
    }

    fn upsert_content_capture(
        &mut self,
        pid: u32,
        fd: i32,
        channel: veriskein_proto::ContentChannel,
        expires_at_ns: u64,
    ) -> Result<()> {
        RuntimeEventSource::upsert_content_capture(self, pid, fd, channel, expires_at_ns)
    }

    fn delete_content_capture(&mut self, pid: u32, fd: i32) -> Result<()> {
        RuntimeEventSource::delete_content_capture(self, pid, fd)
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

struct RuntimeRunConfig {
    cli: Cli,
    config_root: std::path::PathBuf,
    content_capture: ContentCaptureSettings,
    initial_health: RuntimeHealth,
    ipc: Option<IpcServer>,
}

async fn run_with_source_and_sink<S>(
    mut source: S,
    mut sink: Box<dyn Write + Send>,
    config: RuntimeRunConfig,
    mut shutdown: Shutdown,
) -> Result<()>
where
    S: EventSource + Send + 'static,
{
    let mut pipeline = RuntimePipeline::new_with_content_capture(
        &config.config_root,
        &config.cli.workspaces,
        config.content_capture,
    )?;
    let mut health = RuntimeHealthTracker::new(config.initial_health);
    let mut metrics = MetricsTick::new();

    info!("veriskein runtime started");
    info!("using config root {}", config.config_root.display());
    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            _ = tokio::time::sleep(EVENT_LOOP_POLL_INTERVAL) => {
                if shutdown.requested() {
                    break;
                }
                // RuntimeEventSource is a non-blocking poll surface. Drain
                // everything currently buffered before sleeping again so graph
                // state and detector ordering stay aligned with ingest order.
                loop {
                    match source.try_recv() {
                        Ok(Some(raw)) => {
                            pipeline.set_runtime_health(health.current().clone());
                            let alerts =
                                pipeline.process_raw_event_bytes(&raw, &mut *sink, config.cli.dry_run)?;
                            metrics.add_detector_fires(alerts.len());
                            if let Some(ipc) = &config.ipc {
                                for event in pipeline.drain_ipc_events() {
                                    ipc.publish_event(EventFrame::new(
                                        event.event_id,
                                        event.ts_ns,
                                        event.event_kind,
                                        event.pid,
                                        event.session_id,
                                        event.event,
                                    ));
                                }
                                for graph in pipeline.drain_ipc_graph() {
                                    ipc.publish_graph(GraphFrame::new(graph.ts_ns, graph.graph));
                                }
                                for alert in alerts {
                                    ipc.publish_alert(alert.as_value()?);
                                }
                            } else {
                                let _ = pipeline.drain_ipc_events();
                                let _ = pipeline.drain_ipc_graph();
                            }
                            apply_content_capture_updates(
                                &mut source,
                                pipeline.drain_content_capture_updates(),
                            )?;
                        }
                        Ok(None) => break,
                        Err(err) => return Err(err),
                    }
                }
                if let Some(sample) = metrics.maybe_log(pipeline.collector_counters())
                    && let Some(ipc) = &config.ipc
                {
                    ipc.publish_metrics(
                        pipeline.collector_counters(),
                        sample.detector_fires_total,
                        sample.events_per_s,
                        sample.drops_per_s,
                        sample.detector_fires_per_s,
                    );
                }
                health.maybe_update(
                    pipeline.collector_counters(),
                    pipeline.retained_detail_evictions_total(),
                );
                pipeline.maybe_refresh_endpoint_ips();
            }
        }
    }
    source.shutdown().context("stop event source")?;
    if let Some(ipc) = config.ipc {
        ipc.shutdown().await;
    }
    sink.flush().context("flush alert sink")?;
    Ok(())
}

fn apply_content_capture_updates<S: EventSource>(
    source: &mut S,
    updates: Vec<ContentCaptureUpdate>,
) -> Result<()> {
    for update in updates {
        match update {
            ContentCaptureUpdate::Upsert {
                pid,
                fd,
                channel,
                expires_at_ns,
            } => source.upsert_content_capture(pid, fd, channel, expires_at_ns)?,
            ContentCaptureUpdate::Delete { pid, fd } => source.delete_content_capture(pid, fd)?,
        }
    }
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

    use serde_json::Value;
    use tempfile::NamedTempFile;
    use tokio::sync::oneshot;
    use veriskein_proto::{ContentChannel, ContentDirection, EventFixture};

    use super::{
        EventSource, Result, RuntimeRunConfig, Shutdown, open_sink, run_with_source_and_sink,
    };
    use crate::Cli;

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

    fn force_health_window_due(health: &mut super::RuntimeHealthTracker) {
        health.counters.last_at = std::time::Instant::now() - super::HEALTH_UPDATE_INTERVAL;
    }

    #[test]
    fn runtime_health_eviction_degradation_recovers_after_clean_window() {
        let mut health = super::RuntimeHealthTracker::new(veriskein_alert::RuntimeHealth::full());
        let counters = veriskein_collector::CollectorCounters {
            raw_events_total: 100,
            emitted_events_total: 100,
            reorder_or_drop_total: 0,
        };

        force_health_window_due(&mut health);
        health.maybe_update(&counters, 1);
        assert!(
            health
                .current()
                .degradation_sources
                .iter()
                .any(|source| source == super::DEGRADATION_SOURCE_RETENTION_EVICTION)
        );

        force_health_window_due(&mut health);
        health.maybe_update(&counters, 1);
        assert_eq!(
            health.current().pressure,
            veriskein_alert::PressureLevel::Nominal
        );
    }

    #[test]
    fn runtime_health_marks_critical_drop_pressure() {
        let mut health = super::RuntimeHealthTracker::new(veriskein_alert::RuntimeHealth::full());
        let counters = veriskein_collector::CollectorCounters {
            raw_events_total: 100,
            emitted_events_total: 90,
            reorder_or_drop_total: 10,
        };

        force_health_window_due(&mut health);
        health.maybe_update(&counters, 0);

        assert_eq!(
            health.current().pressure,
            veriskein_alert::PressureLevel::Critical
        );
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
                RuntimeRunConfig {
                    cli: Cli {
                        workspaces: vec!["/tmp/ws".into()],
                        dry_run,
                        alert_output: None,
                        ringbuf_size: None,
                        ipc_sock: None,
                        no_ipc: true,
                        disable_tls: false,
                        enable_content_capture: false,
                    },
                    config_root: config_root(),
                    content_capture: super::ContentCaptureSettings::default(),
                    initial_health: veriskein_alert::RuntimeHealth::full(),
                    ipc: None,
                },
                Shutdown::Oneshot(shutdown_rx),
            )
            .await
        });
        tokio::time::sleep(super::TEST_DRIVER_DRAIN_DELAY).await;
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
