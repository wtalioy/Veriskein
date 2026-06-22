use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tracing::{debug, warn};
use veriskein_collector::CollectorCounters;
use veriskein_ipc::{
    AlertFrame, ErrorCode, ErrorFrame, HelloFrame, IpcFrame, MetricsFrame, MetricsSnapshot, Topic,
    WelcomeFrame, decode_ndjson_frame, encode_ndjson_frame,
};

use veriskein_ipc::QueuePolicy;

const SERVER_NAME: &str = "veriskein-daemon";
const OWNER_ONLY_SOCKET_MODE: u32 = 0o600;
const PEERCRED_FILTERED_SOCKET_MODE: u32 = 0o666;

#[derive(Debug, Clone)]
pub(crate) struct IpcSettings {
    pub allow_uids: Vec<u32>,
    pub alerts_capacity: usize,
    pub events_capacity: usize,
    pub graph_capacity: usize,
    pub client_slow_timeout_ms: u64,
}

impl Default for IpcSettings {
    fn default() -> Self {
        Self {
            allow_uids: Vec::new(),
            alerts_capacity: veriskein_ipc::IPC_ALERTS_QUEUE,
            events_capacity: veriskein_ipc::IPC_EVENTS_QUEUE,
            graph_capacity: veriskein_ipc::IPC_GRAPH_QUEUE,
            client_slow_timeout_ms: veriskein_ipc::IPC_CLIENT_SLOW_TIMEOUT_MS,
        }
    }
}

impl IpcSettings {
    fn queue_policy(&self) -> QueuePolicy {
        QueuePolicy {
            events_capacity: self.events_capacity,
            alerts_capacity: self.alerts_capacity,
            graph_capacity: self.graph_capacity,
            client_slow_timeout_ms: self.client_slow_timeout_ms,
        }
    }
}

pub(crate) struct IpcServer {
    path: PathBuf,
    alerts_tx: broadcast::Sender<IpcFrame>,
    metrics_tx: watch::Sender<IpcFrame>,
    handle: JoinHandle<()>,
}

impl IpcServer {
    pub(crate) async fn start(path: PathBuf, settings: IpcSettings) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create IPC socket parent {}", parent.display()))?;
        }
        remove_stale_socket(&path).await?;
        let listener = UnixListener::bind(&path)
            .with_context(|| format!("bind IPC socket {}", path.display()))?;
        let socket_mode = socket_mode_for(&settings);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(socket_mode))
            .with_context(|| format!("chmod IPC socket {}", path.display()))?;

        let (alerts_tx, _) = broadcast::channel(settings.alerts_capacity);
        let (metrics_tx, metrics_rx) = watch::channel(IpcFrame::Metrics(MetricsFrame::new(
            MetricsSnapshot::new(now_ns()),
        )));
        let connection_alerts = alerts_tx.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let alerts_rx = connection_alerts.subscribe();
                        let metrics_rx = metrics_rx.clone();
                        let settings = settings.clone();
                        tokio::spawn(async move {
                            if let Err(err) =
                                serve_client(stream, alerts_rx, metrics_rx, &settings).await
                            {
                                debug!("IPC client disconnected: {err:#}");
                            }
                        });
                    }
                    Err(err) => {
                        warn!("accept IPC client failed: {err}");
                    }
                }
            }
        });

        Ok(Self {
            path,
            alerts_tx,
            metrics_tx,
            handle,
        })
    }

    pub(crate) fn publish_alert(&self, alert: Value) {
        let _ = self.alerts_tx.send(IpcFrame::Alert(AlertFrame::new(alert)));
    }

    pub(crate) fn publish_metrics(
        &self,
        counters: &CollectorCounters,
        detector_fires_total: u64,
        events_per_s: f64,
        drops_per_s: f64,
        detector_fires_per_s: f64,
    ) {
        let mut metrics = MetricsSnapshot::new(now_ns());
        metrics
            .counters
            .insert("raw_events_total".to_string(), counters.raw_events_total);
        metrics.counters.insert(
            "emitted_events_total".to_string(),
            counters.emitted_events_total,
        );
        metrics.counters.insert(
            "reorder_or_drop_total".to_string(),
            counters.reorder_or_drop_total,
        );
        metrics
            .counters
            .insert("detector_fires_total".to_string(), detector_fires_total);
        metrics
            .gauges
            .insert("events_per_s".to_string(), events_per_s);
        metrics
            .gauges
            .insert("drops_per_s".to_string(), drops_per_s);
        metrics
            .gauges
            .insert("detector_fires_per_s".to_string(), detector_fires_per_s);
        let _ = self
            .metrics_tx
            .send(IpcFrame::Metrics(MetricsFrame::new(metrics)));
    }

    pub(crate) async fn shutdown(self) {
        self.handle.abort();
        let _ = tokio::fs::remove_file(&self.path).await;
    }
}

async fn serve_client(
    stream: UnixStream,
    mut alerts_rx: broadcast::Receiver<IpcFrame>,
    mut metrics_rx: watch::Receiver<IpcFrame>,
    settings: &IpcSettings,
) -> Result<()> {
    ensure_peer_allowed(&stream, &settings.allow_uids)?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut hello = String::new();
    reader
        .read_line(&mut hello)
        .await
        .context("read IPC hello")?;
    let subscriptions = match decode_ndjson_frame(&hello) {
        Ok(IpcFrame::Hello(frame)) => accepted_topics(&frame),
        Ok(_) => {
            write_error(
                &mut write_half,
                ErrorCode::DecodeError,
                "first IPC frame must be hello",
                settings.client_slow_timeout_ms,
            )
            .await?;
            return Ok(());
        }
        Err(err) => {
            write_error(
                &mut write_half,
                ErrorCode::VersionMismatch,
                err.to_string(),
                settings.client_slow_timeout_ms,
            )
            .await?;
            return Ok(());
        }
    };

    write_frame(
        &mut write_half,
        &IpcFrame::Welcome(WelcomeFrame {
            accepted_topics: subscriptions.clone(),
            queue_policy: settings.queue_policy(),
            ..WelcomeFrame::new(SERVER_NAME)
        }),
        settings.client_slow_timeout_ms,
    )
    .await?;

    if subscriptions.contains(&Topic::Metrics) {
        let frame = metrics_rx.borrow().clone();
        write_frame(&mut write_half, &frame, settings.client_slow_timeout_ms).await?;
    }

    let mut client_line = String::new();
    loop {
        tokio::select! {
            alert = alerts_rx.recv(), if subscriptions.contains(&Topic::Alert) => {
                match alert {
                    Ok(frame) => write_frame(&mut write_half, &frame, settings.client_slow_timeout_ms).await?,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        write_error(
                            &mut write_half,
                            ErrorCode::QueueOverflow,
                            "alert client lagged",
                            settings.client_slow_timeout_ms,
                        ).await?;
                        return Ok(());
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
            changed = metrics_rx.changed(), if subscriptions.contains(&Topic::Metrics) => {
                if changed.is_err() {
                    return Ok(());
                }
                let frame = metrics_rx.borrow().clone();
                write_frame(&mut write_half, &frame, settings.client_slow_timeout_ms).await?;
            }
            line = reader.read_line(&mut client_line) => {
                if line.unwrap_or(0) == 0 {
                    return Ok(());
                }
                client_line.clear();
            }
        }
    }
}

fn accepted_topics(hello: &HelloFrame) -> Vec<Topic> {
    hello
        .subscriptions
        .iter()
        .copied()
        .filter(|topic| matches!(topic, Topic::Alert | Topic::Metrics))
        .collect()
}

async fn write_error<W>(
    stream: &mut W,
    code: ErrorCode,
    message: impl Into<String>,
    timeout_ms: u64,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_frame(
        stream,
        &IpcFrame::Error(ErrorFrame::new(code, message.into())),
        timeout_ms,
    )
    .await
}

async fn write_frame<W>(stream: &mut W, frame: &IpcFrame, timeout_ms: u64) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let line = encode_ndjson_frame(frame).context("encode IPC frame")?;
    timeout(
        Duration::from_millis(timeout_ms),
        stream.write_all(line.as_bytes()),
    )
    .await
    .context("IPC client write timed out")?
    .context("write IPC frame")
}

fn socket_mode_for(settings: &IpcSettings) -> u32 {
    if settings.allow_uids.is_empty() {
        OWNER_ONLY_SOCKET_MODE
    } else {
        PEERCRED_FILTERED_SOCKET_MODE
    }
}

fn ensure_peer_allowed(stream: &UnixStream, allow_uids: &[u32]) -> Result<()> {
    let peer_uid = peer_uid(stream)?;
    let effective_uid = unsafe { libc::geteuid() };
    if peer_uid == effective_uid {
        return Ok(());
    }
    if effective_uid == 0 && allow_uids.contains(&peer_uid) {
        return Ok(());
    }
    Err(anyhow!("unauthorized IPC peer uid {peer_uid}"))
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("read IPC peer credentials");
    }
    Ok(cred.uid)
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove stale IPC socket {}", path.display())),
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
