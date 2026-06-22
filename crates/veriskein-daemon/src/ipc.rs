use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tracing::{debug, warn};
use veriskein_collector::CollectorCounters;
use veriskein_ipc::IpcError;
use veriskein_ipc::QueuePolicy;
use veriskein_ipc::{
    AlertFrame, ErrorCode, ErrorFrame, EventFrame, GraphFrame, HelloFrame, IpcFrame, MetricsFrame,
    MetricsSnapshot, ReplyFrame, Topic, WelcomeFrame, decode_ndjson, encode_ndjson,
};
use veriskein_proto::EventId;

const SERVER_NAME: &str = "veriskein-daemon";
const OWNER_ONLY_SOCKET_MODE: u32 = 0o600;
const PEERCRED_FILTERED_SOCKET_MODE: u32 = 0o666;
const MAX_IPC_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Default)]
pub(crate) struct IpcSettings {
    pub allow_uids: Vec<u32>,
    pub queue_policy: QueuePolicy,
}

pub(crate) struct IpcServer {
    path: PathBuf,
    alerts_tx: broadcast::Sender<IpcFrame>,
    events_tx: broadcast::Sender<IpcFrame>,
    graph_tx: broadcast::Sender<IpcFrame>,
    metrics_tx: watch::Sender<IpcFrame>,
    handle: JoinHandle<()>,
}

impl IpcServer {
    pub(crate) async fn start(path: PathBuf, settings: IpcSettings) -> Result<Self> {
        if settings.queue_policy.alerts_capacity == 0 {
            bail!("IPC alerts queue capacity must be at least 1");
        }
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

        let (alerts_tx, _) = broadcast::channel(settings.queue_policy.alerts_capacity);
        let (events_tx, _) = broadcast::channel(settings.queue_policy.alerts_capacity);
        let (graph_tx, _) = broadcast::channel(settings.queue_policy.alerts_capacity);
        let (metrics_tx, metrics_rx) = watch::channel(IpcFrame::Metrics(MetricsFrame::new(
            MetricsSnapshot::new(now_ns()),
        )));
        let connection_alerts = alerts_tx.clone();
        let connection_events = events_tx.clone();
        let connection_graph = graph_tx.clone();
        let run_id =
            EventId::from_seed(format!("{}:{}", std::process::id(), now_ns()).as_bytes()).hex();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let alerts_rx = connection_alerts.subscribe();
                        let events_rx = connection_events.subscribe();
                        let graph_rx = connection_graph.subscribe();
                        let metrics_rx = metrics_rx.clone();
                        let settings = settings.clone();
                        let run_id = run_id.clone();
                        tokio::spawn(async move {
                            if let Err(err) = serve_client(
                                stream, alerts_rx, events_rx, graph_rx, metrics_rx, &settings,
                                &run_id,
                            )
                            .await
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
            events_tx,
            graph_tx,
            metrics_tx,
            handle,
        })
    }

    pub(crate) fn publish_alert(&self, alert: Value) {
        let _ = self.alerts_tx.send(IpcFrame::Alert(AlertFrame::new(alert)));
    }

    pub(crate) fn publish_event(&self, event: EventFrame) {
        let _ = self.events_tx.send(IpcFrame::Event(event));
    }

    pub(crate) fn publish_graph(&self, graph: GraphFrame) {
        let _ = self.graph_tx.send(IpcFrame::Graph(graph));
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
        metrics.queue_depths.alerts = self.alerts_tx.len();
        metrics.queue_depths.events = self.events_tx.len();
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
    mut events_rx: broadcast::Receiver<IpcFrame>,
    mut graph_rx: broadcast::Receiver<IpcFrame>,
    mut metrics_rx: watch::Receiver<IpcFrame>,
    settings: &IpcSettings,
    run_id: &str,
) -> Result<()> {
    ensure_peer_allowed(&stream, &settings.allow_uids)?;
    let slow_timeout_ms = settings.queue_policy.client_slow_timeout_ms;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut hello = Vec::new();
    if let Err(err) = read_bounded_line(&mut reader, &mut hello, MAX_IPC_FRAME_BYTES).await {
        write_error(
            &mut write_half,
            ErrorCode::DecodeError,
            err.to_string(),
            slow_timeout_ms,
        )
        .await?;
        return Ok(());
    }
    if hello.is_empty() {
        return Ok(());
    }
    let hello = String::from_utf8(hello).context("decode IPC hello as utf-8")?;
    let subscriptions = match decode_ndjson(&hello) {
        Ok(IpcFrame::Hello(frame)) => accepted_topics(&frame),
        Ok(_) => {
            write_error(
                &mut write_half,
                ErrorCode::DecodeError,
                "first IPC frame must be hello",
                slow_timeout_ms,
            )
            .await?;
            return Ok(());
        }
        Err(IpcError::VersionMismatch {
            received_ipc_version,
            received_schema_version,
            ..
        }) => {
            write_frame(
                &mut write_half,
                &IpcFrame::Error(ErrorFrame::version_mismatch(
                    received_ipc_version,
                    received_schema_version,
                )),
                slow_timeout_ms,
            )
            .await?;
            return Ok(());
        }
        Err(err) => {
            write_error(
                &mut write_half,
                ErrorCode::DecodeError,
                err.to_string(),
                slow_timeout_ms,
            )
            .await?;
            return Ok(());
        }
    };

    write_frame(
        &mut write_half,
        &IpcFrame::Welcome(WelcomeFrame {
            run_id: run_id.to_string(),
            accepted_topics: subscriptions.clone(),
            queue_policy: settings.queue_policy.clone(),
            ..WelcomeFrame::new(SERVER_NAME)
        }),
        slow_timeout_ms,
    )
    .await?;

    if subscriptions.contains(&Topic::Metrics) {
        let frame = metrics_rx.borrow().clone();
        write_frame(&mut write_half, &frame, slow_timeout_ms).await?;
    }

    let mut client_line = Vec::new();
    loop {
        tokio::select! {
            alert = alerts_rx.recv(), if subscriptions.contains(&Topic::Alert) => {
                if !handle_broadcast_frame(alert, &mut write_half, slow_timeout_ms, "alert").await? {
                    return Ok(());
                }
            }
            event = events_rx.recv(), if subscriptions.contains(&Topic::Events) => {
                if !handle_broadcast_frame(event, &mut write_half, slow_timeout_ms, "event").await? {
                    return Ok(());
                }
            }
            graph = graph_rx.recv(), if subscriptions.contains(&Topic::Graph) => {
                if !handle_broadcast_frame(graph, &mut write_half, slow_timeout_ms, "graph").await? {
                    return Ok(());
                }
            }
            changed = metrics_rx.changed(), if subscriptions.contains(&Topic::Metrics) => {
                if changed.is_err() {
                    return Ok(());
                }
                let frame = metrics_rx.borrow().clone();
                write_frame(&mut write_half, &frame, slow_timeout_ms).await?;
            }
            line = read_bounded_line(&mut reader, &mut client_line, MAX_IPC_FRAME_BYTES) => {
                match line {
                    Ok(0) => return Ok(()),
                    Ok(_) => {
                        match decode_ndjson(std::str::from_utf8(&client_line).context("decode IPC client frame as utf-8")?) {
                            Ok(IpcFrame::Query(query)) => {
                                let reply = IpcFrame::Reply(ReplyFrame::error(
                                    query.query_id,
                                    query.topic,
                                    "historical IPC queries are not implemented yet",
                                ));
                                write_frame(&mut write_half, &reply, slow_timeout_ms).await?;
                            }
                            Ok(_) => {
                                write_error(
                                    &mut write_half,
                                    ErrorCode::DecodeError,
                                    "client frame after hello must be query",
                                    slow_timeout_ms,
                                ).await?;
                                return Ok(());
                            }
                            Err(err) => {
                                write_error(
                                    &mut write_half,
                                    ErrorCode::DecodeError,
                                    err.to_string(),
                                    slow_timeout_ms,
                                ).await?;
                                return Ok(());
                            }
                        }
                    }
                    Err(err) => {
                        write_error(
                            &mut write_half,
                            ErrorCode::DecodeError,
                            err.to_string(),
                            slow_timeout_ms,
                        ).await?;
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn handle_broadcast_frame<W>(
    frame: Result<IpcFrame, broadcast::error::RecvError>,
    stream: &mut W,
    timeout_ms: u64,
    topic_name: &str,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    match frame {
        Ok(frame) => {
            write_frame(stream, &frame, timeout_ms).await?;
            Ok(true)
        }
        Err(broadcast::error::RecvError::Lagged(_)) => {
            write_error(
                stream,
                ErrorCode::QueueOverflow,
                format!("{topic_name} client lagged"),
                timeout_ms,
            )
            .await?;
            Ok(false)
        }
        Err(broadcast::error::RecvError::Closed) => Ok(false),
    }
}

async fn read_bounded_line<R>(reader: &mut R, out: &mut Vec<u8>, max_len: usize) -> Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    out.clear();
    loop {
        let (take, has_newline) = {
            let available = reader.fill_buf().await.context("read IPC frame")?;
            if available.is_empty() {
                return Ok(out.len());
            }
            let take = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|index| index + 1)
                .unwrap_or(available.len());
            if out.len().saturating_add(take) > max_len {
                bail!("IPC frame exceeds {max_len} bytes");
            }
            out.extend_from_slice(&available[..take]);
            (take, out.ends_with(b"\n"))
        };
        reader.consume(take);
        if has_newline {
            return Ok(out.len());
        }
    }
}

fn accepted_topics(hello: &HelloFrame) -> Vec<Topic> {
    hello
        .subscriptions
        .iter()
        .copied()
        .filter(|topic| {
            matches!(
                topic,
                Topic::Alert | Topic::Metrics | Topic::Events | Topic::Graph | Topic::Query
            )
        })
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
    let line = encode_ndjson(frame).context("encode IPC frame")?;
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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use veriskein_ipc::{HelloFrame, QueueOverflowPolicy, decode_ndjson, encode_ndjson};

    use super::*;

    #[test]
    fn accepted_topics_filters_provisional_subscriptions() {
        let mut hello = HelloFrame::new("test-client");
        hello.subscriptions = vec![Topic::Alert, Topic::Events, Topic::Graph, Topic::Metrics];

        assert_eq!(
            accepted_topics(&hello),
            vec![Topic::Alert, Topic::Events, Topic::Graph, Topic::Metrics]
        );
    }

    #[tokio::test]
    async fn ipc_server_rejects_zero_alert_queue_capacity() {
        let dir = tempdir().expect("tempdir");
        let settings = IpcSettings {
            queue_policy: QueuePolicy {
                alerts_capacity: 0,
                client_slow_timeout_ms: 1,
                alerts_overflow: QueueOverflowPolicy::DropClientOnLag,
            },
            ..IpcSettings::default()
        };

        let err = match IpcServer::start(dir.path().join("veriskein.sock"), settings).await {
            Ok(server) => {
                server.shutdown().await;
                panic!("zero queue capacity accepted");
            }
            Err(err) => err,
        };

        assert!(err.to_string().contains("at least 1"));
    }

    #[tokio::test]
    async fn ipc_server_streams_live_alerts_after_welcome() {
        let dir = tempdir().expect("tempdir");
        let server = IpcServer::start(dir.path().join("veriskein.sock"), IpcSettings::default())
            .await
            .expect("start server");
        let stream = UnixStream::connect(dir.path().join("veriskein.sock"))
            .await
            .expect("connect");
        let mut reader = BufReader::new(stream);
        let mut hello = HelloFrame::new("test-client");
        hello.subscriptions = vec![Topic::Alert];
        let line = encode_ndjson(&IpcFrame::Hello(hello)).expect("encode hello");
        reader
            .get_mut()
            .write_all(line.as_bytes())
            .await
            .expect("write hello");

        let mut welcome = String::new();
        reader.read_line(&mut welcome).await.expect("read welcome");
        assert!(matches!(
            decode_ndjson(&welcome).expect("decode welcome"),
            IpcFrame::Welcome(_)
        ));

        server.publish_alert(json!({"alert_id":"alert-1","type":"unexpected_shell"}));

        let mut alert = String::new();
        reader.read_line(&mut alert).await.expect("read alert");
        let IpcFrame::Alert(frame) = decode_ndjson(&alert).expect("decode alert") else {
            panic!("expected alert");
        };
        assert_eq!(frame.alert["alert_id"], "alert-1");

        server.shutdown().await;
    }

    #[tokio::test]
    async fn ipc_server_replies_to_query_frames() {
        let dir = tempdir().expect("tempdir");
        let server = IpcServer::start(dir.path().join("veriskein.sock"), IpcSettings::default())
            .await
            .expect("start server");
        let stream = UnixStream::connect(dir.path().join("veriskein.sock"))
            .await
            .expect("connect");
        let mut reader = BufReader::new(stream);
        let mut hello = HelloFrame::new("test-client");
        hello.subscriptions = vec![Topic::Query];
        reader
            .get_mut()
            .write_all(
                encode_ndjson(&IpcFrame::Hello(hello))
                    .expect("encode hello")
                    .as_bytes(),
            )
            .await
            .expect("write hello");

        let mut welcome = String::new();
        reader.read_line(&mut welcome).await.expect("read welcome");
        assert!(matches!(
            decode_ndjson(&welcome).expect("decode welcome"),
            IpcFrame::Welcome(_)
        ));

        reader
            .get_mut()
            .write_all(
                encode_ndjson(&IpcFrame::Query(veriskein_ipc::QueryFrame::new(
                    "q-1",
                    Topic::Events,
                )))
                .expect("encode query")
                .as_bytes(),
            )
            .await
            .expect("write query");

        let mut reply = String::new();
        reader.read_line(&mut reply).await.expect("read reply");
        let IpcFrame::Reply(reply) = decode_ndjson(&reply).expect("decode reply") else {
            panic!("expected reply");
        };
        assert_eq!(reply.query_id, "q-1");
        assert!(!reply.ok);

        server.shutdown().await;
    }

    #[tokio::test]
    async fn ipc_server_streams_event_and_graph_topics() {
        let dir = tempdir().expect("tempdir");
        let server = IpcServer::start(dir.path().join("veriskein.sock"), IpcSettings::default())
            .await
            .expect("start server");
        let stream = UnixStream::connect(dir.path().join("veriskein.sock"))
            .await
            .expect("connect");
        let mut reader = BufReader::new(stream);
        let mut hello = HelloFrame::new("test-client");
        hello.subscriptions = vec![Topic::Events, Topic::Graph];
        reader
            .get_mut()
            .write_all(
                encode_ndjson(&IpcFrame::Hello(hello))
                    .expect("encode hello")
                    .as_bytes(),
            )
            .await
            .expect("write hello");

        let mut welcome = String::new();
        reader.read_line(&mut welcome).await.expect("read welcome");
        assert!(matches!(
            decode_ndjson(&welcome).expect("decode welcome"),
            IpcFrame::Welcome(_)
        ));

        server.publish_event(EventFrame::new(
            "evt-1",
            10,
            "proc_exec",
            42,
            Some("session-1".to_string()),
            json!({"argv":["agent"]}),
        ));
        server.publish_graph(GraphFrame::new(
            11,
            json!({"op":"bind","pid":42,"role":"root_agent"}),
        ));

        let mut event = String::new();
        reader.read_line(&mut event).await.expect("read event");
        let IpcFrame::Event(event) = decode_ndjson(&event).expect("decode event") else {
            panic!("expected event");
        };
        assert_eq!(event.event_id, "evt-1");

        let mut graph = String::new();
        reader.read_line(&mut graph).await.expect("read graph");
        let IpcFrame::Graph(graph) = decode_ndjson(&graph).expect("decode graph") else {
            panic!("expected graph");
        };
        assert_eq!(graph.graph["op"], "bind");

        server.shutdown().await;
    }
}
