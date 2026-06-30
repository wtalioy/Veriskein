use std::collections::VecDeque;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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
use veriskein_ipc::{
    AlertFrame, ErrorCode, ErrorFrame, EventFrame, EventsDroppedFrame, GraphFrame, HelloFrame,
    IpcFrame, MetricsFrame, MetricsSnapshot, QueryFrame, ReplyFrame, Topic, WelcomeFrame,
    decode_ndjson, encode_ndjson,
};
use veriskein_ipc::{QueueOverflowPolicy, QueuePolicy};
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
    history: Arc<Mutex<IpcHistory>>,
    handle: JoinHandle<()>,
}

#[derive(Debug)]
struct IpcHistory {
    alerts: VecDeque<HistoryItem>,
    events: VecDeque<HistoryItem>,
    graph: VecDeque<HistoryItem>,
    metrics: Option<HistoryItem>,
    next_cursor: u64,
    alerts_capacity: usize,
    events_capacity: usize,
    graph_capacity: usize,
}

#[derive(Debug, Clone)]
struct HistoryItem {
    cursor: u64,
    frame: IpcFrame,
}

impl IpcHistory {
    fn new(policy: &QueuePolicy) -> Self {
        Self {
            alerts: VecDeque::with_capacity(policy.alerts_capacity.min(1024)),
            events: VecDeque::with_capacity(policy.events_capacity.min(1024)),
            graph: VecDeque::with_capacity(policy.graph_capacity.min(1024)),
            metrics: None,
            next_cursor: 1,
            alerts_capacity: policy.alerts_capacity,
            events_capacity: policy.events_capacity,
            graph_capacity: policy.graph_capacity,
        }
    }

    fn push_alert(&mut self, frame: IpcFrame) {
        let item = self.next_item(frame);
        push_bounded(&mut self.alerts, self.alerts_capacity, item);
    }

    fn push_event(&mut self, frame: IpcFrame) {
        let item = self.next_item(frame);
        push_bounded(&mut self.events, self.events_capacity, item);
    }

    fn push_graph(&mut self, frame: IpcFrame) {
        let item = self.next_item(frame);
        push_bounded(&mut self.graph, self.graph_capacity, item);
    }

    fn set_metrics(&mut self, frame: IpcFrame) {
        self.metrics = Some(self.next_item(frame));
    }

    fn next_item(&mut self, frame: IpcFrame) -> HistoryItem {
        let cursor = self.next_cursor;
        self.next_cursor = self.next_cursor.saturating_add(1);
        HistoryItem { cursor, frame }
    }
}

impl IpcServer {
    pub(crate) async fn start(path: PathBuf, settings: IpcSettings) -> Result<Self> {
        if settings.queue_policy.alerts_capacity == 0 {
            bail!("IPC alerts queue capacity must be at least 1");
        }
        if settings.queue_policy.events_capacity == 0 {
            bail!("IPC events queue capacity must be at least 1");
        }
        if settings.queue_policy.graph_capacity == 0 {
            bail!("IPC graph queue capacity must be at least 1");
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
        let (events_tx, _) = broadcast::channel(settings.queue_policy.events_capacity);
        let (graph_tx, _) = broadcast::channel(settings.queue_policy.graph_capacity);
        let (metrics_tx, metrics_rx) = watch::channel(IpcFrame::Metrics(MetricsFrame::new(
            MetricsSnapshot::new(now_ns()),
        )));
        let history = Arc::new(Mutex::new(IpcHistory::new(&settings.queue_policy)));
        let connection_alerts = alerts_tx.clone();
        let connection_events = events_tx.clone();
        let connection_graph = graph_tx.clone();
        let connection_history = Arc::clone(&history);
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
                        let history = Arc::clone(&connection_history);
                        let settings = settings.clone();
                        let run_id = run_id.clone();
                        tokio::spawn(async move {
                            if let Err(err) = serve_client(
                                stream,
                                ClientStreams {
                                    alerts_rx,
                                    events_rx,
                                    graph_rx,
                                    metrics_rx,
                                    history,
                                },
                                &settings,
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
            history,
            handle,
        })
    }

    pub(crate) fn publish_alert(&self, alert: Value) {
        let frame = IpcFrame::Alert(AlertFrame::new(alert));
        if let Ok(mut history) = self.history.lock() {
            history.push_alert(frame.clone());
        }
        let _ = self.alerts_tx.send(frame);
    }

    pub(crate) fn publish_event(&self, event: EventFrame) {
        let frame = IpcFrame::Event(event);
        if let Ok(mut history) = self.history.lock() {
            history.push_event(frame.clone());
        }
        let _ = self.events_tx.send(frame);
    }

    pub(crate) fn publish_graph(&self, graph: GraphFrame) {
        let frame = IpcFrame::Graph(graph);
        if let Ok(mut history) = self.history.lock() {
            history.push_graph(frame.clone());
        }
        let _ = self.graph_tx.send(frame);
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
        metrics.queue_depths.graph = self.graph_tx.len();
        let frame = IpcFrame::Metrics(MetricsFrame::new(metrics));
        if let Ok(mut history) = self.history.lock() {
            history.set_metrics(frame.clone());
        }
        let _ = self.metrics_tx.send(frame);
    }

    pub(crate) async fn shutdown(self) {
        self.handle.abort();
        let _ = tokio::fs::remove_file(&self.path).await;
    }
}

struct ClientStreams {
    alerts_rx: broadcast::Receiver<IpcFrame>,
    events_rx: broadcast::Receiver<IpcFrame>,
    graph_rx: broadcast::Receiver<IpcFrame>,
    metrics_rx: watch::Receiver<IpcFrame>,
    history: Arc<Mutex<IpcHistory>>,
}

async fn serve_client(
    stream: UnixStream,
    mut streams: ClientStreams,
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
        let frame = streams.metrics_rx.borrow().clone();
        write_frame(&mut write_half, &frame, slow_timeout_ms).await?;
    }

    let mut client_line = Vec::new();
    loop {
        tokio::select! {
            alert = streams.alerts_rx.recv(), if subscriptions.contains(&Topic::Alert) => {
                if !handle_broadcast_frame(
                    alert,
                    &mut write_half,
                    slow_timeout_ms,
                    "alert",
                    settings.queue_policy.alerts_overflow,
                ).await? {
                    return Ok(());
                }
            }
            event = streams.events_rx.recv(), if subscriptions.contains(&Topic::Events) => {
                if !handle_topic_frame(
                    event,
                    &mut write_half,
                    slow_timeout_ms,
                    "event",
                    settings.queue_policy.events_overflow,
                ).await? {
                    return Ok(());
                }
            }
            graph = streams.graph_rx.recv(), if subscriptions.contains(&Topic::Graph) => {
                if !handle_broadcast_frame(
                    graph,
                    &mut write_half,
                    slow_timeout_ms,
                    "graph",
                    settings.queue_policy.graph_overflow,
                ).await? {
                    return Ok(());
                }
            }
            changed = streams.metrics_rx.changed(), if subscriptions.contains(&Topic::Metrics) => {
                if changed.is_err() {
                    return Ok(());
                }
                let frame = streams.metrics_rx.borrow().clone();
                write_frame(&mut write_half, &frame, slow_timeout_ms).await?;
            }
            line = read_bounded_line(&mut reader, &mut client_line, MAX_IPC_FRAME_BYTES) => {
                match line {
                    Ok(0) => return Ok(()),
                    Ok(_) => {
                        match decode_ndjson(std::str::from_utf8(&client_line).context("decode IPC client frame as utf-8")?) {
                            Ok(IpcFrame::Query(query)) => {
                                let reply = query_history(&streams.history, query);
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
    policy: QueueOverflowPolicy,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    match frame {
        Ok(frame) => {
            write_frame(stream, &frame, timeout_ms).await?;
            Ok(true)
        }
        Err(broadcast::error::RecvError::Lagged(count)) => {
            handle_lagged_topic(stream, timeout_ms, topic_name, policy, count).await
        }
        Err(broadcast::error::RecvError::Closed) => Ok(false),
    }
}

async fn handle_topic_frame<W>(
    frame: Result<IpcFrame, broadcast::error::RecvError>,
    stream: &mut W,
    timeout_ms: u64,
    topic_name: &str,
    policy: QueueOverflowPolicy,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    match frame {
        Ok(frame) => {
            write_frame(stream, &frame, timeout_ms).await?;
            Ok(true)
        }
        Err(broadcast::error::RecvError::Lagged(count)) => {
            handle_lagged_topic(stream, timeout_ms, topic_name, policy, count).await
        }
        Err(broadcast::error::RecvError::Closed) => Ok(false),
    }
}

async fn handle_lagged_topic<W>(
    stream: &mut W,
    timeout_ms: u64,
    topic_name: &str,
    policy: QueueOverflowPolicy,
    count: u64,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    match policy {
        QueueOverflowPolicy::DropClientOnLag => {
            write_error(
                stream,
                ErrorCode::QueueOverflow,
                format!("{topic_name} client lagged"),
                timeout_ms,
            )
            .await?;
            Ok(false)
        }
        QueueOverflowPolicy::ReportDropAndContinue => {
            write_frame(
                stream,
                &IpcFrame::EventsDropped(EventsDroppedFrame::new(
                    now_ns(),
                    count,
                    format!("{topic_name}_client_lagged"),
                )),
                timeout_ms,
            )
            .await?;
            Ok(true)
        }
    }
}

fn query_history(history: &Arc<Mutex<IpcHistory>>, query: QueryFrame) -> IpcFrame {
    let Ok(history) = history.lock() else {
        return IpcFrame::Reply(ReplyFrame::error(
            query.query_id,
            query.topic,
            "IPC history is unavailable",
        ));
    };
    let items = match query.topic {
        Topic::Alert => history_items(&history.alerts, query.after.as_deref(), query.limit),
        Topic::Events => history_items(&history.events, query.after.as_deref(), query.limit),
        Topic::Graph => history_items(&history.graph, query.after.as_deref(), query.limit),
        Topic::Metrics => history
            .metrics
            .as_ref()
            .filter(|item| item_after_cursor(item, query.after.as_deref()))
            .and_then(history_payload)
            .into_iter()
            .collect(),
        _ => {
            return IpcFrame::Reply(ReplyFrame::error(
                query.query_id,
                query.topic,
                "topic is not queryable",
            ));
        }
    };
    IpcFrame::Reply(ReplyFrame::ok(query.query_id, query.topic, items))
}

fn history_items(
    frames: &VecDeque<HistoryItem>,
    after: Option<&str>,
    limit: Option<usize>,
) -> Vec<Value> {
    let limit = limit.unwrap_or(100).min(1_000);
    frames
        .iter()
        .filter(|item| item_after_cursor(item, after))
        .filter_map(history_payload)
        .take(limit)
        .collect()
}

fn item_after_cursor(item: &HistoryItem, after: Option<&str>) -> bool {
    after
        .and_then(|cursor| cursor.parse::<u64>().ok())
        .is_none_or(|cursor| item.cursor > cursor)
}

fn history_payload(item: &HistoryItem) -> Option<Value> {
    frame_payload(&item.frame).map(|payload| {
        serde_json::json!({
            "cursor": item.cursor.to_string(),
            "ts_ns": frame_ts_ns(&item.frame),
            "topic": topic_name(item.frame.topic()),
            "payload": payload,
        })
    })
}

fn frame_payload(frame: &IpcFrame) -> Option<Value> {
    match frame {
        IpcFrame::Alert(frame) => Some(frame.alert.clone()),
        IpcFrame::Event(frame) => serde_json::to_value(frame).ok(),
        IpcFrame::Graph(frame) => Some(frame.graph.clone()),
        IpcFrame::Metrics(frame) => serde_json::to_value(&frame.metrics).ok(),
        _ => None,
    }
}

fn frame_ts_ns(frame: &IpcFrame) -> u64 {
    match frame {
        IpcFrame::Alert(frame) => frame.alert["ts_ns"].as_u64().unwrap_or(0),
        IpcFrame::Event(frame) => frame.ts_ns,
        IpcFrame::EventsDropped(frame) => frame.ts_ns,
        IpcFrame::Graph(frame) => frame.ts_ns,
        IpcFrame::Metrics(frame) => frame.metrics.ts_ns,
        _ => 0,
    }
}

fn topic_name(topic: Topic) -> &'static str {
    match topic {
        Topic::Hello => "hello",
        Topic::Welcome => "welcome",
        Topic::Error => "error",
        Topic::Alert => "alerts",
        Topic::Metrics => "metrics",
        Topic::Events => "events",
        Topic::Graph => "graph",
        Topic::Query => "query",
        Topic::Reply => "reply",
    }
}

fn push_bounded(queue: &mut VecDeque<HistoryItem>, capacity: usize, item: HistoryItem) {
    if capacity == 0 {
        return;
    }
    while queue.len() >= capacity {
        queue.pop_front();
    }
    queue.push_back(item);
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
                events_capacity: 1,
                graph_capacity: 1,
                client_slow_timeout_ms: 1,
                alerts_overflow: QueueOverflowPolicy::DropClientOnLag,
                events_overflow: QueueOverflowPolicy::ReportDropAndContinue,
                graph_overflow: QueueOverflowPolicy::DropClientOnLag,
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
    async fn ipc_server_replies_to_recent_alert_queries() {
        let dir = tempdir().expect("tempdir");
        let server = IpcServer::start(dir.path().join("veriskein.sock"), IpcSettings::default())
            .await
            .expect("start server");
        server.publish_alert(json!({"alert_id":"alert-1","type":"unexpected_shell"}));
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
                encode_ndjson(&IpcFrame::Query(veriskein_ipc::QueryFrame {
                    limit: Some(10),
                    ..veriskein_ipc::QueryFrame::new("q-1", Topic::Alert)
                }))
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
        assert!(reply.ok);
        assert_eq!(reply.items[0]["topic"], "alerts");
        assert_eq!(reply.items[0]["payload"]["alert_id"], "alert-1");
        let cursor = reply.items[0]["cursor"]
            .as_str()
            .expect("cursor")
            .to_string();

        reader
            .get_mut()
            .write_all(
                encode_ndjson(&IpcFrame::Query(veriskein_ipc::QueryFrame {
                    after: Some(cursor),
                    ..veriskein_ipc::QueryFrame::new("q-2", Topic::Alert)
                }))
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
        assert_eq!(reply.query_id, "q-2");
        assert!(reply.ok);
        assert!(reply.items.is_empty());

        server.shutdown().await;
    }

    #[test]
    fn ipc_history_queries_envelope_events_graph_and_metrics() {
        let history = Arc::new(Mutex::new(IpcHistory::new(&QueuePolicy::default())));
        {
            let mut history = history.lock().expect("history");
            history.push_event(IpcFrame::Event(EventFrame::new(
                "evt-1",
                10,
                "proc_exec",
                42,
                Some("session-1".to_string()),
                json!({"argv":["agent"]}),
            )));
            history.push_graph(IpcFrame::Graph(GraphFrame::new(
                11,
                json!({"op":"bind","session_id":"session-1"}),
            )));
            history.set_metrics(IpcFrame::Metrics(MetricsFrame::new(MetricsSnapshot::new(
                12,
            ))));
        }

        let IpcFrame::Reply(events) = query_history(
            &history,
            veriskein_ipc::QueryFrame::new("events", Topic::Events),
        ) else {
            panic!("expected events reply");
        };
        assert!(events.ok);
        assert_eq!(events.items[0]["topic"], "events");
        assert_eq!(events.items[0]["payload"]["event_id"], "evt-1");

        let IpcFrame::Reply(graph) = query_history(
            &history,
            veriskein_ipc::QueryFrame::new("graph", Topic::Graph),
        ) else {
            panic!("expected graph reply");
        };
        assert!(graph.ok);
        assert_eq!(graph.items[0]["topic"], "graph");
        assert_eq!(graph.items[0]["payload"]["op"], "bind");

        let IpcFrame::Reply(metrics) = query_history(
            &history,
            veriskein_ipc::QueryFrame::new("metrics", Topic::Metrics),
        ) else {
            panic!("expected metrics reply");
        };
        assert!(metrics.ok);
        assert_eq!(metrics.items[0]["topic"], "metrics");
        assert_eq!(metrics.items[0]["payload"]["ts_ns"], 12);
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

        let mut first = String::new();
        let mut second = String::new();
        reader.read_line(&mut first).await.expect("read first");
        reader.read_line(&mut second).await.expect("read second");
        let frames = [
            decode_ndjson(&first).expect("decode first"),
            decode_ndjson(&second).expect("decode second"),
        ];
        assert!(
            frames.iter().any(|frame| {
                matches!(frame, IpcFrame::Event(event) if event.event_id == "evt-1")
            })
        );
        assert!(frames.iter().any(|frame| {
            matches!(frame, IpcFrame::Graph(graph) if graph.graph["op"] == "bind")
        }));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn ipc_server_reports_lagged_event_clients() {
        let dir = tempdir().expect("tempdir");
        let server = IpcServer::start(
            dir.path().join("veriskein.sock"),
            IpcSettings {
                queue_policy: QueuePolicy {
                    events_capacity: 1,
                    ..QueuePolicy::default()
                },
                ..IpcSettings::default()
            },
        )
        .await
        .expect("start server");
        let stream = UnixStream::connect(dir.path().join("veriskein.sock"))
            .await
            .expect("connect");
        let mut reader = BufReader::new(stream);
        let mut hello = HelloFrame::new("test-client");
        hello.subscriptions = vec![Topic::Events];
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
        for index in 0..3 {
            server.publish_event(EventFrame::new(
                format!("evt-{index}"),
                index,
                "proc_exec",
                42,
                None,
                json!({"index":index}),
            ));
        }

        let mut dropped = String::new();
        reader.read_line(&mut dropped).await.expect("read dropped");
        let IpcFrame::EventsDropped(dropped) = decode_ndjson(&dropped).expect("decode dropped")
        else {
            panic!("expected events_dropped");
        };
        assert!(dropped.dropped >= 1);

        server.shutdown().await;
    }
}
