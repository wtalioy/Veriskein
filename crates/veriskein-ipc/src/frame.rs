use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use veriskein_proto::defaults;

use crate::{IpcError, IpcResult};

pub const IPC_VERSION: u32 = defaults::IPC_VERSION;
pub const SCHEMA_VERSION: u32 = defaults::IPC_SCHEMA_VERSION;
pub const IPC_ALERTS_QUEUE: usize = defaults::IPC_ALERTS_QUEUE;
pub const IPC_CLIENT_SLOW_TIMEOUT_MS: u64 = defaults::IPC_CLIENT_SLOW_TIMEOUT_MS;
pub const DEFAULT_SOCKET_NAME: &str = "veriskein.sock";

pub fn default_socket_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(DEFAULT_SOCKET_NAME)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Topic {
    #[serde(rename = "hello")]
    Hello,
    #[serde(rename = "welcome")]
    Welcome,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "alerts")]
    Alert,
    #[serde(rename = "metrics")]
    Metrics,
    #[serde(rename = "events")]
    Events,
    #[serde(rename = "graph")]
    Graph,
    #[serde(rename = "query")]
    Query,
    #[serde(rename = "reply")]
    Reply,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcFrame {
    Hello(HelloFrame),
    Welcome(WelcomeFrame),
    Error(ErrorFrame),
    Alert(AlertFrame),
    Metrics(MetricsFrame),
    Event(EventFrame),
    EventsDropped(EventsDroppedFrame),
    Graph(GraphFrame),
    Query(QueryFrame),
    Reply(ReplyFrame),
}

impl IpcFrame {
    pub fn topic(&self) -> Topic {
        match self {
            Self::Hello(_) => Topic::Hello,
            Self::Welcome(_) => Topic::Welcome,
            Self::Error(_) => Topic::Error,
            Self::Alert(_) => Topic::Alert,
            Self::Metrics(_) => Topic::Metrics,
            Self::Event(_) | Self::EventsDropped(_) => Topic::Events,
            Self::Graph(_) => Topic::Graph,
            Self::Query(_) => Topic::Query,
            Self::Reply(_) => Topic::Reply,
        }
    }

    pub fn ipc_version(&self) -> u32 {
        match self {
            Self::Hello(frame) => frame.ipc_version,
            Self::Welcome(frame) => frame.ipc_version,
            Self::Error(frame) => frame.ipc_version,
            Self::Alert(frame) => frame.ipc_version,
            Self::Metrics(frame) => frame.ipc_version,
            Self::Event(frame) => frame.ipc_version,
            Self::EventsDropped(frame) => frame.ipc_version,
            Self::Graph(frame) => frame.ipc_version,
            Self::Query(frame) => frame.ipc_version,
            Self::Reply(frame) => frame.ipc_version,
        }
    }

    pub fn schema_version(&self) -> u32 {
        match self {
            Self::Hello(frame) => frame.schema_version,
            Self::Welcome(frame) => frame.schema_version,
            Self::Error(frame) => frame.schema_version,
            Self::Alert(frame) => frame.schema_version,
            Self::Metrics(frame) => frame.schema_version,
            Self::Event(frame) => frame.schema_version,
            Self::EventsDropped(frame) => frame.schema_version,
            Self::Graph(frame) => frame.schema_version,
            Self::Query(frame) => frame.schema_version,
            Self::Reply(frame) => frame.schema_version,
        }
    }

    pub(crate) fn validate_versions(&self) -> IpcResult<()> {
        validate_versions(self.ipc_version(), self.schema_version())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloFrame {
    #[serde(default = "default_ipc_version")]
    pub ipc_version: u32,
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_client_name")]
    pub client_name: String,
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(rename = "subscribe")]
    #[serde(default = "default_subscriptions")]
    pub subscriptions: Vec<Topic>,
}

impl HelloFrame {
    pub fn new(client_name: impl Into<String>) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            client_name: client_name.into(),
            client_version: None,
            subscriptions: default_subscriptions(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub run_id: String,
    pub schema: BTreeMap<String, u32>,
    pub server_name: String,
    pub server_version: Option<String>,
    pub queue_policy: QueuePolicy,
    pub accepted_topics: Vec<Topic>,
}

impl WelcomeFrame {
    pub fn new(server_name: impl Into<String>) -> Self {
        let mut schema = BTreeMap::new();
        schema.insert("alert".to_string(), SCHEMA_VERSION);
        schema.insert("metrics".to_string(), SCHEMA_VERSION);
        schema.insert("events".to_string(), SCHEMA_VERSION);
        schema.insert("graph".to_string(), SCHEMA_VERSION);
        schema.insert("query".to_string(), SCHEMA_VERSION);
        schema.insert("reply".to_string(), SCHEMA_VERSION);
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            run_id: "unknown".to_string(),
            schema,
            server_name: server_name.into(),
            server_version: None,
            queue_policy: QueuePolicy::default(),
            accepted_topics: vec![
                Topic::Alert,
                Topic::Metrics,
                Topic::Events,
                Topic::Graph,
                Topic::Query,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub code: ErrorCode,
    pub message: String,
    pub expected_ipc_version: Option<u32>,
    pub received_ipc_version: Option<u32>,
    pub expected_schema_version: Option<u32>,
    pub received_schema_version: Option<u32>,
}

impl ErrorFrame {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            code,
            message: message.into(),
            expected_ipc_version: None,
            received_ipc_version: None,
            expected_schema_version: None,
            received_schema_version: None,
        }
    }

    pub fn version_mismatch(received_ipc_version: u32, received_schema_version: u32) -> Self {
        Self {
            expected_ipc_version: Some(IPC_VERSION),
            received_ipc_version: Some(received_ipc_version),
            expected_schema_version: Some(SCHEMA_VERSION),
            received_schema_version: Some(received_schema_version),
            ..Self::new(ErrorCode::VersionMismatch, "IPC protocol version mismatch")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    DecodeError,
    QueueOverflow,
    VersionMismatch,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub alert: Value,
}

impl AlertFrame {
    pub fn new(alert: Value) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            alert,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub metrics: MetricsSnapshot,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub event_id: String,
    pub ts_ns: u64,
    pub event_kind: String,
    pub pid: u32,
    pub session_id: Option<String>,
    pub event: Value,
}

impl EventFrame {
    pub fn new(
        event_id: impl Into<String>,
        ts_ns: u64,
        event_kind: impl Into<String>,
        pid: u32,
        session_id: Option<String>,
        event: Value,
    ) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            event_id: event_id.into(),
            ts_ns,
            event_kind: event_kind.into(),
            pid,
            session_id,
            event,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventsDroppedFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub ts_ns: u64,
    pub dropped: u64,
    pub reason: String,
}

impl EventsDroppedFrame {
    pub fn new(ts_ns: u64, dropped: u64, reason: impl Into<String>) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            ts_ns,
            dropped,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub ts_ns: u64,
    pub graph: Value,
}

impl GraphFrame {
    pub fn new(ts_ns: u64, graph: Value) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            ts_ns,
            graph,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub query_id: String,
    pub topic: Topic,
    pub after: Option<String>,
    pub limit: Option<usize>,
}

impl QueryFrame {
    pub fn new(query_id: impl Into<String>, topic: Topic) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            query_id: query_id.into(),
            topic,
            after: None,
            limit: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplyFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub query_id: String,
    pub topic: Topic,
    pub ok: bool,
    pub items: Vec<Value>,
    pub error: Option<String>,
}

impl ReplyFrame {
    pub fn ok(query_id: impl Into<String>, topic: Topic, items: Vec<Value>) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            query_id: query_id.into(),
            topic,
            ok: true,
            items,
            error: None,
        }
    }

    pub fn error(query_id: impl Into<String>, topic: Topic, message: impl Into<String>) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            query_id: query_id.into(),
            topic,
            ok: false,
            items: Vec::new(),
            error: Some(message.into()),
        }
    }
}

impl MetricsFrame {
    pub fn new(metrics: MetricsSnapshot) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            metrics,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub ts_ns: u64,
    pub counters: BTreeMap<String, u64>,
    pub gauges: BTreeMap<String, f64>,
    pub queue_depths: QueueDepths,
}

impl MetricsSnapshot {
    pub fn new(ts_ns: u64) -> Self {
        Self {
            ts_ns,
            counters: BTreeMap::new(),
            gauges: BTreeMap::new(),
            queue_depths: QueueDepths::default(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueDepths {
    pub alerts: usize,
    pub events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuePolicy {
    pub alerts_capacity: usize,
    pub client_slow_timeout_ms: u64,
    pub alerts_overflow: QueueOverflowPolicy,
}

impl Default for QueuePolicy {
    fn default() -> Self {
        Self {
            alerts_capacity: IPC_ALERTS_QUEUE,
            client_slow_timeout_ms: IPC_CLIENT_SLOW_TIMEOUT_MS,
            alerts_overflow: QueueOverflowPolicy::DropClientOnLag,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueOverflowPolicy {
    DropClientOnLag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMismatch {
    pub expected_ipc_version: u32,
    pub received_ipc_version: u32,
    pub expected_schema_version: u32,
    pub received_schema_version: u32,
}

fn default_ipc_version() -> u32 {
    IPC_VERSION
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

fn default_client_name() -> String {
    "unknown".to_string()
}

fn default_subscriptions() -> Vec<Topic> {
    vec![Topic::Alert, Topic::Metrics]
}

fn validate_versions(ipc_version: u32, schema_version: u32) -> IpcResult<()> {
    if ipc_version == IPC_VERSION && schema_version == SCHEMA_VERSION {
        return Ok(());
    }
    Err(IpcError::from(VersionMismatch {
        expected_ipc_version: IPC_VERSION,
        received_ipc_version: ipc_version,
        expected_schema_version: SCHEMA_VERSION,
        received_schema_version: schema_version,
    }))
}
