use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use veriskein_proto::defaults;

use crate::{IpcError, IpcResult};

pub const IPC_VERSION: u32 = defaults::IPC_VERSION;
pub const SCHEMA_VERSION: u32 = defaults::IPC_SCHEMA_VERSION;
pub const IPC_EVENTS_QUEUE: usize = defaults::IPC_EVENTS_QUEUE;
pub const IPC_ALERTS_QUEUE: usize = defaults::IPC_ALERTS_QUEUE;
pub const IPC_GRAPH_QUEUE: usize = defaults::IPC_GRAPH_QUEUE;
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcFrame {
    Hello(HelloFrame),
    Welcome(WelcomeFrame),
    Error(ErrorFrame),
    Alert(AlertFrame),
    Metrics(MetricsFrame),
}

impl IpcFrame {
    pub fn topic(&self) -> Topic {
        match self {
            Self::Hello(_) => Topic::Hello,
            Self::Welcome(_) => Topic::Welcome,
            Self::Error(_) => Topic::Error,
            Self::Alert(_) => Topic::Alert,
            Self::Metrics(_) => Topic::Metrics,
        }
    }

    pub fn ipc_version(&self) -> u32 {
        match self {
            Self::Hello(frame) => frame.ipc_version,
            Self::Welcome(frame) => frame.ipc_version,
            Self::Error(frame) => frame.ipc_version,
            Self::Alert(frame) => frame.ipc_version,
            Self::Metrics(frame) => frame.ipc_version,
        }
    }

    pub fn schema_version(&self) -> u32 {
        match self {
            Self::Hello(frame) => frame.schema_version,
            Self::Welcome(frame) => frame.schema_version,
            Self::Error(frame) => frame.schema_version,
            Self::Alert(frame) => frame.schema_version,
            Self::Metrics(frame) => frame.schema_version,
        }
    }

    pub fn validate_versions(&self) -> IpcResult<()> {
        validate_versions(self.ipc_version(), self.schema_version())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloFrame {
    pub ipc_version: u32,
    pub schema_version: u32,
    pub client_name: String,
    pub client_version: Option<String>,
    #[serde(rename = "subscribe")]
    pub subscriptions: Vec<Topic>,
}

impl HelloFrame {
    pub fn new(client_name: impl Into<String>) -> Self {
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            client_name: client_name.into(),
            client_version: None,
            subscriptions: vec![Topic::Alert, Topic::Metrics],
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
        Self {
            ipc_version: IPC_VERSION,
            schema_version: SCHEMA_VERSION,
            run_id: "unknown".to_string(),
            schema,
            server_name: server_name.into(),
            server_version: None,
            queue_policy: QueuePolicy::default(),
            accepted_topics: vec![Topic::Alert, Topic::Metrics],
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
    Internal,
    QueueOverflow,
    SlowClient,
    UnsupportedTopic,
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
    pub events: usize,
    pub alerts: usize,
    pub graph: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuePolicy {
    pub events_capacity: usize,
    pub alerts_capacity: usize,
    pub graph_capacity: usize,
    pub client_slow_timeout_ms: u64,
}

impl Default for QueuePolicy {
    fn default() -> Self {
        Self {
            events_capacity: IPC_EVENTS_QUEUE,
            alerts_capacity: IPC_ALERTS_QUEUE,
            graph_capacity: IPC_GRAPH_QUEUE,
            client_slow_timeout_ms: IPC_CLIENT_SLOW_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMismatch {
    pub expected_ipc_version: u32,
    pub received_ipc_version: u32,
    pub expected_schema_version: u32,
    pub received_schema_version: u32,
}

pub fn validate_versions(ipc_version: u32, schema_version: u32) -> IpcResult<()> {
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
