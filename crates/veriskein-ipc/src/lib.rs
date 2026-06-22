//! Public local IPC protocol frames.
//!
//! This crate owns the serde-compatible wire shapes used for daemon/client
//! IPC. It intentionally carries alert payloads as JSON values so the protocol
//! crate does not need to depend on detector or alert projection internals.

mod frame;
mod ndjson;

#[cfg(test)]
mod tests;

pub use frame::{
    AlertFrame, DEFAULT_SOCKET_NAME, ErrorCode, ErrorFrame, HelloFrame, IPC_ALERTS_QUEUE,
    IPC_CLIENT_SLOW_TIMEOUT_MS, IPC_EVENTS_QUEUE, IPC_GRAPH_QUEUE, IPC_VERSION, IpcFrame,
    MetricsFrame, MetricsSnapshot, QueueDepths, QueuePolicy, SCHEMA_VERSION, Topic,
    VersionMismatch, WelcomeFrame, default_socket_path, validate_versions,
};
pub use ndjson::{
    IpcError, IpcResult, decode_ndjson, decode_ndjson_frame, encode_ndjson, encode_ndjson_frame,
};
