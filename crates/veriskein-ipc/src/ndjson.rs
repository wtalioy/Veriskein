use thiserror::Error;

use crate::{IpcFrame, VersionMismatch};

pub type IpcResult<T> = Result<T, IpcError>;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("empty IPC frame line")]
    EmptyLine,
    #[error("IPC frames must be encoded as one NDJSON line")]
    MultilineFrame,
    #[error(
        "IPC version mismatch: expected ipc/schema {expected_ipc_version}/{expected_schema_version}, received {received_ipc_version}/{received_schema_version}"
    )]
    VersionMismatch {
        expected_ipc_version: u32,
        received_ipc_version: u32,
        expected_schema_version: u32,
        received_schema_version: u32,
    },
    #[error("JSON IPC frame error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<VersionMismatch> for IpcError {
    fn from(mismatch: VersionMismatch) -> Self {
        Self::VersionMismatch {
            expected_ipc_version: mismatch.expected_ipc_version,
            received_ipc_version: mismatch.received_ipc_version,
            expected_schema_version: mismatch.expected_schema_version,
            received_schema_version: mismatch.received_schema_version,
        }
    }
}

pub fn encode_ndjson(frame: &IpcFrame) -> IpcResult<String> {
    frame.validate_versions()?;
    let mut line = serde_json::to_string(frame)?;
    line.push('\n');
    Ok(line)
}

pub fn encode_ndjson_frame(frame: &IpcFrame) -> IpcResult<String> {
    encode_ndjson(frame)
}

pub fn decode_ndjson(line: &str) -> IpcResult<IpcFrame> {
    let line = normalize_ndjson_line(line)?;
    let frame: IpcFrame = serde_json::from_str(line)?;
    frame.validate_versions()?;
    Ok(frame)
}

pub fn decode_ndjson_frame(line: &str) -> IpcResult<IpcFrame> {
    decode_ndjson(line)
}

fn normalize_ndjson_line(line: &str) -> IpcResult<&str> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Err(IpcError::EmptyLine);
    }
    if line.contains(['\n', '\r']) {
        return Err(IpcError::MultilineFrame);
    }
    Ok(line)
}
