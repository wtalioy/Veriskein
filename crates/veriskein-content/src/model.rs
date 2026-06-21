use serde::{Deserialize, Serialize};
use veriskein_proto::{
    AgentId, ContentChannel, ContentDirection, EventId, SessionId, VisibilityState,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamOwner {
    pub session_id: Option<SessionId>,
    pub agent_id: Option<AgentId>,
}

impl StreamOwner {
    pub fn new(session_id: Option<SessionId>, agent_id: Option<AgentId>) -> Self {
        Self {
            session_id,
            agent_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamProvenance {
    pub channel: ContentChannel,
    pub direction: ContentDirection,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsStreamKey {
    pub pid: u32,
    pub ssl_ctx: u64,
    pub direction: ContentDirection,
}

impl TlsStreamKey {
    pub fn new(pid: u32, ssl_ctx: u64, direction: ContentDirection) -> Self {
        Self {
            pid,
            ssl_ctx,
            direction,
        }
    }

    pub fn stream_id(self) -> u64 {
        let id = EventId::from_seed(
            format!("{}:{}:{}", self.pid, self.ssl_ctx, self.direction.as_str()).as_bytes(),
        );
        let hex = id.hex();
        u64::from_str_radix(&hex[..16], 16).unwrap_or(self.pid as u64 ^ self.ssl_ctx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentFragment {
    pub stream_id: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub owner: StreamOwner,
    pub provenance: StreamProvenance,
    pub degradation_reasons: Vec<String>,
}

impl ContentFragment {
    pub fn with_degradation(
        stream_id: u64,
        offset: u64,
        bytes: impl Into<Vec<u8>>,
        owner: StreamOwner,
        provenance: StreamProvenance,
        degradation_reasons: Vec<String>,
    ) -> Self {
        Self {
            stream_id,
            offset,
            bytes: bytes.into(),
            owner,
            provenance,
            degradation_reasons,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedPrompt {
    pub stream_id: u64,
    pub owner: StreamOwner,
    pub provenance: StreamProvenance,
    pub text: String,
    pub visibility: VisibilityState,
    pub degradation_reasons: Vec<String>,
}

impl ExtractedPrompt {
    pub(crate) fn new(
        stream_id: u64,
        owner: StreamOwner,
        provenance: StreamProvenance,
        text: String,
        visibility: VisibilityState,
        degradation_reasons: Vec<String>,
    ) -> Self {
        Self {
            stream_id,
            owner,
            provenance,
            text,
            visibility,
            degradation_reasons,
        }
    }
}
