use serde::Serialize;
use veriskein_normalizer::NormalizedEvent;
pub use veriskein_proto::VisibilityState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PromptEvidenceState {
    Available,
    Partial,
    Unavailable,
}

impl PromptEvidenceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FindingType {
    UnexpectedShell,
    SensitiveFileAccess,
    OutOfWorkspaceDeletion,
    SingleAgentDeadloop,
    CrossAgentPromptInjection,
    ExecObserved,
}

impl FindingType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedShell => "unexpected_shell",
            Self::SensitiveFileAccess => "sensitive_file_access",
            Self::OutOfWorkspaceDeletion => "out_of_workspace_deletion",
            Self::SingleAgentDeadloop => "single_agent_deadloop",
            Self::CrossAgentPromptInjection => "cross_agent_prompt_injection",
            Self::ExecObserved => "exec_observed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingHealth {
    pub visibility_state: VisibilityState,
    pub prompt_evidence_state: PromptEvidenceState,
    pub degradation_sources: Vec<String>,
    pub capture_lag_ms: Option<u64>,
}

impl FindingHealth {
    pub fn full() -> Self {
        Self {
            visibility_state: VisibilityState::Full,
            prompt_evidence_state: PromptEvidenceState::Unavailable,
            degradation_sources: Vec::new(),
            capture_lag_ms: None,
        }
    }

    pub fn push_degradation_source(&mut self, source: impl Into<String>) {
        let source = source.into();
        if !self
            .degradation_sources
            .iter()
            .any(|existing| existing == &source)
        {
            self.degradation_sources.push(source);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct FindingObjects {
    pub paths: Vec<String>,
    pub ips: Vec<String>,
    pub ports: Vec<u16>,
    pub prompt_ids: Vec<String>,
    pub artifact_ids: Vec<String>,
    pub event_ids: Vec<String>,
    pub chain_id: Option<String>,
    pub workspace_id: Option<String>,
    pub root_session_id: Option<String>,
    pub downstream_session_id: Option<String>,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingEvidence {
    pub kind: &'static str,
    pub event_id: String,
    pub ingest_seq: u64,
    pub path: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub score: Option<f32>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub op: Option<String>,
    pub note: Option<String>,
}

impl FindingEvidence {
    pub(crate) fn path_event(
        kind: &'static str,
        event: &NormalizedEvent,
        path: String,
        note: Option<String>,
    ) -> Self {
        Self::for_event(kind, event, Some(path), None, None, note)
    }

    pub(crate) fn net_connect(
        event_id: String,
        ingest_seq: u64,
        ip: Option<String>,
        port: Option<u16>,
    ) -> Self {
        Self {
            kind: "net_connect",
            event_id,
            ingest_seq,
            path: None,
            ip,
            port,
            score: None,
            src: None,
            dst: None,
            op: None,
            note: None,
        }
    }

    pub(crate) fn file_access_ref(event_id: String, ingest_seq: u64, path: Option<String>) -> Self {
        Self {
            kind: "file_access",
            event_id,
            ingest_seq,
            path,
            ip: None,
            port: None,
            score: None,
            src: None,
            dst: None,
            op: None,
            note: None,
        }
    }

    pub(crate) fn prompt_ref(prompt_id: String, ingest_seq: u64, note: Option<String>) -> Self {
        Self {
            kind: "prompt_ref",
            event_id: prompt_id,
            ingest_seq,
            path: None,
            ip: None,
            port: None,
            score: None,
            src: None,
            dst: None,
            op: None,
            note,
        }
    }

    pub fn chain_ref(
        kind: &'static str,
        chain_id: String,
        score: Option<f32>,
        src: Option<String>,
        dst: Option<String>,
        note: Option<String>,
    ) -> Self {
        Self {
            kind,
            event_id: chain_id,
            ingest_seq: 0,
            path: None,
            ip: None,
            port: None,
            score,
            src,
            dst,
            op: None,
            note,
        }
    }

    pub fn capture_health(event: &NormalizedEvent, note: String) -> Self {
        Self::for_event("capture_health", event, None, None, None, Some(note))
    }

    fn for_event(
        kind: &'static str,
        event: &NormalizedEvent,
        path: Option<String>,
        ip: Option<String>,
        port: Option<u16>,
        note: Option<String>,
    ) -> Self {
        Self {
            kind,
            event_id: event.event_id.clone(),
            ingest_seq: event.ingest_seq,
            path,
            ip,
            port,
            score: None,
            src: None,
            dst: None,
            op: None,
            note,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub finding_type: FindingType,
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub session_id: String,
    pub agent_id: Option<String>,
    pub reason_code: &'static str,
    pub summary: String,
    pub process_comm: String,
    pub process_binary: String,
    pub workspace: String,
    pub objects: FindingObjects,
    pub evidence: Vec<FindingEvidence>,
    pub health: FindingHealth,
    pub component_scores: std::collections::BTreeMap<&'static str, f32>,
    pub explanation: Option<String>,
}
