use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FindingType {
    UnexpectedShell,
    SensitiveFileAccess,
    OutOfWorkspaceDeletion,
    ExecObserved,
}

impl FindingType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedShell => "unexpected_shell",
            Self::SensitiveFileAccess => "sensitive_file_access",
            Self::OutOfWorkspaceDeletion => "out_of_workspace_deletion",
            Self::ExecObserved => "exec_observed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VisibilityState {
    Full,
    Partial,
    Unsupported,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingHealth {
    pub visibility_state: VisibilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingObjects {
    pub paths: Vec<String>,
    pub event_ids: Vec<String>,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingEvidence {
    pub kind: &'static str,
    pub event_id: String,
    pub ingest_seq: u64,
    pub path: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
}
