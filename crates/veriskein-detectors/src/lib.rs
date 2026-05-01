//! Phase 1 detector findings.

use std::path::Path;

use serde::Serialize;
use veriskein_graph::{Attribution, GraphState};
use veriskein_normalizer::{NormalizedData, NormalizedEvent, PathContext, PathResolutionMode};

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

pub fn detect(event: &NormalizedEvent, graph: &GraphState, dry_run_exec_observed: bool) -> Vec<Finding> {
    let binding = graph.resolve(event.process.pid);
    let mut out = Vec::new();
    if let Some(finding) = detect_unexpected_shell(event, graph, binding) {
        out.push(finding);
    }
    if let Some(finding) = detect_sensitive_file_access(event, graph, binding) {
        out.push(finding);
    }
    if let Some(finding) = detect_out_of_workspace_deletion(event, graph, binding) {
        out.push(finding);
    }
    if out.is_empty() && dry_run_exec_observed {
        if let Some(finding) = detect_exec_observed(event, binding) {
            out.push(finding);
        }
    }
    out
}

fn detect_unexpected_shell(
    event: &NormalizedEvent,
    graph: &GraphState,
    binding: Option<&Attribution>,
) -> Option<Finding> {
    let binding = binding?;
    let (filename, argv) = match &event.data {
        NormalizedData::ProcExec { filename, argv } => (filename, argv),
        _ => return None,
    };
    let shell_name = Path::new(filename)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(filename);
    if !matches!(shell_name, "sh" | "bash" | "zsh" | "dash" | "fish") {
        return None;
    }
    if graph
        .shell_allowlist()
        .is_match(filename)
        || graph.shell_allowlist().is_match(shell_name)
    {
        return None;
    }
    Some(base_finding(
        event,
        binding,
        FindingType::UnexpectedShell,
        "shell_exec_unapproved",
        format!("session spawned unexpected shell {filename}"),
        vec![filename.clone()],
        argv.clone(),
        "syscall",
        Some(filename.clone()),
        None,
    ))
}

fn detect_sensitive_file_access(
    event: &NormalizedEvent,
    graph: &GraphState,
    binding: Option<&Attribution>,
) -> Option<Finding> {
    let binding = binding?;
    let (path_ctx, ret_fd) = match &event.data {
        NormalizedData::FileOpen { path, ret_fd } => (path, *ret_fd),
        _ => return None,
    };
    if ret_fd < 0 || path_ctx.sensitive_rule.is_none() {
        return None;
    }
    let path = preferred_path(path_ctx);
    if graph.sensitive_allowlist().is_match(&path) {
        return None;
    }
    Some(base_finding(
        event,
        binding,
        FindingType::SensitiveFileAccess,
        if path_ctx.resolution.mode == PathResolutionMode::Canonicalized {
            "sensitive_file_open"
        } else {
            "sensitive_file_open_lexical"
        },
        format!("session opened sensitive path {path}"),
        vec![path.clone()],
        event.process.argv.clone(),
        "file_access",
        Some(path),
        note_for_path(path_ctx),
    ))
}

fn detect_out_of_workspace_deletion(
    event: &NormalizedEvent,
    graph: &GraphState,
    binding: Option<&Attribution>,
) -> Option<Finding> {
    let binding = binding?;
    match &event.data {
        NormalizedData::FileUnlink { path } => {
            let preferred = preferred_path(path);
            if event.process.exe.is_empty()
                || path.workspace.is_some()
                || graph.delete_allowlist().is_match(&preferred)
            {
                return None;
            }
            Some(base_finding(
                event,
                binding,
                FindingType::OutOfWorkspaceDeletion,
                "unlink_outside_workspace",
                format!("session deleted path outside workspace {preferred}"),
                vec![preferred.clone()],
                event.process.argv.clone(),
                "syscall",
                Some(preferred),
                note_for_path(path),
            ))
        }
        NormalizedData::FileRename { new_path, .. } => {
            let preferred = preferred_path(new_path);
            if new_path.workspace.is_some()
                || graph.delete_allowlist().is_match(&preferred)
            {
                return None;
            }
            Some(base_finding(
                event,
                binding,
                FindingType::OutOfWorkspaceDeletion,
                "rename_outside_workspace",
                format!("session moved path outside workspace {preferred}"),
                vec![preferred.clone()],
                event.process.argv.clone(),
                "syscall",
                Some(preferred),
                note_for_path(new_path),
            ))
        }
        _ => None,
    }
}

fn detect_exec_observed(event: &NormalizedEvent, binding: Option<&Attribution>) -> Option<Finding> {
    let binding = binding?;
    let (filename, argv) = match &event.data {
        NormalizedData::ProcExec { filename, argv } => (filename, argv),
        _ => return None,
    };
    Some(base_finding(
        event,
        binding,
        FindingType::ExecObserved,
        "exec_observed",
        format!("session executed {filename}"),
        vec![filename.clone()],
        argv.clone(),
        "syscall",
        Some(filename.clone()),
        None,
    ))
}

fn base_finding(
    event: &NormalizedEvent,
    binding: &Attribution,
    finding_type: FindingType,
    reason_code: &'static str,
    summary: String,
    paths: Vec<String>,
    argv: Vec<String>,
    evidence_kind: &'static str,
    evidence_path: Option<String>,
    evidence_note: Option<String>,
) -> Finding {
    Finding {
        finding_type,
        ts_ns: event.ts_ns,
        pid: event.process.pid,
        tid: event.process.tid,
        session_id: binding.session_id.hex(),
        agent_id: Some(binding.agent_id.hex()),
        reason_code,
        summary,
        process_comm: event.process.comm.clone(),
        process_binary: event.process.exe.clone(),
        workspace: binding.workspace.root.display().to_string(),
        objects: FindingObjects {
            paths,
            event_ids: vec![event.event_id.clone()],
            argv,
        },
        evidence: vec![FindingEvidence {
            kind: evidence_kind,
            event_id: event.event_id.clone(),
            ingest_seq: event.ingest_seq,
            path: evidence_path,
            note: evidence_note,
        }],
        health: FindingHealth {
            visibility_state: VisibilityState::Full,
        },
    }
}

fn preferred_path(path: &PathContext) -> String {
    path.resolution
        .canonical
        .as_ref()
        .unwrap_or(&path.resolution.lexical)
        .display()
        .to_string()
}

fn note_for_path(path: &PathContext) -> Option<String> {
    if path.resolution.mode == PathResolutionMode::LexicalOnly {
        Some("lexical_only".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use veriskein_graph::{AgentConfig, GraphState};
    use veriskein_normalizer::{
        NormalizedData, NormalizedEvent, PathContext, PathResolution, PathResolutionMode,
        PathVerdict, ProcessSnapshot, WorkspaceRef,
    };
    use veriskein_proto::EventKind;

    use super::{FindingType, detect};

    fn graph() -> GraphState {
        let mut graph = GraphState::new(AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: vec!["/tmp/allowed.txt".to_string()],
        }, vec![WorkspaceRef { id: "ws".to_string(), root: "/tmp/ws".into() }]).expect("graph");
        let exec = NormalizedEvent {
            ingest_seq: 1,
            event_id: "seed".to_string(),
            ts_ns: 1,
            kind: EventKind::ProcExec,
            process: ProcessSnapshot {
                pid: 10,
                tid: 10,
                ppid: 1,
                exe: "/usr/bin/claude".to_string(),
                comm: "claude".to_string(),
                argv: vec!["claude".to_string()],
                cwd: "/tmp/ws".into(),
            },
            data: NormalizedData::ProcExec {
                filename: "/usr/bin/claude".to_string(),
                argv: vec!["claude".to_string()],
            },
        };
        graph.apply(&exec);
        graph
    }

    fn path_context(path: &str, workspace: Option<&str>, sensitive: bool) -> PathContext {
        PathContext {
            resolution: PathResolution {
                lexical: path.into(),
                canonical: Some(path.into()),
                mode: PathResolutionMode::Canonicalized,
                verdict: PathVerdict::CanonicalTrusted,
                freshness_ns: 1,
            },
            workspace: workspace.map(|root| WorkspaceRef {
                id: "ws".to_string(),
                root: root.into(),
            }),
            sensitive_rule: sensitive.then(|| path.to_string()),
            sensitive_severity: sensitive.then(|| "high".to_string()),
        }
    }

    #[test]
    fn unexpected_shell_fires() {
        let graph = graph();
        let event = NormalizedEvent {
            ingest_seq: 2,
            event_id: "shell".to_string(),
            ts_ns: 2,
            kind: EventKind::ProcExec,
            process: ProcessSnapshot {
                pid: 10,
                tid: 10,
                ppid: 1,
                exe: "/bin/sh".to_string(),
                comm: "sh".to_string(),
                argv: vec!["sh".to_string()],
                cwd: "/tmp/ws".into(),
            },
            data: NormalizedData::ProcExec {
                filename: "/bin/sh".to_string(),
                argv: vec!["sh".to_string()],
            },
        };
        let findings = detect(&event, &graph, false);
        assert_eq!(findings[0].finding_type, FindingType::UnexpectedShell);
    }

    #[test]
    fn sensitive_access_fires() {
        let graph = graph();
        let event = NormalizedEvent {
            ingest_seq: 2,
            event_id: "open".to_string(),
            ts_ns: 2,
            kind: EventKind::FileOpen,
            process: ProcessSnapshot {
                pid: 10,
                tid: 10,
                ppid: 1,
                exe: "/usr/bin/claude".to_string(),
                comm: "claude".to_string(),
                argv: vec!["claude".to_string()],
                cwd: "/tmp/ws".into(),
            },
            data: NormalizedData::FileOpen {
                ret_fd: 3,
                path: path_context("/etc/shadow", None, true),
            },
        };
        let findings = detect(&event, &graph, false);
        assert_eq!(findings[0].finding_type, FindingType::SensitiveFileAccess);
    }

    #[test]
    fn benign_shell_negative_when_not_in_session() {
        let graph = GraphState::new(AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: Vec::new(),
        }, vec![WorkspaceRef { id: "ws".to_string(), root: "/tmp/ws".into() }]).expect("graph");
        let event = NormalizedEvent {
            ingest_seq: 2,
            event_id: "shell".to_string(),
            ts_ns: 2,
            kind: EventKind::ProcExec,
            process: ProcessSnapshot {
                pid: 99,
                tid: 99,
                ppid: 1,
                exe: "/bin/bash".to_string(),
                comm: "bash".to_string(),
                argv: vec!["bash".to_string()],
                cwd: "/tmp".into(),
            },
            data: NormalizedData::ProcExec {
                filename: "/bin/bash".to_string(),
                argv: vec!["bash".to_string()],
            },
        };
        assert!(detect(&event, &graph, false).is_empty());
    }

    #[test]
    fn delete_allowlist_uses_glob() {
        let mut graph = GraphState::new(AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: vec!["/tmp/**".to_string()],
        }, vec![WorkspaceRef { id: "ws".to_string(), root: "/tmp/ws".into() }]).expect("graph");
        let exec = NormalizedEvent {
            ingest_seq: 1,
            event_id: "seed".to_string(),
            ts_ns: 1,
            kind: EventKind::ProcExec,
            process: ProcessSnapshot {
                pid: 11,
                tid: 11,
                ppid: 1,
                exe: "/usr/bin/claude".to_string(),
                comm: "claude".to_string(),
                argv: vec!["claude".to_string()],
                cwd: "/tmp/ws".into(),
            },
            data: NormalizedData::ProcExec {
                filename: "/usr/bin/claude".to_string(),
                argv: vec!["claude".to_string()],
            },
        };
        graph.apply(&exec);
        let event = NormalizedEvent {
            ingest_seq: 2,
            event_id: "unlink".to_string(),
            ts_ns: 2,
            kind: EventKind::FileUnlink,
            process: ProcessSnapshot {
                pid: 11,
                tid: 11,
                ppid: 1,
                exe: "/usr/bin/claude".to_string(),
                comm: "claude".to_string(),
                argv: vec!["claude".to_string()],
                cwd: "/tmp/ws".into(),
            },
            data: NormalizedData::FileUnlink {
                path: path_context("/tmp/allowed/file.txt", None, false),
            },
        };
        assert!(detect(&event, &graph, false).is_empty());
    }
}
