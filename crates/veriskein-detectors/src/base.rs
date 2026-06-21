use std::collections::BTreeMap;
use veriskein_graph::{Attribution, GraphState};
use veriskein_normalizer::{NormalizedData, NormalizedEvent, PathResolutionMode, path_basename};

use crate::finding::{Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType};
use crate::signals::DetectorSignal;

pub(crate) fn detect_unexpected_shell(
    event: &NormalizedEvent,
    graph: &GraphState,
    binding: &Attribution,
) -> Option<Finding> {
    let (filename, argv) = match &event.data {
        NormalizedData::ProcExec { filename, argv } => (filename, argv),
        _ => return None,
    };
    let shell_name = path_basename(filename);
    if !matches!(shell_name, "sh" | "bash" | "zsh" | "dash" | "fish") {
        return None;
    }
    if allowlisted(graph.shell_allowlist(), filename)
        || allowlisted(graph.shell_allowlist(), shell_name)
    {
        return None;
    }
    Some(path_finding(
        event,
        binding,
        PathFindingInput {
            finding_type: FindingType::UnexpectedShell,
            reason_code: "shell_exec_unapproved",
            summary: format!("session spawned unexpected shell {filename}"),
            path: filename.clone(),
            argv: argv.clone(),
            evidence_kind: "syscall",
            evidence_note: None,
        },
    ))
}

pub(crate) fn detect_sensitive_file_access(
    event: &NormalizedEvent,
    graph: &GraphState,
    binding: &Attribution,
    signals: &[DetectorSignal],
) -> Option<Finding> {
    let (path_ctx, ret_fd) = match &event.data {
        NormalizedData::FileOpen { path, ret_fd, .. } => (path, *ret_fd),
        _ => return None,
    };
    let (path, note) = signals.iter().find_map(|signal| match signal {
        DetectorSignal::SensitivePathHit(hit) => Some((&hit.path, &hit.note)),
        _ => None,
    })?;
    if allowlisted(graph.sensitive_allowlist(), path) {
        return None;
    }
    let (reason_code, summary) = if ret_fd >= 0 {
        (
            if path_ctx.resolution.mode == PathResolutionMode::Canonicalized {
                "sensitive_file_open"
            } else {
                "sensitive_file_open_lexical"
            },
            format!("session opened sensitive path {path}"),
        )
    } else {
        (
            "sensitive_file_open_denied",
            format!("session attempted sensitive path {path}"),
        )
    };
    Some(path_finding(
        event,
        binding,
        PathFindingInput {
            finding_type: FindingType::SensitiveFileAccess,
            reason_code,
            summary,
            path: path.clone(),
            argv: event.process.argv.clone(),
            evidence_kind: "file_access",
            evidence_note: note.clone(),
        },
    ))
}

pub(crate) fn detect_out_of_workspace_deletion(
    event: &NormalizedEvent,
    graph: &GraphState,
    binding: &Attribution,
    signals: &[DetectorSignal],
) -> Option<Finding> {
    let mutation = signals.iter().find_map(|signal| match signal {
        DetectorSignal::OutOfWorkspaceMutation(mutation) => Some(mutation),
        _ => None,
    })?;
    let path = &mutation.path;
    let reason_code = mutation.reason_code;
    let note = &mutation.note;
    if event.process.exe.is_empty() || allowlisted(graph.delete_allowlist(), path) {
        return None;
    }
    let summary = match reason_code {
        "rename_outside_workspace" => format!("session moved path outside workspace {path}"),
        _ => format!("session deleted path outside workspace {path}"),
    };
    Some(path_finding(
        event,
        binding,
        PathFindingInput {
            finding_type: FindingType::OutOfWorkspaceDeletion,
            reason_code,
            summary,
            path: path.clone(),
            argv: event.process.argv.clone(),
            evidence_kind: "syscall",
            evidence_note: note.clone(),
        },
    ))
}

pub(crate) fn detect_exec_observed(
    event: &NormalizedEvent,
    binding: &Attribution,
) -> Option<Finding> {
    let (filename, argv) = match &event.data {
        NormalizedData::ProcExec { filename, argv } => (filename, argv),
        _ => return None,
    };
    Some(path_finding(
        event,
        binding,
        PathFindingInput {
            finding_type: FindingType::ExecObserved,
            reason_code: "exec_observed",
            summary: format!("session executed {filename}"),
            path: filename.clone(),
            argv: argv.clone(),
            evidence_kind: "syscall",
            evidence_note: None,
        },
    ))
}

fn allowlisted(globs: &veriskein_normalizer::GlobList, value: &str) -> bool {
    globs.is_match(value)
}

struct PathFindingInput {
    finding_type: FindingType,
    reason_code: &'static str,
    path: String,
    argv: Vec<String>,
    evidence_kind: &'static str,
    evidence_note: Option<String>,
    summary: String,
}

fn path_finding(
    event: &NormalizedEvent,
    binding: &Attribution,
    input: PathFindingInput,
) -> Finding {
    Finding {
        finding_type: input.finding_type,
        ts_ns: event.ts_ns,
        pid: event.process.pid,
        tid: event.process.tid,
        session_id: binding.session_id.hex(),
        agent_id: Some(binding.agent_id.hex()),
        reason_code: input.reason_code,
        summary: input.summary,
        process_comm: event.process.comm.clone(),
        process_binary: event.process.exe.clone(),
        workspace: binding.workspace.root.display().to_string(),
        objects: FindingObjects {
            paths: vec![input.path.clone()],
            ips: Vec::new(),
            ports: Vec::new(),
            event_ids: vec![event.event_id.clone()],
            argv: input.argv,
        },
        evidence: vec![FindingEvidence::path_event(
            input.evidence_kind,
            event,
            input.path,
            input.evidence_note,
        )],
        health: FindingHealth::full(),
        component_scores: BTreeMap::new(),
    }
}
