use std::path::Path;

use veriskein_graph::{Attribution, GraphState};
use veriskein_normalizer::{NormalizedData, NormalizedEvent, PathContext, PathResolutionMode};

use crate::finding::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, VisibilityState,
};

pub fn detect(
    event: &NormalizedEvent,
    graph: &GraphState,
    dry_run_exec_observed: bool,
) -> Vec<Finding> {
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
    let binding = session_binding(binding)?;
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
    if allowlisted(graph.shell_allowlist(), filename)
        || allowlisted(graph.shell_allowlist(), shell_name)
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
    let binding = session_binding(binding)?;
    let (path_ctx, ret_fd) = match &event.data {
        NormalizedData::FileOpen { path, ret_fd } => (path, *ret_fd),
        _ => return None,
    };
    if path_ctx.sensitive_rule.is_none() {
        return None;
    }
    let path = preferred_path(path_ctx);
    if allowlisted(graph.sensitive_allowlist(), &path) {
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
    Some(base_finding(
        event,
        binding,
        FindingType::SensitiveFileAccess,
        reason_code,
        summary,
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
    let binding = session_binding(binding)?;
    match &event.data {
        NormalizedData::FileUnlink { unlink_ret, path } => {
            if *unlink_ret != 0 {
                return None;
            }
            let preferred = preferred_path(path);
            if event.process.exe.is_empty()
                || path.workspace.is_some()
                || allowlisted(graph.delete_allowlist(), &preferred)
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
        NormalizedData::FileRename {
            rename_ret,
            new_path,
            ..
        } => {
            if *rename_ret != 0 {
                return None;
            }
            let preferred = preferred_path(new_path);
            if new_path.workspace.is_some() || allowlisted(graph.delete_allowlist(), &preferred) {
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
    let binding = session_binding(binding)?;
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

fn session_binding(binding: Option<&Attribution>) -> Option<&Attribution> {
    binding
}

fn allowlisted(globs: &veriskein_normalizer::GlobList, value: &str) -> bool {
    globs.is_match(value)
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
