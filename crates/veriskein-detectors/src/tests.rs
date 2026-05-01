use veriskein_graph::{AgentConfig, GraphState};
use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, PathContext, PathResolution, PathResolutionMode, PathVerdict,
    ProcessSnapshot, WorkspaceRef,
};
use veriskein_proto::EventKind;

use crate::{FindingType, detect};

fn graph() -> GraphState {
    let mut graph = GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: vec!["/tmp/allowed.txt".to_string()],
        },
        vec![WorkspaceRef {
            id: "ws".to_string(),
            root: "/tmp/ws".into(),
        }],
    )
    .expect("graph");
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
    let graph = GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: Vec::new(),
        },
        vec![WorkspaceRef {
            id: "ws".to_string(),
            root: "/tmp/ws".into(),
        }],
    )
    .expect("graph");
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
    let mut graph = GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: vec!["/tmp/**".to_string()],
        },
        vec![WorkspaceRef {
            id: "ws".to_string(),
            root: "/tmp/ws".into(),
        }],
    )
    .expect("graph");
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
            unlink_ret: 0,
            path: path_context("/tmp/allowed/file.txt", None, false),
        },
    };
    assert!(detect(&event, &graph, false).is_empty());
}

#[test]
fn failed_unlink_does_not_alert() {
    let graph = graph();
    let event = NormalizedEvent {
        ingest_seq: 2,
        event_id: "unlink-fail".to_string(),
        ts_ns: 2,
        kind: EventKind::FileUnlink,
        process: ProcessSnapshot {
            pid: 10,
            tid: 10,
            ppid: 1,
            exe: "/usr/bin/claude".to_string(),
            comm: "claude".to_string(),
            argv: vec!["claude".to_string()],
            cwd: "/tmp/ws".into(),
        },
        data: NormalizedData::FileUnlink {
            unlink_ret: -1,
            path: path_context("/tmp/outside.txt", None, false),
        },
    };
    assert!(detect(&event, &graph, false).is_empty());
}

#[test]
fn failed_rename_does_not_alert() {
    let graph = graph();
    let event = NormalizedEvent {
        ingest_seq: 2,
        event_id: "rename-fail".to_string(),
        ts_ns: 2,
        kind: EventKind::FileRename,
        process: ProcessSnapshot {
            pid: 10,
            tid: 10,
            ppid: 1,
            exe: "/usr/bin/claude".to_string(),
            comm: "claude".to_string(),
            argv: vec!["claude".to_string()],
            cwd: "/tmp/ws".into(),
        },
        data: NormalizedData::FileRename {
            rename_ret: -1,
            old_path: path_context("/tmp/ws/inside.txt", Some("/tmp/ws"), false),
            new_path: path_context("/tmp/outside.txt", None, false),
        },
    };
    assert!(detect(&event, &graph, false).is_empty());
}

#[test]
fn successful_outside_workspace_delete_alerts() {
    let graph = graph();
    let event = NormalizedEvent {
        ingest_seq: 2,
        event_id: "unlink-ok".to_string(),
        ts_ns: 2,
        kind: EventKind::FileUnlink,
        process: ProcessSnapshot {
            pid: 10,
            tid: 10,
            ppid: 1,
            exe: "/usr/bin/claude".to_string(),
            comm: "claude".to_string(),
            argv: vec!["claude".to_string()],
            cwd: "/tmp/ws".into(),
        },
        data: NormalizedData::FileUnlink {
            unlink_ret: 0,
            path: path_context("/tmp/outside.txt", None, false),
        },
    };
    let findings = detect(&event, &graph, false);
    assert_eq!(
        findings[0].finding_type,
        FindingType::OutOfWorkspaceDeletion
    );
}
