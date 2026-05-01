use veriskein_graph::{AgentConfig, GraphState};
use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, PathContext, PathResolution, PathResolutionMode, PathVerdict,
    ProcessSnapshot, WorkspaceRef,
};
use veriskein_proto::EventKind;

use crate::{FindingType, detect};

const TEST_PID: u32 = 10;

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
    graph.apply(&event(
        EventKind::ProcExec,
        "seed",
        process(TEST_PID, "/usr/bin/claude", "claude", "/tmp/ws"),
        NormalizedData::ProcExec {
            filename: "/usr/bin/claude".to_string(),
            argv: vec!["claude".to_string()],
        },
    ));
    graph
}

fn process(pid: u32, exe: &str, comm: &str, cwd: &str) -> ProcessSnapshot {
    ProcessSnapshot {
        pid,
        tid: pid,
        ppid: 1,
        exe: exe.to_string(),
        comm: comm.to_string(),
        argv: vec![comm.to_string()],
        cwd: cwd.into(),
    }
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

fn event(
    kind: EventKind,
    event_id: &str,
    process: ProcessSnapshot,
    data: NormalizedData,
) -> NormalizedEvent {
    NormalizedEvent {
        ingest_seq: 2,
        event_id: event_id.to_string(),
        ts_ns: 2,
        kind,
        process,
        data,
    }
}

#[test]
fn unexpected_shell_fires() {
    let findings = detect(
        &event(
            EventKind::ProcExec,
            "shell",
            process(TEST_PID, "/bin/sh", "sh", "/tmp/ws"),
            NormalizedData::ProcExec {
                filename: "/bin/sh".to_string(),
                argv: vec!["sh".to_string()],
            },
        ),
        &graph(),
        false,
    );
    assert_eq!(findings[0].finding_type, FindingType::UnexpectedShell);
}

#[test]
fn sensitive_access_fires() {
    let findings = detect(
        &event(
            EventKind::FileOpen,
            "open",
            process(TEST_PID, "/usr/bin/claude", "claude", "/tmp/ws"),
            NormalizedData::FileOpen {
                ret_fd: 3,
                path: path_context("/etc/shadow", None, true),
            },
        ),
        &graph(),
        false,
    );
    assert_eq!(findings[0].finding_type, FindingType::SensitiveFileAccess);
}

#[test]
fn denied_sensitive_access_still_fires() {
    let findings = detect(
        &event(
            EventKind::FileOpen,
            "open-denied",
            process(TEST_PID, "/usr/bin/claude", "claude", "/tmp/ws"),
            NormalizedData::FileOpen {
                ret_fd: -13,
                path: path_context("/etc/shadow", None, true),
            },
        ),
        &graph(),
        false,
    );
    assert_eq!(findings[0].finding_type, FindingType::SensitiveFileAccess);
    assert_eq!(findings[0].reason_code, "sensitive_file_open_denied");
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
    assert!(
        detect(
            &event(
                EventKind::ProcExec,
                "shell",
                process(99, "/bin/bash", "bash", "/tmp"),
                NormalizedData::ProcExec {
                    filename: "/bin/bash".to_string(),
                    argv: vec!["bash".to_string()],
                },
            ),
            &graph,
            false,
        )
        .is_empty()
    );
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
    graph.apply(&event(
        EventKind::ProcExec,
        "seed",
        process(11, "/usr/bin/claude", "claude", "/tmp/ws"),
        NormalizedData::ProcExec {
            filename: "/usr/bin/claude".to_string(),
            argv: vec!["claude".to_string()],
        },
    ));
    assert!(
        detect(
            &event(
                EventKind::FileUnlink,
                "unlink",
                process(11, "/usr/bin/claude", "claude", "/tmp/ws"),
                NormalizedData::FileUnlink {
                    unlink_ret: 0,
                    path: path_context("/tmp/allowed/file.txt", None, false),
                },
            ),
            &graph,
            false,
        )
        .is_empty()
    );
}

#[test]
fn failed_unlink_does_not_alert() {
    assert!(
        detect(
            &event(
                EventKind::FileUnlink,
                "unlink-fail",
                process(TEST_PID, "/usr/bin/claude", "claude", "/tmp/ws"),
                NormalizedData::FileUnlink {
                    unlink_ret: -1,
                    path: path_context("/tmp/outside.txt", None, false),
                },
            ),
            &graph(),
            false,
        )
        .is_empty()
    );
}

#[test]
fn failed_rename_does_not_alert() {
    assert!(
        detect(
            &event(
                EventKind::FileRename,
                "rename-fail",
                process(TEST_PID, "/usr/bin/claude", "claude", "/tmp/ws"),
                NormalizedData::FileRename {
                    rename_ret: -1,
                    old_path: path_context("/tmp/ws/inside.txt", Some("/tmp/ws"), false),
                    new_path: path_context("/tmp/outside.txt", None, false),
                },
            ),
            &graph(),
            false,
        )
        .is_empty()
    );
}

#[test]
fn successful_outside_workspace_delete_alerts() {
    let findings = detect(
        &event(
            EventKind::FileUnlink,
            "unlink-ok",
            process(TEST_PID, "/usr/bin/claude", "claude", "/tmp/ws"),
            NormalizedData::FileUnlink {
                unlink_ret: 0,
                path: path_context("/tmp/outside.txt", None, false),
            },
        ),
        &graph(),
        false,
    );
    assert_eq!(
        findings[0].finding_type,
        FindingType::OutOfWorkspaceDeletion
    );
}
