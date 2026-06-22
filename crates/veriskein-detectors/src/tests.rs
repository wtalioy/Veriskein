use veriskein_graph::{AgentConfig, GraphState};
use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, PathContext, PathResolution, PathResolutionMode, PathVerdict,
    ProcessSnapshot, WorkspaceRef,
};
use veriskein_proto::{EventKind, defaults};

use veriskein_correlator::{PromptEvidence, PromptEvidenceKind};

use crate::deadloop::DeadloopDetector;
use crate::signals::materialize_signals;
use crate::{DetectorEngine, FindingType};

const TEST_PID: u32 = 10;

fn graph() -> GraphState {
    let mut graph = GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            env_hints: Vec::new(),
            argv_hints: Vec::new(),
            llm_endpoints: Vec::new(),
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

fn detect_once(
    event: &NormalizedEvent,
    graph: &GraphState,
    dry_run_exec_observed: bool,
) -> Vec<crate::Finding> {
    DetectorEngine::new().detect(event, graph, dry_run_exec_observed)
}

fn net_connect_event(seq: u64, pid: u32, ip: &str, port: u16) -> NormalizedEvent {
    NormalizedEvent {
        ingest_seq: seq,
        event_id: format!("net-{seq}"),
        ts_ns: defaults::ms_to_ns(seq),
        kind: EventKind::NetConnect,
        process: process(pid, "/usr/bin/claude", "claude", "/tmp/ws"),
        data: NormalizedData::NetConnect {
            sockfd: 3,
            dport_be: port.to_be(),
            dst_ip: Some(ip.to_string()),
            dst_port: Some(port),
            tls_candidate: port == 443,
        },
    }
}

fn file_open_event(seq: u64, pid: u32, path: &str) -> NormalizedEvent {
    NormalizedEvent {
        ingest_seq: seq,
        event_id: format!("file-{seq}"),
        ts_ns: defaults::ms_to_ns(seq),
        kind: EventKind::FileOpen,
        process: process(pid, "/usr/bin/claude", "claude", "/tmp/ws"),
        data: NormalizedData::FileOpen {
            ret_fd: 3,
            flags: 0,
            path: path_context(path, None, false),
        },
    }
}

fn workspace_write_event(seq: u64, pid: u32, path: &str) -> NormalizedEvent {
    NormalizedEvent {
        ingest_seq: seq,
        event_id: format!("write-{seq}"),
        ts_ns: defaults::ms_to_ns(seq),
        kind: EventKind::FileOpen,
        process: process(pid, "/usr/bin/claude", "claude", "/tmp/ws"),
        data: NormalizedData::FileOpen {
            ret_fd: 3,
            flags: 64,
            path: path_context(path, Some("/tmp/ws"), false),
        },
    }
}

fn sensitive_file_open_event(seq: u64, pid: u32, path: &str) -> NormalizedEvent {
    NormalizedEvent {
        ingest_seq: seq,
        event_id: format!("sensitive-file-{seq}"),
        ts_ns: defaults::ms_to_ns(seq),
        kind: EventKind::FileOpen,
        process: process(pid, "/usr/bin/claude", "claude", "/tmp/ws"),
        data: NormalizedData::FileOpen {
            ret_fd: 3,
            flags: 0,
            path: path_context(path, None, true),
        },
    }
}

#[test]
fn unexpected_shell_fires() {
    let findings = detect_once(
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
    let findings = detect_once(
        &event(
            EventKind::FileOpen,
            "open",
            process(TEST_PID, "/usr/bin/claude", "claude", "/tmp/ws"),
            NormalizedData::FileOpen {
                ret_fd: 3,
                flags: 0,
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
    let findings = detect_once(
        &event(
            EventKind::FileOpen,
            "open-denied",
            process(TEST_PID, "/usr/bin/claude", "claude", "/tmp/ws"),
            NormalizedData::FileOpen {
                ret_fd: -13,
                flags: 0,
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
            env_hints: Vec::new(),
            argv_hints: Vec::new(),
            llm_endpoints: Vec::new(),
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
        detect_once(
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
            env_hints: Vec::new(),
            argv_hints: Vec::new(),
            llm_endpoints: Vec::new(),
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
        detect_once(
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
        detect_once(
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
        detect_once(
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
    let findings = detect_once(
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

#[test]
fn deadloop_core_path_requires_two_rules() {
    let graph = graph();
    let mut engine = DetectorEngine::new();
    let mut findings = Vec::new();
    for seq in 1..=60 {
        findings.extend(engine.detect(
            &net_connect_event(seq, TEST_PID, "127.0.0.1", 443),
            &graph,
            false,
        ));
    }
    assert!(
        findings
            .iter()
            .all(|finding| finding.finding_type != FindingType::SingleAgentDeadloop)
    );

    for seq in 61..=80 {
        findings.extend(engine.detect(
            &file_open_event(seq, TEST_PID, "/tmp/loopfile"),
            &graph,
            false,
        ));
    }
    let deadloop = findings
        .iter()
        .find(|finding| finding.finding_type == FindingType::SingleAgentDeadloop)
        .expect("deadloop should fire");
    assert!(
        deadloop
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "net_connect")
    );
    assert!(
        deadloop
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "file_access")
    );
    assert_eq!(deadloop.objects.ips, vec!["127.0.0.1".to_string()]);
    assert_eq!(deadloop.component_scores.get("low_progress"), Some(&1.0));
}

#[test]
fn deadloop_uses_session_cooldown() {
    let graph = graph();
    let mut engine = DetectorEngine::new();
    let mut count = 0;
    for seq in 1..=90 {
        let event = if seq <= 60 {
            net_connect_event(seq, TEST_PID, "127.0.0.1", 443)
        } else {
            file_open_event(seq, TEST_PID, "/tmp/loopfile")
        };
        count += engine
            .detect(&event, &graph, false)
            .into_iter()
            .filter(|finding| finding.finding_type == FindingType::SingleAgentDeadloop)
            .count();
    }
    assert_eq!(count, 1);
}

#[test]
fn deadloop_prunes_expired_sessions_and_cooldowns() {
    let graph = graph();
    let binding = graph.resolve(TEST_PID).expect("binding");
    let mut detector = DeadloopDetector::default();
    let mut count = 0;

    for seq in 1..=90 {
        let event = if seq <= 60 {
            net_connect_event(seq, TEST_PID, "127.0.0.1", 443)
        } else {
            file_open_event(seq, TEST_PID, "/tmp/loopfile")
        };
        let signals = materialize_signals(&event, binding);
        if detector
            .apply(&event, binding, &signals, &[])
            .is_some_and(|finding| finding.finding_type == FindingType::SingleAgentDeadloop)
        {
            count += 1;
        }
    }

    assert_eq!(count, 1);
    assert_eq!(detector.tracked_session_count(), 1);
    assert_eq!(detector.cooldown_count(), 1);

    detector.prune_expired(
        defaults::secs_to_ns(defaults::DEADLOOP_ALERT_COOLDOWN_S + defaults::DEADLOOP_WINDOW_S + 1),
        defaults::secs_to_ns(defaults::DEADLOOP_WINDOW_S),
    );

    assert_eq!(detector.tracked_session_count(), 0);
    assert_eq!(detector.cooldown_count(), 0);
}

#[test]
fn deadloop_evidence_uses_threshold_endpoint_and_path() {
    let graph = graph();
    let mut engine = DetectorEngine::new();
    let mut findings = Vec::new();

    findings.extend(engine.detect(
        &net_connect_event(1, TEST_PID, "10.0.0.2", 443),
        &graph,
        false,
    ));
    for seq in 2..=61 {
        findings.extend(engine.detect(
            &net_connect_event(seq, TEST_PID, "127.0.0.1", 443),
            &graph,
            false,
        ));
    }
    findings.extend(engine.detect(&file_open_event(62, TEST_PID, "/tmp/other"), &graph, false));
    for seq in 63..=82 {
        findings.extend(engine.detect(
            &file_open_event(seq, TEST_PID, "/tmp/loopfile"),
            &graph,
            false,
        ));
    }

    let deadloop = findings
        .iter()
        .find(|finding| finding.finding_type == FindingType::SingleAgentDeadloop)
        .expect("deadloop should fire");
    assert_eq!(deadloop.objects.ips, vec!["127.0.0.1".to_string()]);
    assert_eq!(deadloop.objects.paths, vec!["/tmp/loopfile".to_string()]);
}

#[test]
fn deadloop_counts_sensitive_file_activity() {
    let graph = graph();
    let mut engine = DetectorEngine::new();
    let mut findings = Vec::new();

    for seq in 1..=60 {
        findings.extend(engine.detect(
            &net_connect_event(seq, TEST_PID, "127.0.0.1", 443),
            &graph,
            false,
        ));
    }
    for seq in 61..=80 {
        findings.extend(engine.detect(
            &sensitive_file_open_event(seq, TEST_PID, "/etc/shadow"),
            &graph,
            false,
        ));
    }

    assert!(
        findings
            .iter()
            .any(|finding| finding.finding_type == FindingType::SingleAgentDeadloop)
    );
}

#[test]
fn deadloop_progress_signals_suppress_low_progress_rule() {
    let graph = graph();
    let mut engine = DetectorEngine::new();
    let mut findings = Vec::new();

    for seq in 1..=60 {
        findings.extend(engine.detect(
            &net_connect_event(seq, TEST_PID, "127.0.0.1", 443),
            &graph,
            false,
        ));
    }
    for seq in 61..=80 {
        findings.extend(engine.detect(
            &workspace_write_event(seq, TEST_PID, "/tmp/ws/progress.txt"),
            &graph,
            false,
        ));
    }

    assert!(
        findings
            .iter()
            .all(|finding| finding.finding_type != FindingType::SingleAgentDeadloop)
    );
}

#[test]
fn deadloop_progress_signals_expire_with_window() {
    let graph = graph();
    let mut engine = DetectorEngine::new();
    let mut findings = Vec::new();

    for seq in 1..=10 {
        findings.extend(engine.detect(
            &workspace_write_event(seq, TEST_PID, &format!("/tmp/ws/progress-{seq}.txt")),
            &graph,
            false,
        ));
    }

    let base = 10 + veriskein_proto::defaults::DEADLOOP_WINDOW_S * 1_000;
    for seq in base..base + 60 {
        findings.extend(engine.detect(
            &net_connect_event(seq, TEST_PID, "127.0.0.1", 443),
            &graph,
            false,
        ));
    }
    for seq in base + 60..base + 80 {
        findings.extend(engine.detect(
            &file_open_event(seq, TEST_PID, "/tmp/loopfile"),
            &graph,
            false,
        ));
    }

    assert!(
        findings
            .iter()
            .any(|finding| finding.finding_type == FindingType::SingleAgentDeadloop)
    );
}

#[test]
fn prompt_repeat_can_enhance_deadloop_without_file_repeat() {
    let graph = graph();
    let mut engine = DetectorEngine::new();
    let repeated = vec![PromptEvidence {
        prompt_id: "prompt-1".to_string(),
        ingest_seq: 1,
        visibility_state: veriskein_proto::VisibilityState::Full,
        kind: PromptEvidenceKind::RepeatedPrompt { count: 5 },
    }];
    let mut findings = Vec::new();

    for seq in 1..=60 {
        findings.extend(engine.detect_with_prompt_evidence(
            &net_connect_event(seq, TEST_PID, "127.0.0.1", 443),
            &graph,
            false,
            &repeated,
        ));
    }

    let deadloop = findings
        .iter()
        .find(|finding| finding.finding_type == FindingType::SingleAgentDeadloop)
        .expect("deadloop should fire");
    assert_eq!(deadloop.component_scores.get("prompt_repeat"), Some(&5.0));
    assert!(
        deadloop
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "prompt_ref"
                && evidence.note.as_deref() == Some("repeated_prompt_count=5"))
    );
}

#[test]
fn repeated_prompt_signal_does_not_attach_to_base_findings() {
    let graph = graph();
    let mut engine = DetectorEngine::new();
    let repeated = vec![PromptEvidence {
        prompt_id: "prompt-1".to_string(),
        ingest_seq: 1,
        visibility_state: veriskein_proto::VisibilityState::Full,
        kind: PromptEvidenceKind::RepeatedPrompt { count: 5 },
    }];

    let findings = engine.detect_with_prompt_evidence(
        &sensitive_file_open_event(1, TEST_PID, "/etc/shadow"),
        &graph,
        false,
        &repeated,
    );

    let sensitive = findings
        .iter()
        .find(|finding| finding.finding_type == FindingType::SensitiveFileAccess)
        .expect("sensitive finding");
    assert!(
        sensitive
            .evidence
            .iter()
            .all(|evidence| evidence.kind != "prompt_ref")
    );
}
