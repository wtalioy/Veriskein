use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, PathContext, PathResolution, PathResolutionMode, PathVerdict,
    ProcessSnapshot, WorkspaceRef,
};
use veriskein_proto::{EventKind, defaults};

use crate::{AgentConfig, GraphState, SessionState};

fn graph() -> GraphState {
    GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: Vec::new(),
        },
        vec![WorkspaceRef {
            id: "ws-default".to_string(),
            root: "/tmp/ws".into(),
        }],
    )
    .expect("graph")
}

fn exec_event(pid: u32, filename: &str) -> NormalizedEvent {
    event(
        1,
        format!("evt-{pid}"),
        EventKind::ProcExec,
        process(pid, filename),
        NormalizedData::ProcExec {
            filename: filename.to_string(),
            argv: vec!["claude".to_string()],
        },
    )
}

fn process(pid: u32, exe: &str) -> ProcessSnapshot {
    ProcessSnapshot {
        pid,
        tid: pid,
        ppid: 1,
        exe: exe.to_string(),
        comm: "claude".to_string(),
        argv: vec!["claude".to_string()],
        cwd: "/tmp/ws".into(),
    }
}

fn event(
    ts_ns: u64,
    event_id: impl Into<String>,
    kind: EventKind,
    process: ProcessSnapshot,
    data: NormalizedData,
) -> NormalizedEvent {
    NormalizedEvent {
        ingest_seq: ts_ns,
        event_id: event_id.into(),
        ts_ns,
        kind,
        process,
        data,
    }
}

fn path_context(path: &str) -> PathContext {
    PathContext {
        resolution: PathResolution {
            lexical: path.into(),
            canonical: Some(path.into()),
            mode: PathResolutionMode::Canonicalized,
            verdict: PathVerdict::CanonicalTrusted,
            freshness_ns: 1,
        },
        workspace: None,
        sensitive_rule: None,
        sensitive_severity: None,
    }
}

#[test]
fn binary_seed_confirms_root_immediately() {
    let mut graph = graph();
    let binding = graph
        .apply(&exec_event(100, "/usr/bin/claude"))
        .expect("binding");
    assert_eq!(binding.root_pid, 100);
    assert_eq!(
        binding.workspace.root,
        WorkspaceRef {
            id: "ws-default".to_string(),
            root: "/tmp/ws".into(),
        }
        .root
    );
}

#[test]
fn fork_inherits_session() {
    let mut graph = graph();
    graph.apply(&exec_event(100, "/usr/bin/claude"));
    let fork = event(
        2,
        "evt-fork",
        EventKind::ProcFork,
        process(100, "/usr/bin/claude"),
        NormalizedData::ProcFork {
            child_pid: 101,
            child_tid: 101,
        },
    );
    graph.apply(&fork);
    assert!(graph.resolve(101).is_some());
}

#[test]
fn exit_moves_binding_to_draining_until_timeout() {
    let mut graph = graph();
    graph.apply(&exec_event(100, "/usr/bin/claude"));

    let exited = graph
        .apply(&event(
            2,
            "evt-exit",
            EventKind::ProcExit,
            process(100, "/usr/bin/claude"),
            NormalizedData::ProcExit { exit_code: 0 },
        ))
        .expect("draining binding");
    assert_eq!(exited.state, SessionState::Draining);
    assert_eq!(
        graph.resolve(100).expect("binding should drain").state,
        SessionState::Draining
    );

    graph.apply(&event(
        3,
        "evt-open",
        EventKind::FileOpen,
        process(100, "/usr/bin/claude"),
        NormalizedData::FileOpen {
            ret_fd: 3,
            path: path_context("/tmp/ws/late.txt"),
        },
    ));
    assert_eq!(
        graph
            .resolve(100)
            .expect("late event should still resolve")
            .state,
        SessionState::Draining
    );

    graph.apply(&event(
        3 + defaults::SESSION_DRAIN_SECS * 1_000_000_000,
        "evt-expire",
        EventKind::FileOpen,
        process(999, "/usr/bin/other"),
        NormalizedData::FileOpen {
            ret_fd: 3,
            path: path_context("/tmp/ws/expire.txt"),
        },
    ));
    assert!(graph.resolve(100).is_none());
}

#[test]
fn no_workspace_means_no_binding() {
    let mut graph = GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: Vec::new(),
        },
        Vec::new(),
    )
    .expect("graph");
    assert!(graph.apply(&exec_event(200, "/usr/bin/claude")).is_none());
}
