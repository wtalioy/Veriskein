use veriskein_normalizer::{NormalizedData, NormalizedEvent, ProcessSnapshot, WorkspaceRef};
use veriskein_proto::EventKind;

use crate::{AgentConfig, GraphState};

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
    NormalizedEvent {
        ingest_seq: 1,
        event_id: format!("evt-{pid}"),
        ts_ns: 1,
        kind: EventKind::ProcExec,
        process: ProcessSnapshot {
            pid,
            tid: pid,
            ppid: 1,
            exe: filename.to_string(),
            comm: "claude".to_string(),
            argv: vec!["claude".to_string()],
            cwd: "/tmp/ws".into(),
        },
        data: NormalizedData::ProcExec {
            filename: filename.to_string(),
            argv: vec!["claude".to_string()],
        },
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
    let fork = NormalizedEvent {
        ingest_seq: 2,
        event_id: "evt-fork".to_string(),
        ts_ns: 2,
        kind: EventKind::ProcFork,
        process: ProcessSnapshot {
            pid: 100,
            tid: 100,
            ppid: 1,
            exe: "/usr/bin/claude".to_string(),
            comm: "claude".to_string(),
            argv: vec!["claude".to_string()],
            cwd: "/tmp/ws".into(),
        },
        data: NormalizedData::ProcFork {
            child_pid: 101,
            child_tid: 101,
        },
    };
    graph.apply(&fork);
    assert!(graph.resolve(101).is_some());
}

#[test]
fn allowlists_use_globs() {
    let graph = GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            shell_allowlist: vec!["/bin/*".to_string()],
            sensitive_allowlist: vec!["/etc/*".to_string()],
            delete_allowlist: vec!["/tmp/**".to_string()],
        },
        vec![WorkspaceRef {
            id: "ws-default".to_string(),
            root: "/tmp/ws".into(),
        }],
    )
    .expect("graph");
    assert!(graph.shell_allowlist().is_match("/bin/sh"));
    assert!(graph.sensitive_allowlist().is_match("/etc/shadow"));
    assert!(graph.delete_allowlist().is_match("/tmp/allowed/file.txt"));
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
