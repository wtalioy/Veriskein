use std::net::ToSocketAddrs;

use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, PathContext, PathResolution, PathResolutionMode, PathVerdict,
    ProcessSnapshot, WorkspaceRef,
};
use veriskein_proto::{EventKind, Role, defaults};

use crate::{AgentConfig, EnvEvidence, GraphState, SessionState};

fn graph() -> GraphState {
    let mut graph = GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            env_hints: Vec::new(),
            argv_hints: vec!["--model".to_string()],
            llm_endpoints: vec!["127.0.0.1".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: Vec::new(),
        },
        vec![WorkspaceRef {
            id: "ws-default".to_string(),
            root: "/tmp/ws".into(),
        }],
    )
    .expect("graph");
    graph.refresh_endpoint_ips(["127.0.0.1".parse().expect("test ip")]);
    graph
}

fn exec_event(pid: u32, filename: &str) -> NormalizedEvent {
    exec_event_with(pid, 1, filename, vec!["claude".to_string()])
}

fn exec_event_with(pid: u32, ts_ns: u64, filename: &str, argv: Vec<String>) -> NormalizedEvent {
    event(
        ts_ns,
        format!("evt-{pid}"),
        EventKind::ProcExec,
        process(pid, filename),
        NormalizedData::ProcExec {
            filename: filename.to_string(),
            argv,
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

fn process_with_ppid(pid: u32, ppid: u32, exe: &str, comm: &str) -> ProcessSnapshot {
    ProcessSnapshot {
        pid,
        tid: pid,
        ppid,
        exe: exe.to_string(),
        comm: comm.to_string(),
        argv: vec![comm.to_string()],
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
    assert_eq!(binding.state, SessionState::ConfirmedRoot);
    assert_eq!(binding.role, Role::RootAgent);
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
fn startup_snapshot_seed_confirms_existing_root() {
    let mut graph = graph();
    let snapshot = process(777, "/usr/bin/claude");

    let binding = graph
        .seed_from_snapshot(&snapshot, EnvEvidence::empty())
        .expect("startup root");

    assert_eq!(binding.root_pid, 777);
    assert_eq!(binding.state, SessionState::ConfirmedRoot);
    assert_eq!(
        graph.resolve(777).expect("resolved").session_id,
        binding.session_id
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
    let child = graph.resolve(101).expect("child binding");
    assert_eq!(child.role, Role::Unknown);
    assert_ne!(child.agent_id, graph.resolve(100).expect("root").agent_id);
}

#[test]
fn argv_plus_connect_confirms_candidate() {
    let mut graph = graph();
    let candidate = graph
        .apply(&exec_event_with(
            300,
            1,
            "/usr/bin/python3",
            vec![
                "python3".to_string(),
                "--model".to_string(),
                "mock".to_string(),
            ],
        ))
        .expect("candidate");
    assert_eq!(candidate.state, SessionState::RootCandidate);

    let confirmed = graph
        .apply(&event(
            2,
            "evt-connect",
            EventKind::NetConnect,
            process(300, "/usr/bin/python3"),
            NormalizedData::NetConnect {
                sockfd: 4,
                dport_be: 443_u16.to_be(),
                dst_ip: Some("127.0.0.1".to_string()),
                dst_port: Some(443),
                tls_candidate: true,
            },
        ))
        .expect("confirmed");
    assert_eq!(confirmed.state, SessionState::ConfirmedRoot);
}

#[test]
fn connect_plus_argv_confirms_candidate() {
    let mut graph = graph();
    let candidate = graph
        .apply(&event(
            1,
            "evt-connect",
            EventKind::NetConnect,
            process(302, "/usr/bin/python3"),
            NormalizedData::NetConnect {
                sockfd: 4,
                dport_be: 443_u16.to_be(),
                dst_ip: Some("127.0.0.1".to_string()),
                dst_port: Some(443),
                tls_candidate: true,
            },
        ))
        .expect("candidate");
    assert_eq!(candidate.state, SessionState::RootCandidate);

    let confirmed = graph
        .apply(&exec_event_with(
            302,
            2,
            "/usr/bin/python3",
            vec![
                "python3".to_string(),
                "--model".to_string(),
                "mock".to_string(),
            ],
        ))
        .expect("confirmed");
    assert_eq!(confirmed.state, SessionState::ConfirmedRoot);
    assert_eq!(confirmed.role, Role::RootAgent);
}

#[test]
fn env_evidence_is_explicit_and_can_confirm_candidate() {
    let mut graph = GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            env_hints: vec!["OPENAI_API_KEY".to_string()],
            argv_hints: vec!["--model".to_string()],
            llm_endpoints: Vec::new(),
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: Vec::new(),
        },
        vec![WorkspaceRef {
            id: "ws-default".to_string(),
            root: "/tmp/ws".into(),
        }],
    )
    .expect("graph");

    let candidate = graph
        .apply(&exec_event_with(
            304,
            1,
            "/usr/bin/python3",
            vec![
                "python3".to_string(),
                "--model".to_string(),
                "mock".to_string(),
            ],
        ))
        .expect("candidate");
    assert_eq!(candidate.state, SessionState::RootCandidate);

    let confirmed = graph
        .apply_env_evidence(304, EnvEvidence::new(vec!["OPENAI_API_KEY".to_string()]), 2)
        .expect("env evidence confirms");
    assert_eq!(confirmed.state, SessionState::ConfirmedRoot);
}

#[test]
fn endpoint_refresh_controls_connect_evidence() {
    let mut graph = graph();
    graph.refresh_endpoint_ips(["192.0.2.10".parse().expect("test ip")]);

    assert!(
        graph
            .apply(&event(
                1,
                "evt-connect-miss",
                EventKind::NetConnect,
                process(305, "/usr/bin/python3"),
                NormalizedData::NetConnect {
                    sockfd: 4,
                    dport_be: 443_u16.to_be(),
                    dst_ip: Some("127.0.0.1".to_string()),
                    dst_port: Some(443),
                    tls_candidate: true,
                },
            ))
            .is_none()
    );

    graph.refresh_endpoint_ips(["127.0.0.1".parse().expect("test ip")]);
    let candidate = graph
        .apply(&event(
            2,
            "evt-connect-hit",
            EventKind::NetConnect,
            process(305, "/usr/bin/python3"),
            NormalizedData::NetConnect {
                sockfd: 4,
                dport_be: 443_u16.to_be(),
                dst_ip: Some("127.0.0.1".to_string()),
                dst_port: Some(443),
                tls_candidate: true,
            },
        ))
        .expect("refreshed endpoint should match");
    assert_eq!(candidate.state, SessionState::RootCandidate);
}

#[test]
fn connect_only_stays_candidate_until_expiry() {
    let mut graph = graph();
    let candidate = graph
        .apply(&event(
            1,
            "evt-connect",
            EventKind::NetConnect,
            process(301, "/usr/bin/python3"),
            NormalizedData::NetConnect {
                sockfd: 4,
                dport_be: 443_u16.to_be(),
                dst_ip: Some("127.0.0.1".to_string()),
                dst_port: Some(443),
                tls_candidate: true,
            },
        ))
        .expect("candidate");
    assert_eq!(candidate.state, SessionState::RootCandidate);

    graph.apply(&event(
        1 + defaults::AGENT_PROMOTION_WINDOW_S * 1_000_000_000,
        "evt-expire",
        EventKind::FileOpen,
        process(999, "/usr/bin/other"),
        NormalizedData::FileOpen {
            ret_fd: 3,
            flags: 0,
            path: path_context("/tmp/ws/expire.txt"),
        },
    ));
    assert!(graph.resolve(301).is_none());
}

#[test]
fn hostname_llm_endpoint_matches_resolved_connect_ip() {
    let mut graph = GraphState::new(
        AgentConfig {
            default_workspace: "/tmp/ws".to_string(),
            binary_seeds: vec!["claude".to_string()],
            env_hints: Vec::new(),
            argv_hints: Vec::new(),
            llm_endpoints: vec!["localhost".to_string()],
            shell_allowlist: Vec::new(),
            sensitive_allowlist: Vec::new(),
            delete_allowlist: Vec::new(),
        },
        vec![WorkspaceRef {
            id: "ws-default".to_string(),
            root: "/tmp/ws".into(),
        }],
    )
    .expect("graph");
    let ip = ("localhost", 443)
        .to_socket_addrs()
        .expect("localhost should resolve")
        .next()
        .expect("localhost should have at least one address")
        .ip();
    graph.refresh_endpoint_ips([ip]);

    let candidate = graph
        .apply(&event(
            1,
            "evt-connect",
            EventKind::NetConnect,
            process(303, "/usr/bin/python3"),
            NormalizedData::NetConnect {
                sockfd: 4,
                dport_be: 443_u16.to_be(),
                dst_ip: Some(ip.to_string()),
                dst_port: Some(443),
                tls_candidate: true,
            },
        ))
        .expect("hostname endpoint should match resolved ip");
    assert_eq!(candidate.state, SessionState::RootCandidate);
}

#[test]
fn role_upgrade_preserves_agent_identity() {
    let mut graph = graph();
    graph.apply(&exec_event(100, "/usr/bin/claude"));
    graph.apply(&event(
        2,
        "evt-fork",
        EventKind::ProcFork,
        process(100, "/usr/bin/claude"),
        NormalizedData::ProcFork {
            child_pid: 101,
            child_tid: 101,
        },
    ));
    let before = graph.resolve(101).expect("child before").clone();
    let after = graph
        .apply(&event(
            3,
            "evt-child-exec",
            EventKind::ProcExec,
            process_with_ppid(101, 100, "/bin/sh", "sh"),
            NormalizedData::ProcExec {
                filename: "/bin/sh".to_string(),
                argv: vec!["sh".to_string()],
            },
        ))
        .expect("child after");
    assert_eq!(before.agent_id, after.agent_id);
    assert_eq!(after.role, Role::ShellTool);
    assert!(after.role_version > before.role_version);
}

#[test]
fn concurrent_roots_are_isolated() {
    let mut graph = graph();
    let left = graph
        .apply(&exec_event(400, "/usr/bin/claude"))
        .expect("left");
    let right = graph
        .apply(&exec_event_with(
            401,
            2,
            "/usr/bin/claude",
            vec!["claude".to_string()],
        ))
        .expect("right");
    assert_ne!(left.session_id, right.session_id);
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
            flags: 0,
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
            flags: 0,
            path: path_context("/tmp/ws/expire.txt"),
        },
    ));
    assert!(graph.resolve(100).is_none());
}

#[test]
fn child_exit_does_not_drain_root_session() {
    let mut graph = graph();
    graph.apply(&exec_event(100, "/usr/bin/claude"));
    graph.apply(&event(
        2,
        "evt-fork",
        EventKind::ProcFork,
        process(100, "/usr/bin/claude"),
        NormalizedData::ProcFork {
            child_pid: 101,
            child_tid: 101,
        },
    ));

    let child_exit = graph
        .apply(&event(
            3,
            "evt-child-exit",
            EventKind::ProcExit,
            process_with_ppid(101, 100, "/usr/bin/python3", "python3"),
            NormalizedData::ProcExit { exit_code: 0 },
        ))
        .expect("child attribution");

    assert_eq!(child_exit.state, SessionState::ConfirmedRoot);
    assert_eq!(
        graph.resolve(100).expect("root stays active").state,
        SessionState::ConfirmedRoot
    );
    assert_eq!(
        graph.resolve(101).expect("late child attribution").state,
        SessionState::ConfirmedRoot
    );
}

#[test]
fn exec_after_draining_pid_reuse_starts_fresh() {
    let mut graph = graph();
    let original = graph
        .apply(&exec_event(100, "/usr/bin/claude"))
        .expect("original root");
    graph.apply(&event(
        2,
        "evt-exit",
        EventKind::ProcExit,
        process(100, "/usr/bin/claude"),
        NormalizedData::ProcExit { exit_code: 0 },
    ));
    assert_eq!(
        graph.resolve(100).expect("draining binding").state,
        SessionState::Draining
    );

    assert!(
        graph
            .apply(&event(
                3,
                "evt-reuse-non-agent",
                EventKind::ProcExec,
                process(100, "/usr/bin/grep"),
                NormalizedData::ProcExec {
                    filename: "/usr/bin/grep".to_string(),
                    argv: vec!["grep".to_string()],
                },
            ))
            .is_none()
    );
    assert!(graph.resolve(100).is_none());

    let fresh = graph
        .apply(&exec_event_with(
            100,
            4,
            "/usr/bin/claude",
            vec!["claude".to_string()],
        ))
        .expect("fresh root");
    assert_eq!(fresh.state, SessionState::ConfirmedRoot);
    assert_ne!(fresh.session_id, original.session_id);
}

#[test]
fn no_workspace_means_no_binding() {
    let mut graph = GraphState::new(
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
        Vec::new(),
    )
    .expect("graph");
    assert!(graph.apply(&exec_event(200, "/usr/bin/claude")).is_none());
}
