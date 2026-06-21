use std::path::PathBuf;

use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, PathContext, PathResolution, PathResolutionMode, PathVerdict,
    ProcessSnapshot,
};
use veriskein_proto::EventKind;

use crate::{FdIdentityKind, StateNet};

fn process() -> ProcessSnapshot {
    ProcessSnapshot {
        pid: 10,
        tid: 10,
        ppid: 1,
        exe: "/usr/bin/claude".to_string(),
        comm: "claude".to_string(),
        argv: vec!["claude".to_string()],
        cwd: PathBuf::from("/tmp/ws"),
    }
}

fn event(seq: u64, data: NormalizedData) -> NormalizedEvent {
    NormalizedEvent {
        ingest_seq: seq,
        event_id: format!("evt-{seq}"),
        ts_ns: seq,
        kind: match &data {
            NormalizedData::FileOpen { .. } => EventKind::FileOpen,
            NormalizedData::FdDup { .. } => EventKind::FdDup,
            NormalizedData::NetConnect { .. } => EventKind::NetConnect,
            _ => EventKind::ProcExec,
        },
        process: process(),
        data,
    }
}

fn path(path: &str) -> PathContext {
    PathContext {
        resolution: PathResolution {
            lexical: path.into(),
            canonical: Some(path.into()),
            mode: PathResolutionMode::Canonicalized,
            verdict: PathVerdict::CanonicalTrusted,
            freshness_ns: 0,
        },
        workspace: None,
        sensitive_rule: None,
        sensitive_severity: None,
    }
}

#[test]
fn open_and_reopen_bumps_fd_version() {
    let mut state = StateNet::new();
    state.apply(&event(
        1,
        NormalizedData::FileOpen {
            ret_fd: 3,
            flags: 0,
            path: path("/tmp/a"),
        },
    ));
    assert_eq!(state.fd_snapshot(10, 3).expect("fd").fd_version, 1);

    state.apply(&event(
        2,
        NormalizedData::FileOpen {
            ret_fd: 3,
            flags: 0,
            path: path("/tmp/b"),
        },
    ));
    let fd = state.fd_snapshot(10, 3).expect("fd");
    assert_eq!(fd.fd_version, 2);
    assert_eq!(fd.path.as_deref(), Some("/tmp/b"));
}

#[test]
fn dup_replaces_destination_with_new_version() {
    let mut state = StateNet::new();
    state.apply(&event(
        1,
        NormalizedData::FileOpen {
            ret_fd: 3,
            flags: 0,
            path: path("/tmp/a"),
        },
    ));
    state.apply(&event(
        2,
        NormalizedData::FdDup {
            oldfd: 3,
            newfd: 9,
            dup_ret: 9,
        },
    ));
    let fd = state.fd_snapshot(10, 9).expect("dup fd");
    assert_eq!(fd.fd_version, 1);
    assert_eq!(fd.path.as_deref(), Some("/tmp/a"));
}

#[test]
fn close_then_reopen_advances_version() {
    let mut state = StateNet::new();
    state.apply(&event(
        1,
        NormalizedData::FileOpen {
            ret_fd: 3,
            flags: 0,
            path: path("/tmp/a"),
        },
    ));
    state.apply(&event(
        2,
        NormalizedData::FdDup {
            oldfd: -1,
            newfd: 3,
            dup_ret: 0,
        },
    ));
    assert!(state.fd_snapshot(10, 3).is_none());
    state.apply(&event(
        3,
        NormalizedData::FileOpen {
            ret_fd: 3,
            flags: 0,
            path: path("/tmp/b"),
        },
    ));
    assert_eq!(state.fd_snapshot(10, 3).expect("fd").fd_version, 3);
}

#[test]
fn connect_publishes_endpoint_snapshot() {
    let mut state = StateNet::new();
    state.apply(&event(
        1,
        NormalizedData::NetConnect {
            sockfd: 4,
            dport_be: 443_u16.to_be(),
            dst_ip: Some("127.0.0.1".to_string()),
            dst_port: Some(443),
            tls_candidate: true,
        },
    ));
    let endpoint = state.endpoint_snapshots().first().expect("endpoint");
    assert_eq!(endpoint.fd_version, 1);
    assert_eq!(endpoint.dst.ip, "127.0.0.1");
    assert!(endpoint.tls_candidate);
    assert_eq!(
        state.fd_snapshot(10, 4).expect("socket").kind,
        FdIdentityKind::Socket
    );
}
