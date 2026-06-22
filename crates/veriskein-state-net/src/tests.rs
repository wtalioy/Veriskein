use std::path::PathBuf;

use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, PathContext, PathResolution, PathResolutionMode, PathVerdict,
    ProcessSnapshot,
};
use veriskein_proto::{ContentDirection, EventKind, VisibilityState};

use crate::{StateNet, state::FdIdentityKind};

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
            NormalizedData::TlsAssoc { .. } => EventKind::TlsAssoc,
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
    let endpoint = state.endpoint_snapshots().front().expect("endpoint");
    assert_eq!(endpoint.fd_version, 1);
    assert_eq!(endpoint.dst.ip, "127.0.0.1");
    assert!(endpoint.tls_candidate);
    assert_eq!(
        state.fd_snapshot(10, 4).expect("socket").kind,
        FdIdentityKind::Socket
    );
}

#[test]
fn tls_fragment_attribution_uses_ssl_fd_association() {
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
    state.apply(&event(
        2,
        NormalizedData::TlsAssoc {
            ssl_ctx: 0xabc,
            fd: 4,
            assoc_ret: 1,
            direction: ContentDirection::Write,
        },
    ));

    let assoc = state
        .tls_association(10, 0xabc, ContentDirection::Write)
        .expect("association");
    assert_eq!(assoc.fd, 4);

    let attribution = state.record_tls_fragment(10, 0xabc, ContentDirection::Write, 3);

    assert_eq!(attribution.visibility_state, VisibilityState::Full);
    assert_eq!(attribution.endpoint.expect("endpoint").ip, "127.0.0.1");
    assert!(attribution.degradation_reason.is_none());
}

#[test]
fn tls_fragment_attribution_requires_matching_direction() {
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
    state.apply(&event(
        2,
        NormalizedData::TlsAssoc {
            ssl_ctx: 0xabc,
            fd: 4,
            assoc_ret: 1,
            direction: ContentDirection::Read,
        },
    ));

    let attribution = state.record_tls_fragment(10, 0xabc, ContentDirection::Write, 3);

    assert_eq!(attribution.visibility_state, VisibilityState::Partial);
    assert_eq!(
        attribution.degradation_reason,
        Some("missing_tls_association")
    );
    assert!(attribution.endpoint.is_none());
}

#[test]
fn tls_fragment_attribution_degrades_without_ssl_fd_association() {
    let mut state = StateNet::new();

    let missing = state.record_tls_fragment(10, 0xabc, ContentDirection::Write, 1);
    assert_eq!(missing.visibility_state, VisibilityState::Partial);
    assert_eq!(missing.degradation_reason, Some("missing_tls_association"));

    for seq in 1..=2 {
        state.apply(&event(
            seq,
            NormalizedData::NetConnect {
                sockfd: seq as i32,
                dport_be: 443_u16.to_be(),
                dst_ip: Some(format!("127.0.0.{seq}")),
                dst_port: Some(443),
                tls_candidate: true,
            },
        ));
    }

    let still_missing = state.record_tls_fragment(10, 0xabc, ContentDirection::Write, 3);
    assert_eq!(still_missing.visibility_state, VisibilityState::Partial);
    assert_eq!(
        still_missing.degradation_reason,
        Some("missing_tls_association")
    );
    assert!(still_missing.endpoint.is_none());
}

#[test]
fn tls_fragment_attribution_degrades_when_associated_fd_has_no_endpoint() {
    let mut state = StateNet::new();
    state.apply(&event(
        1,
        NormalizedData::FileOpen {
            ret_fd: 4,
            flags: 0,
            path: path("/tmp/not-a-socket"),
        },
    ));
    state.apply(&event(
        2,
        NormalizedData::TlsAssoc {
            ssl_ctx: 0xabc,
            fd: 4,
            assoc_ret: 1,
            direction: ContentDirection::Write,
        },
    ));

    let attribution = state.record_tls_fragment(10, 0xabc, ContentDirection::Write, 3);

    assert_eq!(attribution.visibility_state, VisibilityState::Partial);
    assert_eq!(attribution.degradation_reason, Some("missing_tls_endpoint"));
    assert!(attribution.endpoint.is_none());
}

#[test]
fn tls_fragment_attribution_rejects_stale_fd_reuse() {
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
    state.apply(&event(
        2,
        NormalizedData::TlsAssoc {
            ssl_ctx: 0xabc,
            fd: 4,
            assoc_ret: 1,
            direction: ContentDirection::Write,
        },
    ));
    state.apply(&event(
        3,
        NormalizedData::FileOpen {
            ret_fd: 4,
            flags: 0,
            path: path("/tmp/reused"),
        },
    ));

    let attribution = state.record_tls_fragment(10, 0xabc, ContentDirection::Write, 4);

    assert_eq!(attribution.visibility_state, VisibilityState::Partial);
    assert_eq!(
        attribution.degradation_reason,
        Some("stale_tls_association")
    );
    assert!(attribution.endpoint.is_none());
}

#[test]
fn endpoint_snapshots_are_bounded_to_recent_entries() {
    let mut state = StateNet::with_test_limits(16, 2, 16);
    for seq in 1..=4 {
        state.apply(&event(
            seq,
            NormalizedData::NetConnect {
                sockfd: seq as i32,
                dport_be: 443_u16.to_be(),
                dst_ip: Some(format!("127.0.0.{seq}")),
                dst_port: Some(443),
                tls_candidate: true,
            },
        ));
    }

    let endpoints: Vec<_> = state
        .endpoint_snapshots()
        .iter()
        .map(|endpoint| endpoint.event_id.as_str())
        .collect();
    assert_eq!(endpoints, vec!["evt-3", "evt-4"]);
}

#[test]
fn fd_eviction_removes_dependent_tls_associations() {
    let mut state = StateNet::with_test_limits(1, 8, 8);
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
    state.apply(&event(
        2,
        NormalizedData::TlsAssoc {
            ssl_ctx: 0xabc,
            fd: 4,
            assoc_ret: 1,
            direction: ContentDirection::Write,
        },
    ));
    state.apply(&event(
        3,
        NormalizedData::FileOpen {
            ret_fd: 5,
            flags: 0,
            path: path("/tmp/newer"),
        },
    ));

    assert!(state.fd_snapshot(10, 4).is_none());
    assert!(
        state
            .tls_association(10, 0xabc, ContentDirection::Write)
            .is_none()
    );
    assert_eq!(
        state
            .record_tls_fragment(10, 0xabc, ContentDirection::Write, 4)
            .degradation_reason,
        Some("missing_tls_association")
    );
}

#[test]
fn tls_associations_are_bounded_to_recent_entries() {
    let mut state = StateNet::with_test_limits(8, 8, 1);
    for seq in 1..=2 {
        state.apply(&event(
            seq,
            NormalizedData::NetConnect {
                sockfd: seq as i32,
                dport_be: 443_u16.to_be(),
                dst_ip: Some(format!("127.0.0.{seq}")),
                dst_port: Some(443),
                tls_candidate: true,
            },
        ));
        state.apply(&event(
            seq + 10,
            NormalizedData::TlsAssoc {
                ssl_ctx: seq,
                fd: seq as i32,
                assoc_ret: 1,
                direction: ContentDirection::Write,
            },
        ));
    }

    assert!(
        state
            .tls_association(10, 1, ContentDirection::Write)
            .is_none()
    );
    assert!(
        state
            .tls_association(10, 2, ContentDirection::Write)
            .is_some()
    );
}
