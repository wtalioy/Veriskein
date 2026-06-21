use std::collections::BTreeMap;

use serde::Serialize;
use veriskein_normalizer::{NormalizedData, NormalizedEvent};
use veriskein_proto::{FdDupEffect, VisibilityState, fd_dup_effect};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FdIdentitySnapshot {
    pub(crate) pid: u32,
    pub(crate) fd: i32,
    pub(crate) fd_version: u32,
    pub(crate) kind: FdIdentityKind,
    pub(crate) path: Option<String>,
    pub(crate) endpoint: Option<EndpointAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) enum FdIdentityKind {
    File,
    Socket,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndpointAddr {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EndpointSnapshot {
    pub(crate) pid: u32,
    pub(crate) sockfd: i32,
    pub(crate) fd_version: u32,
    pub(crate) dst: EndpointAddr,
    pub(crate) tls_candidate: bool,
    pub(crate) event_id: String,
    pub(crate) ts_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsAttributionSnapshot {
    pub endpoint: Option<EndpointAddr>,
    pub visibility_state: VisibilityState,
    pub degradation_reason: Option<&'static str>,
}

impl FdIdentitySnapshot {
    fn file(pid: u32, fd: i32, fd_version: u32, path: String) -> Self {
        Self {
            pid,
            fd,
            fd_version,
            kind: FdIdentityKind::File,
            path: Some(path),
            endpoint: None,
        }
    }

    fn socket(pid: u32, fd: i32, fd_version: u32, endpoint: EndpointAddr) -> Self {
        Self {
            pid,
            fd,
            fd_version,
            kind: FdIdentityKind::Socket,
            path: None,
            endpoint: Some(endpoint),
        }
    }

    fn unknown(pid: u32, fd: i32, fd_version: u32) -> Self {
        Self {
            pid,
            fd,
            fd_version,
            kind: FdIdentityKind::Unknown,
            path: None,
            endpoint: None,
        }
    }
}

impl EndpointSnapshot {
    fn from_connect(
        event: &NormalizedEvent,
        sockfd: i32,
        fd_version: u32,
        dst: EndpointAddr,
        tls_candidate: bool,
    ) -> Self {
        Self {
            pid: event.process.pid,
            sockfd,
            fd_version,
            dst,
            tls_candidate,
            event_id: event.event_id.clone(),
            ts_ns: event.ts_ns,
        }
    }
}

#[derive(Debug, Default)]
pub struct StateNet {
    versions: BTreeMap<(u32, i32), u32>,
    fds: BTreeMap<(u32, i32), FdIdentitySnapshot>,
    endpoints: Vec<EndpointSnapshot>,
}

impl StateNet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, event: &NormalizedEvent) {
        match &event.data {
            NormalizedData::FileOpen {
                ret_fd,
                path,
                flags: _,
            } if *ret_fd >= 0 => {
                let version = self.bump_version(event.process.pid, *ret_fd);
                self.fds.insert(
                    (event.process.pid, *ret_fd),
                    FdIdentitySnapshot::file(
                        event.process.pid,
                        *ret_fd,
                        version,
                        path.preferred_path_string(),
                    ),
                );
            }
            NormalizedData::FdDup {
                oldfd,
                newfd,
                dup_ret,
            } => self.apply_fd_dup(event.process.pid, *oldfd, *newfd, *dup_ret),
            NormalizedData::NetConnect {
                sockfd,
                dst_ip: Some(ip),
                dst_port: Some(port),
                tls_candidate,
                ..
            } => self.apply_connect(event, *sockfd, ip, *port, *tls_candidate),
            _ => {}
        }
    }

    #[cfg(test)]
    pub(crate) fn fd_snapshot(&self, pid: u32, fd: i32) -> Option<&FdIdentitySnapshot> {
        self.fds.get(&(pid, fd))
    }

    #[cfg(test)]
    pub(crate) fn endpoint_snapshots(&self) -> &[EndpointSnapshot] {
        &self.endpoints
    }

    pub fn record_tls_fragment(
        &self,
        pid: u32,
        _ssl_ctx: u64,
        ts_ns: u64,
    ) -> TlsAttributionSnapshot {
        let mut candidates = self
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.pid == pid && endpoint.tls_candidate && endpoint.ts_ns <= ts_ns
            })
            .rev();
        let first = candidates.next();
        let second = candidates.next();
        match (first, second) {
            (Some(endpoint), None) => TlsAttributionSnapshot {
                endpoint: Some(endpoint.dst.clone()),
                visibility_state: VisibilityState::Full,
                degradation_reason: None,
            },
            (Some(endpoint), Some(_)) => TlsAttributionSnapshot {
                endpoint: Some(endpoint.dst.clone()),
                visibility_state: VisibilityState::Partial,
                degradation_reason: Some("inferred_tls_endpoint"),
            },
            (None, _) => TlsAttributionSnapshot {
                endpoint: None,
                visibility_state: VisibilityState::Partial,
                degradation_reason: Some("missing_tls_endpoint"),
            },
        }
    }

    fn apply_fd_dup(&mut self, pid: u32, oldfd: i32, newfd: i32, dup_ret: i32) {
        match fd_dup_effect(oldfd, newfd, dup_ret) {
            FdDupEffect::Close { fd } => self.close_fd(pid, fd),
            FdDupEffect::Duplicate { oldfd, newfd } => {
                let version = self.bump_version(pid, newfd);
                let mut snapshot = self
                    .fds
                    .get(&(pid, oldfd))
                    .cloned()
                    .unwrap_or_else(|| FdIdentitySnapshot::unknown(pid, newfd, version));
                snapshot.fd = newfd;
                snapshot.fd_version = version;
                self.fds.insert((pid, newfd), snapshot);
            }
            FdDupEffect::Noop => {}
        }
    }

    fn apply_connect(
        &mut self,
        event: &NormalizedEvent,
        sockfd: i32,
        ip: &str,
        port: u16,
        tls_candidate: bool,
    ) {
        let pid = event.process.pid;
        let version = self.current_or_first_version(pid, sockfd);
        let endpoint = EndpointAddr {
            ip: ip.to_string(),
            port,
        };
        self.fds.insert(
            (pid, sockfd),
            FdIdentitySnapshot::socket(pid, sockfd, version, endpoint.clone()),
        );
        self.endpoints.push(EndpointSnapshot::from_connect(
            event,
            sockfd,
            version,
            endpoint,
            tls_candidate,
        ));
    }

    fn close_fd(&mut self, pid: u32, fd: i32) {
        self.bump_version(pid, fd);
        self.fds.remove(&(pid, fd));
    }

    fn bump_version(&mut self, pid: u32, fd: i32) -> u32 {
        let version = self.versions.entry((pid, fd)).or_insert(0);
        *version = version.saturating_add(1);
        *version
    }

    fn current_or_first_version(&mut self, pid: u32, fd: i32) -> u32 {
        *self.versions.entry((pid, fd)).or_insert(1)
    }
}
