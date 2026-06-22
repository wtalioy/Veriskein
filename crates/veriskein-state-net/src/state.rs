use std::collections::{BTreeMap, VecDeque};

use serde::Serialize;
use veriskein_normalizer::{NormalizedData, NormalizedEvent};
use veriskein_proto::{ContentDirection, FdDupEffect, VisibilityState, defaults, fd_dup_effect};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FdIdentitySnapshot {
    pub(crate) pid: u32,
    pub(crate) fd: i32,
    pub(crate) fd_version: u32,
    pub(crate) ts_ns: u64,
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
pub(crate) struct TlsAssociationSnapshot {
    pub(crate) pid: u32,
    pub(crate) ssl_ctx: u64,
    pub(crate) fd: i32,
    pub(crate) direction: ContentDirection,
    pub(crate) fd_version: u32,
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
    fn file(pid: u32, fd: i32, fd_version: u32, ts_ns: u64, path: String) -> Self {
        Self {
            pid,
            fd,
            fd_version,
            ts_ns,
            kind: FdIdentityKind::File,
            path: Some(path),
            endpoint: None,
        }
    }

    fn socket(pid: u32, fd: i32, fd_version: u32, ts_ns: u64, endpoint: EndpointAddr) -> Self {
        Self {
            pid,
            fd,
            fd_version,
            ts_ns,
            kind: FdIdentityKind::Socket,
            path: None,
            endpoint: Some(endpoint),
        }
    }

    fn unknown(pid: u32, fd: i32, fd_version: u32, ts_ns: u64) -> Self {
        Self {
            pid,
            fd,
            fd_version,
            ts_ns,
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

#[derive(Debug, Clone, Copy)]
struct StateNetLimits {
    max_fd_identities: usize,
    max_fd_versions: usize,
    max_endpoint_snapshots: usize,
    max_tls_associations: usize,
}

impl Default for StateNetLimits {
    fn default() -> Self {
        Self {
            max_fd_identities: defaults::MAX_PROCESS_STATES,
            max_fd_versions: defaults::MAX_PROCESS_STATES,
            max_endpoint_snapshots: defaults::MAX_EVENT_INDEX,
            max_tls_associations: defaults::MAX_STREAMS * 2,
        }
    }
}

#[derive(Debug, Default)]
pub struct StateNet {
    limits: StateNetLimits,
    versions: BTreeMap<(u32, i32), u32>,
    fds: BTreeMap<(u32, i32), FdIdentitySnapshot>,
    fd_order: VecDeque<((u32, i32), u64)>,
    endpoints: VecDeque<EndpointSnapshot>,
    tls_associations: BTreeMap<(u32, u64, u8), TlsAssociationSnapshot>,
    tls_association_order: VecDeque<((u32, u64, u8), u64)>,
}

impl StateNet {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn with_test_limits(
        max_fd_identities: usize,
        max_endpoint_snapshots: usize,
        max_tls_associations: usize,
    ) -> Self {
        Self {
            limits: StateNetLimits {
                max_fd_identities,
                max_fd_versions: max_fd_identities,
                max_endpoint_snapshots,
                max_tls_associations,
            },
            ..Self::default()
        }
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
                        event.ts_ns,
                        path.preferred_path_string(),
                    ),
                );
                self.remember_fd(event.process.pid, *ret_fd, event.ts_ns);
            }
            NormalizedData::FdDup {
                oldfd,
                newfd,
                dup_ret,
            } => self.apply_fd_dup(event, *oldfd, *newfd, *dup_ret),
            NormalizedData::NetConnect {
                sockfd,
                dst_ip: Some(ip),
                dst_port: Some(port),
                tls_candidate,
                ..
            } => self.apply_connect(event, *sockfd, ip, *port, *tls_candidate),
            NormalizedData::TlsAssoc {
                ssl_ctx,
                fd,
                assoc_ret,
                direction,
            } if *assoc_ret > 0 && *fd >= 0 => {
                self.apply_tls_assoc(event, *ssl_ctx, *fd, *direction)
            }
            _ => {}
        }
        self.prune();
    }

    #[cfg(test)]
    pub(crate) fn fd_snapshot(&self, pid: u32, fd: i32) -> Option<&FdIdentitySnapshot> {
        self.fds.get(&(pid, fd))
    }

    #[cfg(test)]
    pub(crate) fn endpoint_snapshots(&self) -> &VecDeque<EndpointSnapshot> {
        &self.endpoints
    }

    #[cfg(test)]
    pub(crate) fn tls_association(
        &self,
        pid: u32,
        ssl_ctx: u64,
        direction: ContentDirection,
    ) -> Option<&TlsAssociationSnapshot> {
        self.tls_associations.get(&(pid, ssl_ctx, direction as u8))
    }

    pub fn record_tls_fragment(
        &self,
        pid: u32,
        ssl_ctx: u64,
        direction: ContentDirection,
        _ts_ns: u64,
    ) -> TlsAttributionSnapshot {
        let Some(assoc) = self.tls_associations.get(&(pid, ssl_ctx, direction as u8)) else {
            return TlsAttributionSnapshot {
                endpoint: None,
                visibility_state: VisibilityState::Partial,
                degradation_reason: Some("missing_tls_association"),
            };
        };
        let Some(fd) = self.fds.get(&(pid, assoc.fd)) else {
            return TlsAttributionSnapshot {
                endpoint: None,
                visibility_state: VisibilityState::Partial,
                degradation_reason: Some("missing_tls_endpoint"),
            };
        };
        if fd.fd_version != assoc.fd_version {
            return TlsAttributionSnapshot {
                endpoint: None,
                visibility_state: VisibilityState::Partial,
                degradation_reason: Some("stale_tls_association"),
            };
        }
        match &fd.endpoint {
            Some(endpoint) => TlsAttributionSnapshot {
                endpoint: Some(endpoint.clone()),
                visibility_state: VisibilityState::Full,
                degradation_reason: None,
            },
            None => TlsAttributionSnapshot {
                endpoint: None,
                visibility_state: VisibilityState::Partial,
                degradation_reason: Some("missing_tls_endpoint"),
            },
        }
    }

    fn apply_fd_dup(&mut self, event: &NormalizedEvent, oldfd: i32, newfd: i32, dup_ret: i32) {
        let pid = event.process.pid;
        match fd_dup_effect(oldfd, newfd, dup_ret) {
            FdDupEffect::Close { fd } => self.close_fd(pid, fd),
            FdDupEffect::Duplicate { oldfd, newfd } => {
                let version = self.bump_version(pid, newfd);
                let mut snapshot = self.fds.get(&(pid, oldfd)).cloned().unwrap_or_else(|| {
                    FdIdentitySnapshot::unknown(pid, newfd, version, event.ts_ns)
                });
                snapshot.fd = newfd;
                snapshot.fd_version = version;
                snapshot.ts_ns = event.ts_ns;
                self.fds.insert((pid, newfd), snapshot);
                self.remember_fd(pid, newfd, event.ts_ns);
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
            FdIdentitySnapshot::socket(pid, sockfd, version, event.ts_ns, endpoint.clone()),
        );
        self.remember_fd(pid, sockfd, event.ts_ns);
        self.endpoints.push_back(EndpointSnapshot::from_connect(
            event,
            sockfd,
            version,
            endpoint,
            tls_candidate,
        ));
    }

    fn apply_tls_assoc(
        &mut self,
        event: &NormalizedEvent,
        ssl_ctx: u64,
        fd: i32,
        direction: ContentDirection,
    ) {
        let pid = event.process.pid;
        let fd_version = self.current_or_first_version(pid, fd);
        let snapshot = TlsAssociationSnapshot {
            pid,
            ssl_ctx,
            fd,
            direction,
            fd_version,
            event_id: event.event_id.clone(),
            ts_ns: event.ts_ns,
        };
        self.tls_associations
            .insert((pid, ssl_ctx, direction as u8), snapshot);
        self.remember_tls_association(pid, ssl_ctx, direction, event.ts_ns);
    }

    fn close_fd(&mut self, pid: u32, fd: i32) {
        self.bump_version(pid, fd);
        self.fds.remove(&(pid, fd));
        self.remove_tls_associations_for_fd(pid, fd);
    }

    fn bump_version(&mut self, pid: u32, fd: i32) -> u32 {
        let version = self.versions.entry((pid, fd)).or_insert(0);
        *version = version.saturating_add(1);
        *version
    }

    fn current_or_first_version(&mut self, pid: u32, fd: i32) -> u32 {
        *self.versions.entry((pid, fd)).or_insert(1)
    }

    fn remember_fd(&mut self, pid: u32, fd: i32, ts_ns: u64) {
        let key = (pid, fd);
        self.fd_order.push_back((key, ts_ns));
    }

    fn remember_tls_association(
        &mut self,
        pid: u32,
        ssl_ctx: u64,
        direction: ContentDirection,
        ts_ns: u64,
    ) {
        let key = (pid, ssl_ctx, direction as u8);
        self.tls_association_order.push_back((key, ts_ns));
    }

    fn prune(&mut self) {
        while self.endpoints.len() > self.limits.max_endpoint_snapshots {
            self.endpoints.pop_front();
        }

        while self.tls_associations.len() > self.limits.max_tls_associations {
            let Some((key, ts_ns)) = self.tls_association_order.pop_front() else {
                break;
            };
            if self
                .tls_associations
                .get(&key)
                .is_some_and(|association| association.ts_ns == ts_ns)
            {
                self.tls_associations.remove(&key);
            }
        }

        while self.fds.len() > self.limits.max_fd_identities {
            let Some(((pid, fd), ts_ns)) = self.fd_order.pop_front() else {
                break;
            };
            if self
                .fds
                .get(&(pid, fd))
                .is_some_and(|snapshot| snapshot.ts_ns == ts_ns)
                && self.fds.remove(&(pid, fd)).is_some()
            {
                self.remove_tls_associations_for_fd(pid, fd);
            }
        }

        while self.versions.len() > self.limits.max_fd_versions {
            let Some(key) = self
                .versions
                .keys()
                .find(|key| !self.fds.contains_key(key))
                .copied()
            else {
                break;
            };
            self.versions.remove(&key);
        }
    }

    fn remove_tls_associations_for_fd(&mut self, pid: u32, fd: i32) {
        self.tls_associations
            .retain(|_, association| association.pid != pid || association.fd != fd);
        self.tls_association_order
            .retain(|(key, _)| self.tls_associations.contains_key(key));
    }
}
