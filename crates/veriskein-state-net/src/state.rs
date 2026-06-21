use std::collections::BTreeMap;

use serde::Serialize;
use veriskein_normalizer::{NormalizedData, NormalizedEvent};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FdIdentitySnapshot {
    pub pid: u32,
    pub fd: i32,
    pub fd_version: u32,
    pub kind: FdIdentityKind,
    pub path: Option<String>,
    pub endpoint: Option<EndpointAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FdIdentityKind {
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
pub struct EndpointSnapshot {
    pub pid: u32,
    pub sockfd: i32,
    pub fd_version: u32,
    pub dst: EndpointAddr,
    pub tls_candidate: bool,
    pub event_id: String,
    pub ts_ns: u64,
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
                        preferred_path(path),
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

    pub fn fd_snapshot(&self, pid: u32, fd: i32) -> Option<&FdIdentitySnapshot> {
        self.fds.get(&(pid, fd))
    }

    pub fn endpoint_snapshots(&self) -> &[EndpointSnapshot] {
        &self.endpoints
    }

    fn apply_fd_dup(&mut self, pid: u32, oldfd: i32, newfd: i32, dup_ret: i32) {
        if oldfd == -1 {
            if dup_ret == 0 {
                self.close_fd(pid, newfd);
            }
            return;
        }

        if dup_ret < 0 {
            if newfd >= 0 {
                self.close_fd(pid, newfd);
            }
            return;
        }

        let destination = if newfd >= 0 { newfd } else { dup_ret };
        let version = self.bump_version(pid, destination);
        let mut snapshot = self
            .fds
            .get(&(pid, oldfd))
            .cloned()
            .unwrap_or_else(|| FdIdentitySnapshot::unknown(pid, destination, version));
        snapshot.fd = destination;
        snapshot.fd_version = version;
        self.fds.insert((pid, destination), snapshot);
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

fn preferred_path(path: &veriskein_normalizer::PathContext) -> String {
    path.resolution
        .canonical
        .as_ref()
        .unwrap_or(&path.resolution.lexical)
        .display()
        .to_string()
}
