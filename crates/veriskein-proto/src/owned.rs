use serde::Serialize;

use crate::{DropReason, EventHeader, EventId, EventKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedProcForkEvent {
    pub header: EventHeader,
    pub child_pid: u32,
    pub child_tid: u32,
    pub clone_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedProcExecEvent {
    pub header: EventHeader,
    pub filename: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedProcExitEvent {
    pub header: EventHeader,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedProcChdirEvent {
    pub header: EventHeader,
    pub dirfd: i32,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedFdDupEvent {
    pub header: EventHeader,
    pub oldfd: i32,
    pub newfd: i32,
    pub dup_ret: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedFileOpenEvent {
    pub header: EventHeader,
    pub dirfd: i32,
    pub ret_fd: i32,
    pub flags: u32,
    pub mode: u32,
    pub inode: u64,
    pub dev: u64,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedFileUnlinkEvent {
    pub header: EventHeader,
    pub dirfd: i32,
    pub unlink_ret: i32,
    pub flags: u32,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedFileRenameEvent {
    pub header: EventHeader,
    pub olddirfd: i32,
    pub newdirfd: i32,
    pub rename_ret: i32,
    pub flags: u32,
    pub old_path: String,
    pub new_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedNetConnectEvent {
    pub header: EventHeader,
    pub sockfd: i32,
    pub connect_ret: i32,
    pub family: u16,
    pub dport_be: u16,
    pub sport_be: u16,
    pub tls_candidate: bool,
    pub addr_dst: [u8; 16],
    pub addr_src: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedMetaDropEvent {
    pub header: EventHeader,
    pub expected_seq: u64,
    pub observed_seq: u64,
    pub missing: u64,
    pub reason: DropReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnedEvent {
    ProcFork(OwnedProcForkEvent),
    ProcExec(OwnedProcExecEvent),
    ProcExit(OwnedProcExitEvent),
    ProcChdir(OwnedProcChdirEvent),
    FdDup(OwnedFdDupEvent),
    FileOpen(OwnedFileOpenEvent),
    FileUnlink(OwnedFileUnlinkEvent),
    FileRename(OwnedFileRenameEvent),
    NetConnect(OwnedNetConnectEvent),
    MetaDrop(OwnedMetaDropEvent),
}

impl OwnedEvent {
    pub fn header(&self) -> &EventHeader {
        match self {
            Self::ProcFork(evt) => &evt.header,
            Self::ProcExec(evt) => &evt.header,
            Self::ProcExit(evt) => &evt.header,
            Self::ProcChdir(evt) => &evt.header,
            Self::FdDup(evt) => &evt.header,
            Self::FileOpen(evt) => &evt.header,
            Self::FileUnlink(evt) => &evt.header,
            Self::FileRename(evt) => &evt.header,
            Self::NetConnect(evt) => &evt.header,
            Self::MetaDrop(evt) => &evt.header,
        }
    }

    pub fn kind(&self) -> EventKind {
        match self {
            Self::ProcFork(_) => EventKind::ProcFork,
            Self::ProcExec(_) => EventKind::ProcExec,
            Self::ProcExit(_) => EventKind::ProcExit,
            Self::ProcChdir(_) => EventKind::ProcChdir,
            Self::FdDup(_) => EventKind::FdDup,
            Self::FileOpen(_) => EventKind::FileOpen,
            Self::FileUnlink(_) => EventKind::FileUnlink,
            Self::FileRename(_) => EventKind::FileRename,
            Self::NetConnect(_) => EventKind::NetConnect,
            Self::MetaDrop(_) => EventKind::MetaDrop,
        }
    }

    pub fn event_id(&self) -> EventId {
        let header = self.header();
        let pid = header.pid;
        let tid = header.tid;
        let seq = header.seq;
        let ts_ns = header.ts_ns;
        let kind = header.kind;
        let seed = format!("{}:{}:{}:{}:{}", pid, tid, seq, ts_ns, kind);
        EventId::from_seed(seed.as_bytes())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EventRef<'a> {
    ProcFork(&'a crate::ProcForkEvent),
    ProcExec(&'a crate::ProcExecEvent),
    ProcExit(&'a crate::ProcExitEvent),
    ProcChdir(&'a crate::ProcChdirEvent),
    FdDup(&'a crate::FdDupEvent),
    FileOpen(&'a crate::FileOpenEvent),
    FileUnlink(&'a crate::FileUnlinkEvent),
    FileRename(&'a crate::FileRenameEvent),
    NetConnect(&'a crate::NetConnectEvent),
    MetaDrop(&'a crate::MetaDropEvent),
}

impl<'a> EventRef<'a> {
    pub fn header(&self) -> &EventHeader {
        match self {
            Self::ProcFork(evt) => &evt.header,
            Self::ProcExec(evt) => &evt.header,
            Self::ProcExit(evt) => &evt.header,
            Self::ProcChdir(evt) => &evt.header,
            Self::FdDup(evt) => &evt.header,
            Self::FileOpen(evt) => &evt.header,
            Self::FileUnlink(evt) => &evt.header,
            Self::FileRename(evt) => &evt.header,
            Self::NetConnect(evt) => &evt.header,
            Self::MetaDrop(evt) => &evt.header,
        }
    }

    pub fn kind(&self) -> EventKind {
        EventKind::from_raw(self.header().kind).expect("kind should be validated")
    }

    pub fn to_owned(self) -> OwnedEvent {
        match self {
            Self::ProcFork(evt) => OwnedEvent::ProcFork(OwnedProcForkEvent {
                header: evt.header,
                child_pid: evt.child_pid,
                child_tid: evt.child_tid,
                clone_flags: evt.clone_flags,
            }),
            Self::ProcExec(evt) => OwnedEvent::ProcExec(OwnedProcExecEvent {
                header: evt.header,
                filename: crate::parse_c_string(&evt.filename),
                argv: crate::parse_arg_vector(&evt.argv),
            }),
            Self::ProcExit(evt) => OwnedEvent::ProcExit(OwnedProcExitEvent {
                header: evt.header,
                exit_code: evt.exit_code,
            }),
            Self::ProcChdir(evt) => OwnedEvent::ProcChdir(OwnedProcChdirEvent {
                header: evt.header,
                dirfd: evt.dirfd,
                path: crate::parse_c_string(&evt.path),
            }),
            Self::FdDup(evt) => OwnedEvent::FdDup(OwnedFdDupEvent {
                header: evt.header,
                oldfd: evt.oldfd,
                newfd: evt.newfd,
                dup_ret: evt.dup_ret,
            }),
            Self::FileOpen(evt) => OwnedEvent::FileOpen(OwnedFileOpenEvent {
                header: evt.header,
                dirfd: evt.dirfd,
                ret_fd: evt.ret_fd,
                flags: evt.flags,
                mode: evt.mode,
                inode: evt.inode,
                dev: evt.dev,
                path: crate::parse_c_string(&evt.path),
            }),
            Self::FileUnlink(evt) => OwnedEvent::FileUnlink(OwnedFileUnlinkEvent {
                header: evt.header,
                dirfd: evt.dirfd,
                unlink_ret: evt.unlink_ret,
                flags: evt.flags,
                path: crate::parse_c_string(&evt.path),
            }),
            Self::FileRename(evt) => {
                let (old_path, new_path) = crate::parse_path_pair(&evt.paths);
                OwnedEvent::FileRename(OwnedFileRenameEvent {
                    header: evt.header,
                    olddirfd: evt.olddirfd,
                    newdirfd: evt.newdirfd,
                    rename_ret: evt.rename_ret,
                    flags: evt.flags,
                    old_path,
                    new_path,
                })
            }
            Self::NetConnect(evt) => OwnedEvent::NetConnect(OwnedNetConnectEvent {
                header: evt.header,
                sockfd: evt.sockfd,
                connect_ret: evt.connect_ret,
                family: evt.family,
                dport_be: evt.dport_be,
                sport_be: evt.sport_be,
                tls_candidate: evt.tls_candidate != 0,
                addr_dst: evt.addr_dst,
                addr_src: evt.addr_src,
            }),
            Self::MetaDrop(evt) => OwnedEvent::MetaDrop(OwnedMetaDropEvent {
                header: evt.header,
                expected_seq: evt.expected_seq,
                observed_seq: evt.observed_seq,
                missing: evt.missing,
                reason: DropReason::from_raw(evt.reason).unwrap_or(DropReason::SeqGap),
            }),
        }
    }
}
