use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use veriskein_proto::{
    EventHeader, EventKind, FdDupEffect, OwnedEvent, OwnedFdDupEvent, OwnedFileOpenEvent,
    OwnedFileRenameEvent, OwnedFileUnlinkEvent, OwnedNetConnectEvent, OwnedProcChdirEvent,
    OwnedProcExecEvent, OwnedProcExitEvent, OwnedProcForkEvent, OwnedTlsAssocEvent,
    event_id_hex_from_header, fd_dup_effect, parse_c_string,
};

use super::process::{FdEntry, ProcessState};
use super::{NormalizedData, NormalizedEvent, Normalizer, ProcessSnapshot};

impl Normalizer {
    pub fn apply(&mut self, ingest_seq: u64, event: &OwnedEvent) -> Vec<NormalizedEvent> {
        self.collect_expired(event.header().ts_ns);
        match event {
            OwnedEvent::ProcFork(evt) => self.on_proc_fork(ingest_seq, evt),
            OwnedEvent::ProcExec(evt) => vec![self.on_proc_exec(ingest_seq, evt)],
            OwnedEvent::ProcExit(evt) => self.on_proc_exit(ingest_seq, evt),
            OwnedEvent::ProcChdir(evt) => self.on_proc_chdir(ingest_seq, evt),
            OwnedEvent::FdDup(evt) => self.on_fd_dup(ingest_seq, evt),
            OwnedEvent::FileOpen(evt) => self.on_file_open(ingest_seq, evt),
            OwnedEvent::FileUnlink(evt) => self.on_file_unlink(ingest_seq, evt),
            OwnedEvent::FileRename(evt) => self.on_file_rename(ingest_seq, evt),
            OwnedEvent::NetConnect(evt) => vec![self.on_net_connect(ingest_seq, evt)],
            OwnedEvent::TlsAssoc(evt) => vec![self.on_tls_assoc(ingest_seq, evt)],
            OwnedEvent::ContentFrag(_) => Vec::new(),
            OwnedEvent::MetaDrop(_) => Vec::new(),
        }
    }

    fn snapshot_for(&self, pid: u32, fallback_header: &EventHeader) -> ProcessSnapshot {
        if let Some(proc) = self.processes.get(&pid).or_else(|| self.expiring.get(&pid)) {
            return proc.snapshot();
        }

        ProcessSnapshot {
            pid: fallback_header.pid,
            tid: fallback_header.tid,
            ppid: fallback_header.ppid,
            exe: String::new(),
            comm: parse_c_string(&fallback_header.comm),
            argv: Vec::new(),
            cwd: self
                .workspaces
                .first()
                .map(|workspace| workspace.root.clone())
                .unwrap_or_else(|| PathBuf::from("/")),
        }
    }

    fn on_proc_fork(&mut self, ingest_seq: u64, evt: &OwnedProcForkEvent) -> Vec<NormalizedEvent> {
        let parent_pid = evt.header.pid;
        let child = self
            .processes
            .get(&parent_pid)
            .cloned()
            .unwrap_or(ProcessState {
                pid: evt.child_pid,
                tid: evt.child_tid,
                ppid: parent_pid,
                mount_ns: evt.header.mount_ns,
                exe: String::new(),
                comm: String::new(),
                argv: Vec::new(),
                cwd: PathBuf::from("/"),
                fds: Arc::new(BTreeMap::new()),
                expired_at_ns: None,
            });
        self.processes.insert(
            evt.child_pid,
            ProcessState {
                pid: evt.child_pid,
                tid: evt.child_tid,
                ppid: parent_pid,
                mount_ns: child.mount_ns,
                exe: child.exe,
                comm: child.comm,
                argv: child.argv,
                cwd: child.cwd,
                fds: child.fds,
                expired_at_ns: None,
            },
        );
        vec![self.normalized_event(
            ingest_seq,
            EventKind::ProcFork,
            self.snapshot_for(parent_pid, &evt.header),
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::ProcFork {
                child_pid: evt.child_pid,
                child_tid: evt.child_tid,
            },
        )]
    }

    fn on_proc_exec(&mut self, ingest_seq: u64, evt: &OwnedProcExecEvent) -> NormalizedEvent {
        let pid = evt.header.pid;
        let prior = self.processes.get(&pid).cloned();
        let cwd = prior
            .as_ref()
            .map(|proc| proc.cwd.clone())
            .or_else(|| {
                self.workspaces
                    .first()
                    .map(|workspace| workspace.root.clone())
            })
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));

        self.processes.insert(
            pid,
            ProcessState {
                pid,
                tid: evt.header.tid,
                ppid: evt.header.ppid,
                mount_ns: evt.header.mount_ns,
                exe: evt.filename.clone(),
                comm: parse_c_string(&evt.header.comm),
                argv: evt.argv.clone(),
                cwd,
                fds: prior
                    .map(|proc| proc.fds)
                    .unwrap_or_else(|| Arc::new(BTreeMap::new())),
                expired_at_ns: None,
            },
        );

        self.normalized_event(
            ingest_seq,
            EventKind::ProcExec,
            self.snapshot_for(pid, &evt.header),
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::ProcExec {
                filename: evt.filename.clone(),
                argv: evt.argv.clone(),
            },
        )
    }

    fn on_proc_exit(&mut self, ingest_seq: u64, evt: &OwnedProcExitEvent) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let snapshot = self.snapshot_for(pid, &evt.header);
        if let Some(mut exiting) = self.processes.remove(&pid) {
            exiting.expired_at_ns = Some(evt.header.ts_ns.saturating_add(
                veriskein_proto::defaults::ms_to_ns(
                    veriskein_proto::defaults::EXPIRING_PROC_HOLD_MS,
                ),
            ));
            self.expiring.insert(pid, exiting);
        }
        vec![self.normalized_event(
            ingest_seq,
            EventKind::ProcExit,
            snapshot,
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::ProcExit {
                exit_code: evt.exit_code,
            },
        )]
    }

    fn on_proc_chdir(
        &mut self,
        ingest_seq: u64,
        evt: &OwnedProcChdirEvent,
    ) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let resolved = self.resolve_path(pid, evt.dirfd, &evt.path, evt.header.ts_ns);
        if let Some(proc) = self.processes.get_mut(&pid) {
            proc.cwd = resolved
                .resolution
                .canonical
                .clone()
                .unwrap_or_else(|| resolved.resolution.lexical.clone());
        }
        vec![self.normalized_event(
            ingest_seq,
            EventKind::ProcChdir,
            self.snapshot_for(pid, &evt.header),
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::ProcChdir { path: resolved },
        )]
    }

    fn on_fd_dup(&mut self, ingest_seq: u64, evt: &OwnedFdDupEvent) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        if let Some(proc) = self.processes.get_mut(&pid) {
            let fds = Arc::make_mut(&mut proc.fds);
            match fd_dup_effect(evt.oldfd, evt.newfd, evt.dup_ret) {
                FdDupEffect::Close { fd } => {
                    fds.remove(&fd);
                }
                FdDupEffect::Duplicate { oldfd, newfd } => {
                    if let Some(entry) = fds.get(&oldfd).cloned() {
                        fds.insert(newfd, entry);
                    }
                }
                FdDupEffect::Noop => {}
            }
        }
        vec![self.normalized_event(
            ingest_seq,
            EventKind::FdDup,
            self.snapshot_for(pid, &evt.header),
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::FdDup {
                oldfd: evt.oldfd,
                newfd: evt.newfd,
                dup_ret: evt.dup_ret,
            },
        )]
    }

    fn on_file_open(&mut self, ingest_seq: u64, evt: &OwnedFileOpenEvent) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let resolved = self.resolve_path(pid, evt.dirfd, &evt.path, evt.header.ts_ns);
        if evt.ret_fd >= 0 {
            if let Some(proc) = self.processes.get_mut(&pid) {
                let stored = resolved
                    .resolution
                    .canonical
                    .clone()
                    .unwrap_or_else(|| resolved.resolution.lexical.clone());
                Arc::make_mut(&mut proc.fds).insert(evt.ret_fd, FdEntry::File(stored));
            }
        }
        vec![self.normalized_event(
            ingest_seq,
            EventKind::FileOpen,
            self.snapshot_for(pid, &evt.header),
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::FileOpen {
                ret_fd: evt.ret_fd,
                flags: evt.flags,
                path: resolved,
            },
        )]
    }

    fn on_file_unlink(
        &mut self,
        ingest_seq: u64,
        evt: &OwnedFileUnlinkEvent,
    ) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let resolved = self.resolve_path(pid, evt.dirfd, &evt.path, evt.header.ts_ns);
        vec![self.normalized_event(
            ingest_seq,
            EventKind::FileUnlink,
            self.snapshot_for(pid, &evt.header),
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::FileUnlink {
                unlink_ret: evt.unlink_ret,
                path: resolved,
            },
        )]
    }

    fn on_file_rename(
        &mut self,
        ingest_seq: u64,
        evt: &OwnedFileRenameEvent,
    ) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let old_path = self.resolve_path(pid, evt.olddirfd, &evt.old_path, evt.header.ts_ns);
        let new_path = self.resolve_path(pid, evt.newdirfd, &evt.new_path, evt.header.ts_ns);
        vec![self.normalized_event(
            ingest_seq,
            EventKind::FileRename,
            self.snapshot_for(pid, &evt.header),
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::FileRename {
                rename_ret: evt.rename_ret,
                old_path,
                new_path,
            },
        )]
    }

    fn on_net_connect(&mut self, ingest_seq: u64, evt: &OwnedNetConnectEvent) -> NormalizedEvent {
        let pid = evt.header.pid;
        self.normalized_event(
            ingest_seq,
            EventKind::NetConnect,
            self.snapshot_for(pid, &evt.header),
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::NetConnect {
                sockfd: evt.sockfd,
                dport_be: evt.dport_be,
                dst_ip: net_dst_ip(evt.family, evt.addr_dst),
                dst_port: Some(u16::from_be(evt.dport_be)),
                tls_candidate: evt.tls_candidate,
            },
        )
    }

    fn on_tls_assoc(&mut self, ingest_seq: u64, evt: &OwnedTlsAssocEvent) -> NormalizedEvent {
        let pid = evt.header.pid;
        self.normalized_event(
            ingest_seq,
            EventKind::TlsAssoc,
            self.snapshot_for(pid, &evt.header),
            event_id_hex_from_header(&evt.header),
            evt.header.ts_ns,
            NormalizedData::TlsAssoc {
                ssl_ctx: evt.ssl_ctx,
                fd: evt.fd,
                assoc_ret: evt.assoc_ret,
                direction: evt.direction,
            },
        )
    }

    fn normalized_event(
        &self,
        ingest_seq: u64,
        kind: EventKind,
        process: ProcessSnapshot,
        event_id: String,
        ts_ns: u64,
        data: NormalizedData,
    ) -> NormalizedEvent {
        NormalizedEvent {
            ingest_seq,
            event_id,
            ts_ns,
            kind,
            process,
            data,
        }
    }

    fn collect_expired(&mut self, ts_ns: u64) {
        self.expiring
            .retain(|_, proc| proc.expired_at_ns.is_some_and(|until| until > ts_ns));
    }
}

fn net_dst_ip(family: u16, addr_dst: [u8; 16]) -> Option<String> {
    match family {
        2 => Some(
            std::net::Ipv4Addr::new(addr_dst[12], addr_dst[13], addr_dst[14], addr_dst[15])
                .to_string(),
        ),
        10 => Some(std::net::Ipv6Addr::from(addr_dst).to_string()),
        _ => None,
    }
}
