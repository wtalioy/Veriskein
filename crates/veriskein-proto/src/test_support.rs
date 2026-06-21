use crate::{
    ContentChannel, ContentDirection, ContentFragEvent, DropReason, EventHeader, EventKind,
    FdDupEvent, FileOpenEvent, FileRenameEvent, FileUnlinkEvent, MetaDropEvent, NetConnectEvent,
    ProcChdirEvent, ProcExecEvent, ProcExitEvent, ProcForkEvent, defaults,
};

#[derive(Debug, Clone)]
pub struct EventFixture {
    pub cpu: u32,
    pub seq: u64,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub comm: String,
}

impl EventFixture {
    pub fn new(cpu: u32, seq: u64, pid: u32, tid: u32, ppid: u32, comm: impl Into<String>) -> Self {
        Self {
            cpu,
            seq,
            pid,
            tid,
            ppid,
            comm: comm.into(),
        }
    }

    pub fn for_pid(seq: u64, pid: u32, ppid: u32, comm: impl Into<String>) -> Self {
        Self::new(0, seq, pid, pid, ppid, comm)
    }

    pub fn with_seq(&self, seq: u64) -> Self {
        Self {
            seq,
            ..self.clone()
        }
    }

    pub fn exec(&self, filename: &str, argv: &[&str]) -> Vec<u8> {
        let mut event = ProcExecEvent {
            header: self.header(EventKind::ProcExec, 0),
            argv_len: joined_arg_len(argv) as u32,
            filename_len: filename.len() as u32,
            filename: [0; defaults::PATH_INLINE_MAX],
            argv: [0; defaults::ARGV_INLINE_MAX],
        };
        write_c_bytes(&mut event.filename, filename.as_bytes());
        write_arg_bytes(&mut event.argv, argv);
        as_vec(&event)
    }

    pub fn fork(&self, child_pid: u32, child_tid: u32) -> Vec<u8> {
        let event = ProcForkEvent {
            header: self.header(EventKind::ProcFork, 0),
            child_pid,
            child_tid,
            clone_flags: 0,
            _pad: 0,
        };
        as_vec(&event)
    }

    pub fn exit(&self, exit_code: i32) -> Vec<u8> {
        let event = ProcExitEvent {
            header: self.header(EventKind::ProcExit, exit_code),
            exit_code,
            _pad: 0,
        };
        as_vec(&event)
    }

    pub fn chdir(&self, path: &str) -> Vec<u8> {
        let mut event = ProcChdirEvent {
            header: self.header(EventKind::ProcChdir, 0),
            dirfd: -100,
            _pad: 0,
            path_len: path.len() as u32,
            path: [0; defaults::PATH_INLINE_MAX],
        };
        write_c_bytes(&mut event.path, path.as_bytes());
        as_vec(&event)
    }

    pub fn dup(&self, oldfd: i32, newfd: i32, dup_ret: i32) -> Vec<u8> {
        let event = FdDupEvent {
            header: self.header(EventKind::FdDup, dup_ret),
            oldfd,
            newfd,
            dup_ret,
            _pad: 0,
        };
        as_vec(&event)
    }

    pub fn open(&self, dirfd: i32, ret_fd: i32, path: &str) -> Vec<u8> {
        self.open_with_flags(dirfd, ret_fd, path, 0)
    }

    pub fn open_with_flags(&self, dirfd: i32, ret_fd: i32, path: &str, flags: u32) -> Vec<u8> {
        let mut event = FileOpenEvent {
            header: self.header(EventKind::FileOpen, ret_fd),
            dirfd,
            ret_fd,
            flags,
            mode: 0,
            inode: 1,
            dev: 1,
            path_len: path.len() as u32,
            path: [0; defaults::PATH_INLINE_MAX],
        };
        write_c_bytes(&mut event.path, path.as_bytes());
        as_vec(&event)
    }

    pub fn unlink(&self, dirfd: i32, unlink_ret: i32, path: &str) -> Vec<u8> {
        let mut event = FileUnlinkEvent {
            header: self.header(EventKind::FileUnlink, unlink_ret),
            dirfd,
            unlink_ret,
            flags: 0,
            path_len: path.len() as u32,
            path: [0; defaults::PATH_INLINE_MAX],
        };
        write_c_bytes(&mut event.path, path.as_bytes());
        as_vec(&event)
    }

    pub fn rename(
        &self,
        olddirfd: i32,
        newdirfd: i32,
        rename_ret: i32,
        old_path: &str,
        new_path: &str,
    ) -> Vec<u8> {
        let mut event = FileRenameEvent {
            header: self.header(EventKind::FileRename, rename_ret),
            olddirfd,
            newdirfd,
            rename_ret,
            flags: 0,
            oldpath_len: old_path.len() as u32,
            newpath_len: new_path.len() as u32,
            paths: [0; defaults::PATH_INLINE_MAX * 2],
        };
        write_path_pair(&mut event.paths, old_path, new_path);
        as_vec(&event)
    }

    pub fn connect(&self, sockfd: i32, dport: u16, tls_candidate: bool) -> Vec<u8> {
        let event = NetConnectEvent {
            header: self.header(EventKind::NetConnect, 0),
            sockfd,
            connect_ret: 0,
            family: 2,
            dport_be: dport.to_be(),
            sport_be: 0,
            tls_candidate: u8::from(tls_candidate),
            _pad0: 0,
            _pad1: 0,
            addr_dst: [0; 16],
            addr_src: [0; 16],
        };
        as_vec(&event)
    }

    pub fn meta_drop(
        &self,
        expected_seq: u64,
        observed_seq: u64,
        missing: u64,
        reason: DropReason,
    ) -> Vec<u8> {
        let event = MetaDropEvent {
            header: self.header(EventKind::MetaDrop, 0),
            expected_seq,
            observed_seq,
            missing,
            reason: reason as u8,
            _reserved: [0; 7],
        };
        as_vec(&event)
    }

    pub fn content_frag(
        &self,
        ssl_ctx: u64,
        stream_offset: u64,
        channel: ContentChannel,
        direction: ContentDirection,
        data: &[u8],
        truncated: bool,
    ) -> Vec<u8> {
        let mut event = ContentFragEvent {
            header: self.header(EventKind::ContentFrag, 0),
            ssl_ctx,
            stream_offset,
            byte_len: data.len() as u32 + u32::from(truncated),
            frag_len: data.len().min(defaults::CONTENT_INLINE_MAX) as u32,
            channel: channel as u8,
            direction: direction as u8,
            flags: u16::from(truncated),
            _reserved: 0,
            data: [0; defaults::CONTENT_INLINE_MAX],
        };
        let len = data.len().min(event.data.len());
        event.data[..len].copy_from_slice(&data[..len]);
        as_vec(&event)
    }

    fn header(&self, kind: EventKind, ret: i32) -> EventHeader {
        let mut header = EventHeader {
            ts_ns: 1_700_000_000_000_000_000 + self.seq,
            abi_version: defaults::EVT_ABI_VERSION,
            kind: kind as u16,
            total_len: 0,
            pid: self.pid,
            tid: self.tid,
            ppid: self.ppid,
            uid: 1000,
            gid: 1000,
            cgroup_id: 0,
            cpu: self.cpu,
            seq: self.seq,
            mount_ns: 42,
            ret,
            _reserved: 0,
            comm: [0; defaults::TASK_COMM_LEN],
        };
        write_c_bytes(&mut header.comm, self.comm.as_bytes());
        header
    }
}

fn as_vec<T: plain::Plain>(event: &T) -> Vec<u8> {
    let mut out = unsafe { plain::as_bytes(event) }.to_vec();
    let len = out.len() as u16;
    out[14..16].copy_from_slice(&len.to_ne_bytes());
    out
}

fn write_c_bytes(target: &mut [u8], source: &[u8]) {
    let max = target.len().saturating_sub(1);
    let len = source.len().min(max);
    target[..len].copy_from_slice(&source[..len]);
    if !target.is_empty() {
        target[len] = 0;
    }
}

fn write_arg_bytes(target: &mut [u8], args: &[&str]) {
    let mut offset = 0;
    for arg in args {
        let bytes = arg.as_bytes();
        let needed = bytes.len() + 1;
        if offset + needed > target.len() {
            break;
        }
        target[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
        target[offset] = 0;
        offset += 1;
    }
}

fn write_path_pair(target: &mut [u8], left: &str, right: &str) {
    write_arg_bytes(target, &[left, right]);
}

fn joined_arg_len(args: &[&str]) -> usize {
    args.iter().map(|arg| arg.len() + 1).sum()
}
