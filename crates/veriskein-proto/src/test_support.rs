use crate::{
    DropReason, EventHeader, EventKind, FdDupEvent, FileOpenEvent, FileRenameEvent,
    FileUnlinkEvent, MetaDropEvent, NetConnectEvent, ProcChdirEvent, ProcExecEvent, ProcExitEvent,
    ProcForkEvent, defaults,
};

pub fn build_proc_fork_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    child_pid: u32,
    child_tid: u32,
) -> Vec<u8> {
    let event = ProcForkEvent {
        header: base_header(cpu, seq, EventKind::ProcFork, pid, tid, ppid, comm, 0),
        child_pid,
        child_tid,
        clone_flags: 0,
        _pad: 0,
    };
    as_vec(&event)
}

pub fn build_exec_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    filename: &str,
    argv: &[&str],
) -> Vec<u8> {
    let mut event = ProcExecEvent {
        header: base_header(cpu, seq, EventKind::ProcExec, pid, tid, ppid, comm, 0),
        argv_len: joined_arg_len(argv) as u32,
        filename_len: filename.len() as u32,
        filename: [0; defaults::PATH_INLINE_MAX],
        argv: [0; defaults::ARGV_INLINE_MAX],
    };
    write_c_bytes(&mut event.filename, filename.as_bytes());
    write_arg_bytes(&mut event.argv, argv);
    as_vec(&event)
}

pub fn build_proc_exit_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    exit_code: i32,
) -> Vec<u8> {
    let event = ProcExitEvent {
        header: base_header(
            cpu,
            seq,
            EventKind::ProcExit,
            pid,
            tid,
            ppid,
            comm,
            exit_code,
        ),
        exit_code,
        _pad: 0,
    };
    as_vec(&event)
}

pub fn build_proc_chdir_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    path: &str,
) -> Vec<u8> {
    let mut event = ProcChdirEvent {
        header: base_header(cpu, seq, EventKind::ProcChdir, pid, tid, ppid, comm, 0),
        dirfd: -100,
        _pad: 0,
        path_len: path.len() as u32,
        path: [0; defaults::PATH_INLINE_MAX],
    };
    write_c_bytes(&mut event.path, path.as_bytes());
    as_vec(&event)
}

pub fn build_fd_dup_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    oldfd: i32,
    newfd: i32,
    dup_ret: i32,
) -> Vec<u8> {
    let event = FdDupEvent {
        header: base_header(cpu, seq, EventKind::FdDup, pid, tid, ppid, comm, dup_ret),
        oldfd,
        newfd,
        dup_ret,
        _pad: 0,
    };
    as_vec(&event)
}

pub fn build_file_open_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    dirfd: i32,
    ret_fd: i32,
    path: &str,
) -> Vec<u8> {
    let mut event = FileOpenEvent {
        header: base_header(cpu, seq, EventKind::FileOpen, pid, tid, ppid, comm, ret_fd),
        dirfd,
        ret_fd,
        flags: 0,
        mode: 0,
        inode: 1,
        dev: 1,
        path_len: path.len() as u32,
        path: [0; defaults::PATH_INLINE_MAX],
    };
    write_c_bytes(&mut event.path, path.as_bytes());
    as_vec(&event)
}

pub fn build_file_unlink_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    dirfd: i32,
    unlink_ret: i32,
    path: &str,
) -> Vec<u8> {
    let mut event = FileUnlinkEvent {
        header: base_header(
            cpu,
            seq,
            EventKind::FileUnlink,
            pid,
            tid,
            ppid,
            comm,
            unlink_ret,
        ),
        dirfd,
        unlink_ret,
        flags: 0,
        path_len: path.len() as u32,
        path: [0; defaults::PATH_INLINE_MAX],
    };
    write_c_bytes(&mut event.path, path.as_bytes());
    as_vec(&event)
}

pub fn build_file_rename_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    olddirfd: i32,
    newdirfd: i32,
    rename_ret: i32,
    old_path: &str,
    new_path: &str,
) -> Vec<u8> {
    let mut event = FileRenameEvent {
        header: base_header(
            cpu,
            seq,
            EventKind::FileRename,
            pid,
            tid,
            ppid,
            comm,
            rename_ret,
        ),
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

pub fn build_net_connect_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    sockfd: i32,
    dport: u16,
    tls_candidate: bool,
) -> Vec<u8> {
    let event = NetConnectEvent {
        header: base_header(cpu, seq, EventKind::NetConnect, pid, tid, ppid, comm, 0),
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

pub fn build_meta_drop_event_bytes(
    cpu: u32,
    seq: u64,
    expected_seq: u64,
    observed_seq: u64,
    missing: u64,
    reason: DropReason,
) -> Vec<u8> {
    let event = MetaDropEvent {
        header: base_header(cpu, seq, EventKind::MetaDrop, 0, 0, 0, "meta", 0),
        expected_seq,
        observed_seq,
        missing,
        reason: reason as u8,
        _reserved: [0; 7],
    };
    as_vec(&event)
}

fn base_header(
    cpu: u32,
    seq: u64,
    kind: EventKind,
    pid: u32,
    tid: u32,
    ppid: u32,
    comm: &str,
    ret: i32,
) -> EventHeader {
    let mut header = EventHeader {
        ts_ns: 1_700_000_000_000_000_000 + seq,
        abi_version: defaults::EVT_ABI_VERSION,
        kind: kind as u16,
        total_len: 0,
        pid,
        tid,
        ppid,
        uid: 1000,
        gid: 1000,
        cgroup_id: 0,
        cpu,
        seq,
        mount_ns: 42,
        ret,
        _reserved: 0,
        comm: [0; defaults::TASK_COMM_LEN],
    };
    write_c_bytes(&mut header.comm, comm.as_bytes());
    header
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
