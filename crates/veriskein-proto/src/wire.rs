use plain::Plain;
use serde::Serialize;

use crate::defaults;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct EventHeader {
    // This layout is shared byte-for-byte with the BPF side.
    pub ts_ns: u64,
    pub abi_version: u32,
    pub kind: u16,
    pub total_len: u16,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub cpu: u32,
    pub seq: u64,
    pub mount_ns: u64,
    pub ret: i32,
    pub _reserved: u32,
    pub comm: [u8; defaults::TASK_COMM_LEN],
}

unsafe impl Plain for EventHeader {}

macro_rules! plain_struct {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[repr(C, packed)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name {
            pub header: EventHeader,
            $(pub $field: $ty),*
        }

        // `plain` is only sound here because the structs stay POD mirrors of
        // the kernel event payloads with no Rust-managed invariants.
        unsafe impl Plain for $name {}
    };
}

plain_struct!(ProcForkEvent {
    child_pid: u32,
    child_tid: u32,
    clone_flags: u32,
    _pad: u32
});

plain_struct!(ProcExecEvent {
    argv_len: u32,
    filename_len: u32,
    filename: [u8; defaults::PATH_INLINE_MAX],
    argv: [u8; defaults::ARGV_INLINE_MAX]
});

plain_struct!(ProcExitEvent {
    exit_code: i32,
    _pad: u32
});

plain_struct!(ProcChdirEvent {
    dirfd: i32,
    _pad: u32,
    path_len: u32,
    path: [u8; defaults::PATH_INLINE_MAX]
});

plain_struct!(FdDupEvent {
    oldfd: i32,
    newfd: i32,
    dup_ret: i32,
    _pad: u32
});

plain_struct!(FileOpenEvent {
    dirfd: i32,
    ret_fd: i32,
    flags: u32,
    mode: u32,
    inode: u64,
    dev: u64,
    path_len: u32,
    path: [u8; defaults::PATH_INLINE_MAX]
});

plain_struct!(FileUnlinkEvent {
    dirfd: i32,
    unlink_ret: i32,
    flags: u32,
    path_len: u32,
    path: [u8; defaults::PATH_INLINE_MAX]
});

plain_struct!(FileRenameEvent {
    olddirfd: i32,
    newdirfd: i32,
    rename_ret: i32,
    flags: u32,
    oldpath_len: u32,
    newpath_len: u32,
    paths: [u8; defaults::PATH_INLINE_MAX * 2]
});

plain_struct!(NetConnectEvent {
    sockfd: i32,
    connect_ret: i32,
    family: u16,
    dport_be: u16,
    sport_be: u16,
    tls_candidate: u8,
    _pad0: u8,
    _pad1: u8,
    addr_dst: [u8; 16],
    addr_src: [u8; 16]
});

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetaDropEvent {
    pub header: EventHeader,
    pub expected_seq: u64,
    pub observed_seq: u64,
    pub missing: u64,
    pub reason: u8,
    pub _reserved: [u8; 7],
}

unsafe impl Plain for MetaDropEvent {}
