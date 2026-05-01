use plain::Plain;
use serde::Serialize;

use crate::defaults;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct EventHeader {
    // The header is shared by every kernel event and is validated before any
    // payload-specific reinterpretation happens in the parser.
    pub abi_version: u32,
    pub kind: u16,
    pub header_len: u16,
    pub total_len: u32,
    pub cpu: u32,
    pub seq: u64,
    pub ts_ns: u64,
}

// SAFETY: The type is plain old data with no invalid bit patterns.
unsafe impl Plain for EventHeader {}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcExecEvent {
    // Fixed-width inline byte regions keep the wire ABI simple and verifier-
    // friendly; downstream code is responsible for turning them into strings.
    pub header: EventHeader,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub mount_ns: u64,
    pub comm: [u8; defaults::TASK_COMM_LEN],
    pub filename: [u8; defaults::PATH_INLINE_MAX],
    pub argv: [u8; defaults::ARGV_INLINE_MAX],
}

unsafe impl Plain for ProcExecEvent {}

impl Default for ProcExecEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            pid: 0,
            tgid: 0,
            ppid: 0,
            mount_ns: 0,
            comm: [0; defaults::TASK_COMM_LEN],
            filename: [0; defaults::PATH_INLINE_MAX],
            argv: [0; defaults::ARGV_INLINE_MAX],
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetaDropEvent {
    // Synthetic drop events reuse the same ABI machinery as kernel-emitted
    // events so downstream consumers do not need a side channel for loss facts.
    pub header: EventHeader,
    pub expected_seq: u64,
    pub observed_seq: u64,
    pub missing: u64,
    pub reason: u8,
    pub _reserved: [u8; 7],
}

unsafe impl Plain for MetaDropEvent {}
