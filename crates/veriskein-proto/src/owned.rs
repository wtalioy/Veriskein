use serde::Serialize;

use crate::{DropReason, EventHeader, EventId, EventKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnedProcExecEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub mount_ns: u64,
    pub comm: String,
    pub filename: String,
    pub argv: Vec<String>,
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
    ProcExec(OwnedProcExecEvent),
    MetaDrop(OwnedMetaDropEvent),
}

impl OwnedEvent {
    pub fn header(&self) -> &EventHeader {
        match self {
            Self::ProcExec(evt) => &evt.header,
            Self::MetaDrop(evt) => &evt.header,
        }
    }

    pub fn event_id(&self) -> EventId {
        let header = self.header();
        let cpu = header.cpu;
        let seq = header.seq;
        let ts_ns = header.ts_ns;
        let kind = header.kind;
        let seed = format!("{cpu}:{seq}:{ts_ns}:{kind}");
        EventId::from_seed(seed.as_bytes())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EventRef<'a> {
    ProcExec(&'a crate::ProcExecEvent),
    MetaDrop(&'a crate::MetaDropEvent),
}

impl<'a> EventRef<'a> {
    pub fn header(&self) -> &EventHeader {
        match self {
            Self::ProcExec(evt) => &evt.header,
            Self::MetaDrop(evt) => &evt.header,
        }
    }

    pub fn kind(&self) -> EventKind {
        match self {
            Self::ProcExec(_) => EventKind::ProcExec,
            Self::MetaDrop(_) => EventKind::MetaDrop,
        }
    }

    pub fn to_owned(self) -> OwnedEvent {
        match self {
            // Crossing into owned events is where we normalize byte-oriented wire
            // fields into ordinary Rust strings/collections for downstream crates.
            Self::ProcExec(evt) => OwnedEvent::ProcExec(OwnedProcExecEvent {
                header: evt.header,
                pid: evt.pid,
                tgid: evt.tgid,
                ppid: evt.ppid,
                mount_ns: evt.mount_ns,
                comm: crate::parse_c_string(&evt.comm),
                filename: crate::parse_c_string(&evt.filename),
                argv: crate::parse_arg_vector(&evt.argv),
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
