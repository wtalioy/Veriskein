use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum EventKind {
    ProcExec = 1,
    MetaDrop = 2,
}

impl EventKind {
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::ProcExec),
            2 => Some(Self::MetaDrop),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DropReason {
    SeqGap = 1,
    Reordered = 2,
}

impl DropReason {
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::SeqGap),
            2 => Some(Self::Reordered),
            _ => None,
        }
    }
}
