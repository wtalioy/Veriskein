use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum EventKind {
    ProcFork = 1,
    ProcExec = 2,
    ProcExit = 3,
    ProcChdir = 4,
    FdDup = 5,
    FileOpen = 10,
    FileUnlink = 11,
    FileRename = 12,
    NetConnect = 20,
    MetaDrop = 250,
}

impl EventKind {
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::ProcFork),
            2 => Some(Self::ProcExec),
            3 => Some(Self::ProcExit),
            4 => Some(Self::ProcChdir),
            5 => Some(Self::FdDup),
            10 => Some(Self::FileOpen),
            11 => Some(Self::FileUnlink),
            12 => Some(Self::FileRename),
            20 => Some(Self::NetConnect),
            250 => Some(Self::MetaDrop),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcFork => "proc_fork",
            Self::ProcExec => "proc_exec",
            Self::ProcExit => "proc_exit",
            Self::ProcChdir => "proc_chdir",
            Self::FdDup => "fd_dup",
            Self::FileOpen => "file_open",
            Self::FileUnlink => "file_unlink",
            Self::FileRename => "file_rename",
            Self::NetConnect => "net_connect",
            Self::MetaDrop => "meta_drop",
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
