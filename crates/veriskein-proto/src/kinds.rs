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
    ContentFrag = 30,
    TlsAssoc = 31,
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
            30 => Some(Self::ContentFrag),
            31 => Some(Self::TlsAssoc),
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
            Self::ContentFrag => "content_frag",
            Self::TlsAssoc => "tls_assoc",
            Self::MetaDrop => "meta_drop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentChannel {
    Tls = 1,
    Stdio = 2,
    Pipe = 3,
    Mcp = 4,
}

impl ContentChannel {
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Tls),
            2 => Some(Self::Stdio),
            3 => Some(Self::Pipe),
            4 => Some(Self::Mcp),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Stdio => "stdio",
            Self::Pipe => "pipe",
            Self::Mcp => "mcp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentDirection {
    Read = 1,
    Write = 2,
}

impl ContentDirection {
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
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
