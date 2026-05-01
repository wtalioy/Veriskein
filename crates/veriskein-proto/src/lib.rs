//! Phase 0 ABI mirrors, ids, defaults, and zero-copy parsers.
//! This crate owns the kernel/user event contract and does not perform
//! collection, normalization, or alert policy.

pub mod defaults;

mod ids;
mod kinds;
mod owned;
mod parse;
mod test_support;
mod wire;

pub use ids::{AgentId, ArtifactId, ChainId, EventId, PromptId, SessionId};
pub use kinds::{DropReason, EventKind};
pub use owned::{
    EventRef, OwnedEvent, OwnedFdDupEvent, OwnedFileOpenEvent, OwnedFileRenameEvent,
    OwnedFileUnlinkEvent, OwnedMetaDropEvent, OwnedNetConnectEvent, OwnedProcChdirEvent,
    OwnedProcExecEvent, OwnedProcExitEvent, OwnedProcForkEvent,
};
pub use parse::{ParseError, parse, parse_arg_vector, parse_c_string, parse_path_pair};
pub use test_support::{
    build_exec_event_bytes, build_fd_dup_event_bytes, build_file_open_event_bytes,
    build_file_rename_event_bytes, build_file_unlink_event_bytes, build_meta_drop_event_bytes,
    build_net_connect_event_bytes, build_proc_chdir_event_bytes, build_proc_exit_event_bytes,
    build_proc_fork_event_bytes,
};
pub use wire::{
    EventHeader, FdDupEvent, FileOpenEvent, FileRenameEvent, FileUnlinkEvent, MetaDropEvent,
    NetConnectEvent, ProcChdirEvent, ProcExecEvent, ProcExitEvent, ProcForkEvent,
};
