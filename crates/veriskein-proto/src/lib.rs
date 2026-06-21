//! Phase 0 ABI mirrors, ids, defaults, and zero-copy parsers.
//! This crate owns the kernel/user event contract and does not perform
//! collection, normalization, or alert policy.

pub mod defaults;

mod contracts;
mod ids;
mod kinds;
mod owned;
mod parse;
mod runtime;
mod test_support;
mod wire;

pub use contracts::{DETECTOR_INPUTS, RECONCILERS, REGISTRY_OWNERS};
pub use ids::{AgentId, ArtifactId, ChainId, EventId, PromptId, SessionId};
pub use kinds::{DropReason, EventKind};
pub use owned::{
    EventRef, OwnedEvent, OwnedFdDupEvent, OwnedFileOpenEvent, OwnedFileRenameEvent,
    OwnedFileUnlinkEvent, OwnedMetaDropEvent, OwnedNetConnectEvent, OwnedProcChdirEvent,
    OwnedProcExecEvent, OwnedProcExitEvent, OwnedProcForkEvent,
};
pub use parse::{ParseError, parse, parse_arg_vector, parse_c_string, parse_path_pair};
pub use runtime::{AttributionStrength, Role, RoleTag, VisibilityState};
pub use test_support::EventFixture;
pub use wire::{
    EventHeader, FdDupEvent, FileOpenEvent, FileRenameEvent, FileUnlinkEvent, MetaDropEvent,
    NetConnectEvent, ProcChdirEvent, ProcExecEvent, ProcExitEvent, ProcForkEvent,
};
