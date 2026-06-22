//! ABI mirrors, ids, defaults, and zero-copy parsers.
//! This crate owns the kernel/user event contract and does not perform
//! collection, normalization, or alert policy.

pub mod defaults;

mod contracts;
mod kinds;
mod net;
mod owned;
mod parse;
mod test_support;
mod types;
mod wire;

#[cfg(test)]
mod tests;

pub use contracts::{DETECTOR_INPUTS, RECONCILERS, REGISTRY_OWNERS};
pub use kinds::{ContentChannel, ContentDirection, DropReason, EventKind};
pub use net::{AF_INET_RAW, AF_INET6_RAW, net_addr_from_raw, raw_net_addr};
pub use owned::{
    EventRef, FdDupEffect, OwnedContentFragEvent, OwnedEvent, OwnedFdDupEvent, OwnedFileOpenEvent,
    OwnedFileRenameEvent, OwnedFileUnlinkEvent, OwnedMetaDropEvent, OwnedNetConnectEvent,
    OwnedProcChdirEvent, OwnedProcExecEvent, OwnedProcExitEvent, OwnedProcForkEvent,
    OwnedTlsAssocEvent, event_id_from_header, event_id_hex_from_header, fd_dup_effect,
};
pub use parse::{ParseError, parse, parse_arg_vector, parse_c_string, parse_path_pair};
pub use test_support::EventFixture;
pub use types::{
    AgentId, ArtifactId, AttributionStrength, ChainId, EventId, PromptId, Role, RoleTag, SessionId,
    VisibilityState,
};
pub use wire::{
    ContentFragEvent, EventHeader, FdDupEvent, FileOpenEvent, FileRenameEvent, FileUnlinkEvent,
    MetaDropEvent, NetConnectEvent, ProcChdirEvent, ProcExecEvent, ProcExitEvent, ProcForkEvent,
    TlsAssocEvent,
};
