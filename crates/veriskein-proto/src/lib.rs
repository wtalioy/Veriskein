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
pub use owned::{EventRef, OwnedEvent, OwnedMetaDropEvent, OwnedProcExecEvent};
pub use parse::{ParseError, parse, parse_arg_vector, parse_c_string};
pub use test_support::{build_exec_event_bytes, build_meta_drop_event_bytes};
pub use wire::{EventHeader, MetaDropEvent, ProcExecEvent};
