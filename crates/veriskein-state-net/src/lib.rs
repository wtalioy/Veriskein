//! Connection and fd identity state for Phase 2+ stream ownership.

mod state;
#[cfg(test)]
mod tests;

pub use state::{EndpointAddr, EndpointSnapshot, FdIdentityKind, FdIdentitySnapshot, StateNet};
