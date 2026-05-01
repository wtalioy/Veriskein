//! Phase 1 detector findings.

mod engine;
mod finding;
#[cfg(test)]
mod tests;

pub use engine::detect;
pub use finding::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, VisibilityState,
};
