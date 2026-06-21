//! Phase 1 detector findings.

mod base;
mod deadloop;
mod engine;
mod finding;
mod signals;
#[cfg(test)]
mod tests;

pub use engine::{DetectorEngine, detect};
pub use finding::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, VisibilityState,
};
