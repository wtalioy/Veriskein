//! Detector findings and anomaly engines.

mod base;
mod capi;
mod deadloop;
mod engine;
mod finding;
mod signals;
#[cfg(test)]
mod tests;

pub use capi::detect_cross_agent_prompt_injection;
pub use engine::DetectorEngine;
pub use finding::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, PromptEvidenceState,
    VisibilityState,
};
