//! Phase 1 root election and session attribution.

mod config;
mod state;
#[cfg(test)]
mod tests;

pub use config::AgentConfig;
pub use state::{Attribution, GraphState, SessionState};
