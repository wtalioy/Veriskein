//! Root election, session attribution, and role state.

mod config;
mod evidence;
mod state;
#[cfg(test)]
mod tests;

pub use config::AgentConfig;
pub use evidence::{EnvEvidence, LlmEndpointResolver};
pub use state::{Attribution, GraphState, RootEvidence, RootEvidenceKind, SessionState};
