//! Prompt storage and same-session correlation.

mod prompt;

pub use prompt::{
    PromptEvidence, PromptEvidenceKind, PromptInput, PromptRiskLink, PromptStore,
    RepeatedPromptSignal,
};
