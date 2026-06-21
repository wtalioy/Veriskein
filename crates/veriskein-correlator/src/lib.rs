//! Prompt, artifact, and evidence-chain correlation.

mod artifact;
mod capi;
mod chain;
mod matching;
mod prompt;
mod redaction;

pub use artifact::{ArtifactInput, ArtifactStore, SourceArtifact, SourceLocator, SourceType};
pub use capi::{CapiState, FileEventInput, InjectionKeywordConfig};
pub use chain::{
    ChainInput, ChainRiskKind, ComponentScores, CrossSessionMatchCandidate, EvidenceChain,
    MatchTier, PropagationFact, build_evidence_chain, gated_match_candidate,
};
pub use matching::{ContentSignature, match_score, minhash_jaccard, normalize_text};
pub use prompt::{
    PromptEvidence, PromptEvidenceKind, PromptInput, PromptRiskLink, PromptSnapshot, PromptStore,
    RepeatedPromptSignal,
};
pub use redaction::{RedactionMode, redact_excerpt, redact_excerpt_string};
