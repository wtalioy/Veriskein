//! Phase 1 normalization, path resolution, and process state ownership.

mod config;
mod state;

pub use config::{
    GlobList, SensitiveConfig, SensitiveRule, WorkspaceRef, lexical_clean, load_workspaces,
};
pub use state::{
    NormalizedData, NormalizedEvent, Normalizer, PathContext, PathResolution, PathResolutionMode,
    PathVerdict, ProcessSnapshot,
};
