//! Normalization, path resolution, and process state ownership.

mod access;
mod config;
mod state;
#[cfg(test)]
mod tests;

pub use access::{FileAccessMode, file_access_mode};
pub use config::{
    GlobList, SensitiveConfig, SensitiveRule, WorkspaceRef, lexical_clean, load_workspaces,
};
pub use state::{
    NormalizedData, NormalizedEvent, Normalizer, PathContext, PathResolution, PathResolutionMode,
    PathVerdict, ProcessSnapshot, path_basename,
};
