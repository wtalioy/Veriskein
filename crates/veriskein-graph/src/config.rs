use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub default_workspace: String,
    #[serde(default)]
    pub binary_seeds: Vec<String>,
    #[serde(default)]
    pub shell_allowlist: Vec<String>,
    #[serde(default)]
    pub sensitive_allowlist: Vec<String>,
    #[serde(default)]
    pub delete_allowlist: Vec<String>,
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read agents config {}", path.display()))?;
        toml::from_str(&text).context("parse agents toml")
    }
}
