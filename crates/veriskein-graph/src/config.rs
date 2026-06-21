use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub default_workspace: String,
    #[serde(default)]
    pub binary_seeds: Vec<String>,
    #[serde(default)]
    pub env_hints: Vec<String>,
    #[serde(default)]
    pub argv_hints: Vec<String>,
    #[serde(default)]
    pub llm_endpoints: Vec<String>,
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

    pub fn workspace_inputs_with_default(&self, inputs: &[PathBuf]) -> Vec<PathBuf> {
        let mut out = inputs.to_vec();
        if out.is_empty() && !self.default_workspace.is_empty() {
            out.push(self.default_workspace.clone().into());
        }
        out
    }
}
