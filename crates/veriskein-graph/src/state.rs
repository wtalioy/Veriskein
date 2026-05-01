use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use veriskein_normalizer::{GlobList, NormalizedData, NormalizedEvent, WorkspaceRef};
use veriskein_proto::{AgentId, SessionId};

use crate::AgentConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    RootCandidate,
    ConfirmedRoot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub workspace: WorkspaceRef,
    pub root_pid: u32,
    pub state: SessionState,
}

pub struct GraphState {
    config: AgentConfig,
    workspaces: Vec<WorkspaceRef>,
    shell_allowlist: GlobList,
    sensitive_allowlist: GlobList,
    delete_allowlist: GlobList,
    bindings: BTreeMap<u32, Attribution>,
}

impl GraphState {
    pub fn new(config: AgentConfig, workspaces: Vec<WorkspaceRef>) -> Result<Self> {
        Ok(Self {
            shell_allowlist: GlobList::new(config.shell_allowlist.clone())?,
            sensitive_allowlist: GlobList::new(config.sensitive_allowlist.clone())?,
            delete_allowlist: GlobList::new(config.delete_allowlist.clone())?,
            config,
            workspaces,
            bindings: BTreeMap::new(),
        })
    }

    pub fn apply(&mut self, event: &NormalizedEvent) -> Option<Attribution> {
        match &event.data {
            NormalizedData::ProcFork { child_pid, .. } => {
                if let Some(parent) = self.bindings.get(&event.process.pid).cloned() {
                    self.bindings.insert(*child_pid, parent.clone());
                    return Some(parent);
                }
                None
            }
            NormalizedData::ProcExec { filename, .. } => {
                if let Some(existing) = self.bindings.get(&event.process.pid).cloned() {
                    self.bindings.insert(event.process.pid, existing.clone());
                    return Some(existing);
                }
                if self.is_seed_binary(filename) {
                    let workspace = self.workspace_for_event(event)?;
                    let session_id = SessionId::from_seed(
                        format!("{}:{}:{}", event.process.pid, filename, workspace.id).as_bytes(),
                    );
                    let agent_id = AgentId::from_seed(
                        format!("{}:{}", session_id.hex(), event.process.pid).as_bytes(),
                    );
                    let attribution = Attribution {
                        session_id,
                        agent_id,
                        workspace,
                        root_pid: event.process.pid,
                        state: SessionState::ConfirmedRoot,
                    };
                    self.bindings.insert(event.process.pid, attribution.clone());
                    return Some(attribution);
                }
                None
            }
            NormalizedData::ProcExit { .. } => self.bindings.remove(&event.process.pid),
            _ => self.bindings.get(&event.process.pid).cloned(),
        }
    }

    pub fn resolve(&self, pid: u32) -> Option<&Attribution> {
        self.bindings.get(&pid)
    }

    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    pub fn shell_allowlist(&self) -> &GlobList {
        &self.shell_allowlist
    }

    pub fn sensitive_allowlist(&self) -> &GlobList {
        &self.sensitive_allowlist
    }

    pub fn delete_allowlist(&self) -> &GlobList {
        &self.delete_allowlist
    }

    fn is_seed_binary(&self, filename: &str) -> bool {
        let basename = Path::new(filename)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(filename);
        self.config.binary_seeds.iter().any(|seed| seed == basename)
    }

    fn workspace_for_event(&self, event: &NormalizedEvent) -> Option<WorkspaceRef> {
        if let Some(workspace) = self
            .workspaces
            .iter()
            .find(|workspace| event.process.cwd.starts_with(&workspace.root))
        {
            return Some(workspace.clone());
        }

        if !self.config.default_workspace.is_empty() {
            return self
                .workspaces
                .iter()
                .find(|workspace| workspace.root == Path::new(&self.config.default_workspace))
                .cloned();
        }

        None
    }
}
