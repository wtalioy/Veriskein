//! Phase 1 root election and session attribution.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use veriskein_normalizer::{GlobList, NormalizedData, NormalizedEvent, WorkspaceRef};
use veriskein_proto::{AgentId, SessionId};

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
                    let agent_id =
                        AgentId::from_seed(format!("{}:{}", session_id.hex(), event.process.pid).as_bytes());
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

#[cfg(test)]
mod tests {
    use veriskein_normalizer::{NormalizedData, NormalizedEvent, ProcessSnapshot, WorkspaceRef};
    use veriskein_proto::EventKind;

    use super::{AgentConfig, GraphState};

    fn graph() -> GraphState {
        GraphState::new(
            AgentConfig {
                default_workspace: "/tmp/ws".to_string(),
                binary_seeds: vec!["claude".to_string()],
                shell_allowlist: Vec::new(),
                sensitive_allowlist: Vec::new(),
                delete_allowlist: Vec::new(),
            },
            vec![WorkspaceRef {
                id: "ws-default".to_string(),
                root: "/tmp/ws".into(),
            }],
        )
        .expect("graph")
    }

    fn exec_event(pid: u32, filename: &str) -> NormalizedEvent {
        NormalizedEvent {
            ingest_seq: 1,
            event_id: format!("evt-{pid}"),
            ts_ns: 1,
            kind: EventKind::ProcExec,
            process: ProcessSnapshot {
                pid,
                tid: pid,
                ppid: 1,
                exe: filename.to_string(),
                comm: "claude".to_string(),
                argv: vec!["claude".to_string()],
                cwd: "/tmp/ws".into(),
            },
            data: NormalizedData::ProcExec {
                filename: filename.to_string(),
                argv: vec!["claude".to_string()],
            },
        }
    }

    #[test]
    fn binary_seed_confirms_root_immediately() {
        let mut graph = graph();
        let binding = graph.apply(&exec_event(100, "/usr/bin/claude")).expect("binding");
        assert_eq!(binding.root_pid, 100);
        assert_eq!(binding.workspace.root, WorkspaceRef { id: "ws-default".to_string(), root: "/tmp/ws".into() }.root);
    }

    #[test]
    fn fork_inherits_session() {
        let mut graph = graph();
        graph.apply(&exec_event(100, "/usr/bin/claude"));
        let fork = NormalizedEvent {
            ingest_seq: 2,
            event_id: "evt-fork".to_string(),
            ts_ns: 2,
            kind: EventKind::ProcFork,
            process: ProcessSnapshot {
                pid: 100,
                tid: 100,
                ppid: 1,
                exe: "/usr/bin/claude".to_string(),
                comm: "claude".to_string(),
                argv: vec!["claude".to_string()],
                cwd: "/tmp/ws".into(),
            },
            data: NormalizedData::ProcFork {
                child_pid: 101,
                child_tid: 101,
            },
        };
        graph.apply(&fork);
        assert!(graph.resolve(101).is_some());
    }

    #[test]
    fn allowlists_use_globs() {
        let graph = GraphState::new(
            AgentConfig {
                default_workspace: "/tmp/ws".to_string(),
                binary_seeds: vec!["claude".to_string()],
                shell_allowlist: vec!["/bin/*".to_string()],
                sensitive_allowlist: vec!["/etc/*".to_string()],
                delete_allowlist: vec!["/tmp/**".to_string()],
            },
            vec![WorkspaceRef {
                id: "ws-default".to_string(),
                root: "/tmp/ws".into(),
            }],
        )
        .expect("graph");
        assert!(graph.shell_allowlist().is_match("/bin/sh"));
        assert!(graph.sensitive_allowlist().is_match("/etc/shadow"));
        assert!(graph.delete_allowlist().is_match("/tmp/allowed/file.txt"));
    }

    #[test]
    fn no_workspace_means_no_binding() {
        let mut graph = GraphState::new(
            AgentConfig {
                default_workspace: "/tmp/ws".to_string(),
                binary_seeds: vec!["claude".to_string()],
                shell_allowlist: Vec::new(),
                sensitive_allowlist: Vec::new(),
                delete_allowlist: Vec::new(),
            },
            Vec::new(),
        )
        .expect("graph");
        assert!(graph.apply(&exec_event(200, "/usr/bin/claude")).is_none());
    }
}
