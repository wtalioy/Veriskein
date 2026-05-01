use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use veriskein_normalizer::{GlobList, NormalizedData, NormalizedEvent, WorkspaceRef};
use veriskein_proto::{AgentId, SessionId, defaults};

use crate::AgentConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    RootCandidate,
    ConfirmedRoot,
    Draining,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub workspace: WorkspaceRef,
    pub root_pid: u32,
    pub state: SessionState,
}

#[derive(Debug, Clone)]
struct DrainingBinding {
    attribution: Attribution,
    expires_at_ns: u64,
}

pub struct GraphState {
    config: AgentConfig,
    workspaces: Vec<WorkspaceRef>,
    shell_allowlist: GlobList,
    sensitive_allowlist: GlobList,
    delete_allowlist: GlobList,
    bindings: BTreeMap<u32, Attribution>,
    draining: BTreeMap<u32, DrainingBinding>,
}

impl GraphState {
    pub fn new(config: AgentConfig, workspaces: Vec<WorkspaceRef>) -> Result<Self> {
        let mut delete_patterns = config.delete_allowlist.clone();
        // These runtime-owned scratch locations are noisy enough that the graph
        // bakes them in even when the user config omits them.
        for pattern in ["/var/tmp/**", "/run/**", "/dev/shm/**"] {
            if !delete_patterns.iter().any(|existing| existing == pattern) {
                delete_patterns.push(pattern.to_string());
            }
        }
        Ok(Self {
            shell_allowlist: GlobList::new(config.shell_allowlist.clone())?,
            sensitive_allowlist: GlobList::new(config.sensitive_allowlist.clone())?,
            delete_allowlist: GlobList::new(delete_patterns)?,
            config,
            workspaces,
            bindings: BTreeMap::new(),
            draining: BTreeMap::new(),
        })
    }

    pub fn apply(&mut self, event: &NormalizedEvent) -> Option<Attribution> {
        self.collect_garbage(event.ts_ns);
        match &event.data {
            NormalizedData::ProcFork { child_pid, .. } => {
                // Child processes inherit the active session immediately so the
                // next syscall after fork is still attributable.
                let parent = self.resolve(event.process.pid)?.clone();
                self.bindings.insert(*child_pid, parent.clone());
                Some(parent)
            }
            NormalizedData::ProcExec { filename, .. } => {
                if let Some(existing) = self.resolve(event.process.pid).cloned() {
                    let mut existing = existing;
                    if matches!(existing.state, SessionState::Draining) {
                        existing.state = SessionState::ConfirmedRoot;
                    }
                    self.draining.remove(&event.process.pid);
                    self.bindings.insert(event.process.pid, existing.clone());
                    return Some(existing);
                }
                self.seed_root_candidate(event, filename)
            }
            NormalizedData::ProcExit { .. } => self.on_exit(event),
            _ => self.resolve(event.process.pid).cloned(),
        }
    }

    pub fn resolve(&self, pid: u32) -> Option<&Attribution> {
        self.bindings
            .get(&pid)
            .or_else(|| self.draining.get(&pid).map(|entry| &entry.attribution))
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

    fn seed_root_candidate(
        &mut self,
        event: &NormalizedEvent,
        filename: &str,
    ) -> Option<Attribution> {
        if !self.is_seed_binary(filename) {
            return None;
        }
        let workspace = self.workspace_for_event(event)?;
        let mut attribution = Attribution {
            session_id: SessionId::from_seed(
                format!("{}:{}:{}", event.process.pid, filename, workspace.id).as_bytes(),
            ),
            agent_id: AgentId::from_seed(
                format!("{}:{}", event.process.pid, event.event_id).as_bytes(),
            ),
            workspace,
            root_pid: event.process.pid,
            state: SessionState::RootCandidate,
        };
        // The state machine keeps the explicit candidate step even though Phase
        // 1 confirms immediately, because later heuristics may require delayed
        // promotion without changing the external graph contract.
        self.bindings.insert(event.process.pid, attribution.clone());
        attribution.state = SessionState::ConfirmedRoot;
        self.bindings.insert(event.process.pid, attribution.clone());
        Some(attribution)
    }

    fn on_exit(&mut self, event: &NormalizedEvent) -> Option<Attribution> {
        let pid = event.process.pid;
        let mut attribution = self
            .bindings
            .remove(&pid)
            .or_else(|| self.draining.remove(&pid).map(|entry| entry.attribution))?;
        attribution.state = SessionState::Draining;
        self.draining.insert(
            pid,
            DrainingBinding {
                attribution: attribution.clone(),
                // Draining keeps late file/network events attributable after a
                // root process exits but children or delayed cleanup linger.
                expires_at_ns: event.ts_ns + defaults::SESSION_DRAIN_SECS * 1_000_000_000,
            },
        );
        Some(attribution)
    }

    fn collect_garbage(&mut self, ts_ns: u64) {
        self.draining.retain(|_, entry| entry.expires_at_ns > ts_ns);
    }

    fn is_seed_binary(&self, filename: &str) -> bool {
        let basename = Path::new(filename)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(filename);
        self.config.binary_seeds.iter().any(|seed| seed == basename)
    }

    fn workspace_for_event(&self, event: &NormalizedEvent) -> Option<WorkspaceRef> {
        // CWD is the primary workspace signal in Phase 1; a configured default
        // only fills the gap when the process has not entered a workspace yet.
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
