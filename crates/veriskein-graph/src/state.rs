use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use veriskein_normalizer::{
    GlobList, NormalizedData, NormalizedEvent, ProcessSnapshot, WorkspaceRef, path_basename,
};
use veriskein_proto::{AgentId, AttributionStrength, Role, RoleTag, SessionId, defaults};

use crate::AgentConfig;
use crate::evidence::EnvEvidence;

mod roles;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    RootCandidate,
    ConfirmedRoot,
    Draining,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootEvidenceKind {
    BinarySeed,
    EnvHint,
    ArgvHint,
    LlmConnect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootEvidence {
    pub kind: RootEvidenceKind,
    pub value: String,
    pub ts_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub lineage_id: String,
    pub workspace: WorkspaceRef,
    pub root_pid: u32,
    pub state: SessionState,
    pub role: Role,
    pub role_version: u32,
    pub role_tags: Vec<RoleTag>,
    pub attribution_strength: AttributionStrength,
    pub root_evidence: Vec<RootEvidence>,
    pub revocable_until_ns: Option<u64>,
}

impl Attribution {
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self.state,
            SessionState::ConfirmedRoot | SessionState::Draining
        )
    }
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
    endpoint_ips: BTreeSet<IpAddr>,
    env_evidence: BTreeMap<u32, EnvEvidence>,
    bindings: BTreeMap<u32, Attribution>,
    draining: BTreeMap<u32, DrainingBinding>,
}

impl GraphState {
    pub fn new(config: AgentConfig, workspaces: Vec<WorkspaceRef>) -> Result<Self> {
        let mut delete_patterns = config.delete_allowlist.clone();
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
            endpoint_ips: BTreeSet::new(),
            env_evidence: BTreeMap::new(),
            bindings: BTreeMap::new(),
            draining: BTreeMap::new(),
        })
    }

    pub fn seed_from_snapshot(
        &mut self,
        snapshot: &ProcessSnapshot,
        env_evidence: EnvEvidence,
    ) -> Option<Attribution> {
        if self.bindings.contains_key(&snapshot.pid) || self.draining.contains_key(&snapshot.pid) {
            return self.resolve(snapshot.pid).cloned();
        }
        if !env_evidence.is_empty() {
            self.env_evidence.insert(snapshot.pid, env_evidence);
        }
        let event = NormalizedEvent {
            ingest_seq: 0,
            event_id: format!("startup-{}", snapshot.pid),
            ts_ns: 0,
            kind: veriskein_proto::EventKind::ProcExec,
            process: snapshot.clone(),
            data: NormalizedData::ProcExec {
                filename: snapshot.exe.clone(),
                argv: snapshot.argv.clone(),
            },
        };
        self.seed_root_candidate(&event, &snapshot.exe, &snapshot.argv)
    }

    pub fn apply_env_evidence(
        &mut self,
        pid: u32,
        env_evidence: EnvEvidence,
        ts_ns: u64,
    ) -> Option<Attribution> {
        if env_evidence.is_empty() {
            return self.resolve(pid).cloned();
        }
        self.env_evidence.insert(pid, env_evidence.clone());
        let evidence = env_evidence
            .hits()
            .iter()
            .map(|hint| RootEvidence {
                kind: RootEvidenceKind::EnvHint,
                value: hint.clone(),
                ts_ns,
            })
            .collect::<Vec<_>>();
        self.merge_root_evidence(pid, evidence)
    }

    pub fn refresh_endpoint_ips<I>(&mut self, resolved_ips: I)
    where
        I: IntoIterator<Item = IpAddr>,
    {
        self.endpoint_ips = resolved_ips.into_iter().collect();
    }

    pub fn apply(&mut self, event: &NormalizedEvent) -> Option<Attribution> {
        self.collect_garbage(event.ts_ns);
        match &event.data {
            NormalizedData::ProcFork { child_pid, .. } => {
                let parent = self.resolve(event.process.pid)?.clone();
                let child = self.child_binding(*child_pid, event, &parent);
                self.bindings.insert(*child_pid, child.clone());
                Some(child)
            }
            NormalizedData::ProcExec { filename, argv } => {
                if self.draining.contains_key(&event.process.pid)
                    && !self.bindings.contains_key(&event.process.pid)
                {
                    self.draining.remove(&event.process.pid);
                    return self.seed_root_candidate(event, filename, argv);
                }
                if let Some(existing) = self.resolve(event.process.pid).cloned() {
                    let mut upgraded = existing;
                    if matches!(upgraded.state, SessionState::RootCandidate)
                        && event.process.pid == upgraded.root_pid
                    {
                        upgraded
                            .root_evidence
                            .extend(self.exec_evidence(event, filename, argv));
                        upgraded.attribution_strength =
                            strength_for_evidence(&upgraded.root_evidence);
                        self.confirm_if_ready(&mut upgraded);
                    }
                    self.apply_role(&mut upgraded, event, filename);
                    self.draining.remove(&event.process.pid);
                    self.bindings.insert(event.process.pid, upgraded.clone());
                    return Some(upgraded);
                }
                self.seed_root_candidate(event, filename, argv)
            }
            NormalizedData::NetConnect { .. } => self.on_connect(event),
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
        argv: &[String],
    ) -> Option<Attribution> {
        let workspace = self.workspace_for_event(event)?;
        let evidence = self.exec_evidence(event, filename, argv);
        if evidence.is_empty() {
            return None;
        }

        let lineage_id = veriskein_proto::EventId::from_seed(
            format!(
                "{}:{}:{}:{}:{}",
                event.process.pid,
                event.ts_ns,
                event.process.ppid,
                event.process.cwd.display(),
                filename
            )
            .as_bytes(),
        )
        .hex();
        let session_id = SessionId::from_seed(format!("{lineage_id}:{}", workspace.id).as_bytes());
        let mut attribution = Attribution {
            session_id,
            agent_id: AgentId::from_seed(
                format!("{lineage_id}:{}:{}", event.process.pid, event.ts_ns).as_bytes(),
            ),
            lineage_id: lineage_id.clone(),
            workspace,
            root_pid: event.process.pid,
            state: SessionState::RootCandidate,
            role: Role::RootAgent,
            role_version: 1,
            role_tags: Vec::new(),
            attribution_strength: strength_for_evidence(&evidence),
            root_evidence: evidence,
            revocable_until_ns: Some(
                event.ts_ns + defaults::AGENT_PROMOTION_WINDOW_S * 1_000_000_000,
            ),
        };
        self.confirm_if_ready(&mut attribution);
        self.bindings.insert(event.process.pid, attribution.clone());
        Some(attribution)
    }

    fn exec_evidence(
        &self,
        event: &NormalizedEvent,
        filename: &str,
        argv: &[String],
    ) -> Vec<RootEvidence> {
        let mut evidence = Vec::new();
        if self.is_seed_binary(filename) {
            evidence.push(RootEvidence {
                kind: RootEvidenceKind::BinarySeed,
                value: path_basename(filename).to_string(),
                ts_ns: event.ts_ns,
            });
        }
        for hint in self.argv_hits(argv) {
            evidence.push(RootEvidence {
                kind: RootEvidenceKind::ArgvHint,
                value: hint,
                ts_ns: event.ts_ns,
            });
        }
        for hint in self.cached_env_hits(event.process.pid) {
            evidence.push(RootEvidence {
                kind: RootEvidenceKind::EnvHint,
                value: hint,
                ts_ns: event.ts_ns,
            });
        }
        evidence
    }

    fn on_connect(&mut self, event: &NormalizedEvent) -> Option<Attribution> {
        let NormalizedData::NetConnect {
            dst_ip,
            dst_port,
            tls_candidate,
            ..
        } = &event.data
        else {
            return None;
        };
        let hit = *tls_candidate
            && dst_port == &Some(443)
            && dst_ip
                .as_deref()
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                .is_some_and(|ip| self.endpoint_ips.contains(&ip));

        if !hit {
            return self.resolve(event.process.pid).cloned();
        }

        if let Some(mut attribution) = self.resolve(event.process.pid).cloned() {
            if matches!(attribution.state, SessionState::RootCandidate) {
                attribution = self.merge_root_evidence(
                    event.process.pid,
                    vec![RootEvidence {
                        kind: RootEvidenceKind::LlmConnect,
                        value: dst_ip.clone().unwrap_or_default(),
                        ts_ns: event.ts_ns,
                    }],
                )?;
            }
            return Some(attribution);
        }

        let workspace = self.workspace_for_event(event)?;
        let lineage_id = veriskein_proto::EventId::from_seed(
            format!("{}:{}:connect", event.process.pid, event.ts_ns).as_bytes(),
        )
        .hex();
        let mut attribution = Attribution {
            session_id: SessionId::from_seed(format!("{lineage_id}:{}", workspace.id).as_bytes()),
            agent_id: AgentId::from_seed(
                format!("{lineage_id}:{}:{}", event.process.pid, event.ts_ns).as_bytes(),
            ),
            lineage_id: lineage_id.clone(),
            workspace,
            root_pid: event.process.pid,
            state: SessionState::RootCandidate,
            role: Role::Unknown,
            role_version: 1,
            role_tags: Vec::new(),
            attribution_strength: AttributionStrength::Weak,
            root_evidence: vec![RootEvidence {
                kind: RootEvidenceKind::LlmConnect,
                value: dst_ip.clone().unwrap_or_default(),
                ts_ns: event.ts_ns,
            }],
            revocable_until_ns: Some(
                event.ts_ns + defaults::AGENT_PROMOTION_WINDOW_S * 1_000_000_000,
            ),
        };
        self.confirm_if_ready(&mut attribution);
        self.bindings.insert(event.process.pid, attribution.clone());
        Some(attribution)
    }

    fn child_binding(
        &self,
        child_pid: u32,
        event: &NormalizedEvent,
        parent: &Attribution,
    ) -> Attribution {
        Attribution {
            session_id: parent.session_id,
            agent_id: AgentId::from_seed(
                format!("{}:{}:{}", parent.lineage_id, child_pid, event.ts_ns).as_bytes(),
            ),
            lineage_id: parent.lineage_id.clone(),
            workspace: parent.workspace.clone(),
            root_pid: parent.root_pid,
            state: parent.state.clone(),
            role: Role::Unknown,
            role_version: 1,
            role_tags: Vec::new(),
            attribution_strength: parent.attribution_strength,
            root_evidence: parent.root_evidence.clone(),
            revocable_until_ns: parent.revocable_until_ns,
        }
    }

    fn on_exit(&mut self, event: &NormalizedEvent) -> Option<Attribution> {
        let pid = event.process.pid;
        let mut attribution = self
            .bindings
            .remove(&pid)
            .or_else(|| self.draining.remove(&pid).map(|entry| entry.attribution))?;
        if pid == attribution.root_pid {
            attribution.state = SessionState::Draining;
        }
        self.draining.insert(
            pid,
            DrainingBinding {
                attribution: attribution.clone(),
                expires_at_ns: event.ts_ns + defaults::SESSION_DRAIN_SECS * 1_000_000_000,
            },
        );
        Some(attribution)
    }

    fn confirm_if_ready(&self, attribution: &mut Attribution) {
        if has_binary_seed(&attribution.root_evidence)
            || weak_signal_count(&attribution.root_evidence) >= 2
        {
            attribution.state = SessionState::ConfirmedRoot;
            attribution.attribution_strength = strength_for_evidence(&attribution.root_evidence);
            if !matches!(attribution.attribution_strength, AttributionStrength::Weak) {
                attribution.revocable_until_ns = None;
            }
        }
    }

    fn merge_root_evidence(
        &mut self,
        pid: u32,
        evidence: Vec<RootEvidence>,
    ) -> Option<Attribution> {
        let mut attribution = self.resolve(pid).cloned()?;
        for evidence in evidence {
            if !attribution
                .root_evidence
                .iter()
                .any(|entry| entry.kind == evidence.kind && entry.value == evidence.value)
            {
                attribution.root_evidence.push(evidence);
            }
        }
        attribution.attribution_strength = strength_for_evidence(&attribution.root_evidence);
        self.confirm_if_ready(&mut attribution);
        if let Some(binding) = self.bindings.get_mut(&pid) {
            *binding = attribution.clone();
        } else if let Some(binding) = self.draining.get_mut(&pid) {
            binding.attribution = attribution.clone();
        }
        Some(attribution)
    }

    fn collect_garbage(&mut self, ts_ns: u64) {
        self.draining.retain(|_, entry| entry.expires_at_ns > ts_ns);
        self.bindings.retain(|_, binding| {
            !matches!(binding.state, SessionState::RootCandidate)
                || binding.revocable_until_ns.is_none_or(|until| until > ts_ns)
        });
    }

    fn is_seed_binary(&self, filename: &str) -> bool {
        let basename = path_basename(filename);
        self.config.binary_seeds.iter().any(|seed| seed == basename)
    }

    fn argv_hits(&self, argv: &[String]) -> Vec<String> {
        self.config
            .argv_hints
            .iter()
            .filter(|hint| argv.iter().any(|arg| arg.contains(hint.as_str())))
            .cloned()
            .collect()
    }

    fn cached_env_hits(&self, pid: u32) -> Vec<String> {
        self.env_evidence
            .get(&pid)
            .map(|evidence| evidence.hits().to_vec())
            .unwrap_or_default()
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
        self.workspaces.first().cloned()
    }
}

fn has_binary_seed(evidence: &[RootEvidence]) -> bool {
    evidence
        .iter()
        .any(|entry| entry.kind == RootEvidenceKind::BinarySeed)
}

fn weak_signal_count(evidence: &[RootEvidence]) -> usize {
    let mut kinds = BTreeSet::new();
    for entry in evidence {
        match entry.kind {
            RootEvidenceKind::BinarySeed => {}
            RootEvidenceKind::EnvHint => {
                kinds.insert("env");
            }
            RootEvidenceKind::ArgvHint => {
                kinds.insert("argv");
            }
            RootEvidenceKind::LlmConnect => {
                kinds.insert("connect");
            }
        }
    }
    kinds.len()
}

fn strength_for_evidence(evidence: &[RootEvidence]) -> AttributionStrength {
    if has_binary_seed(evidence) {
        AttributionStrength::Strong
    } else if weak_signal_count(evidence) >= 2 {
        AttributionStrength::Medium
    } else {
        AttributionStrength::Weak
    }
}
