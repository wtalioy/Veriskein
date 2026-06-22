use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use veriskein_alert::{AlertThrottler, emit_ndjson_line, validate};
use veriskein_collector::CollectorCore;
use veriskein_content::{
    ContentFragment, ContentRuntime, ExtractedPrompt, StreamOwner, StreamProvenance, TlsStreamKey,
};
use veriskein_correlator::{
    CapiState, ChainRiskKind, FileEventInput, InjectionKeywordConfig, PromptEvidence, PromptInput,
    PromptStore,
};
use veriskein_detectors::{DetectorEngine, Finding, detect_cross_agent_prompt_injection};
use veriskein_graph::{AgentConfig, EnvEvidence, GraphState, LlmEndpointResolver};
use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, Normalizer, ProcessSnapshot, SensitiveConfig,
    file_access_mode, load_workspaces,
};
use veriskein_proto::{OwnedContentFragEvent, OwnedEvent, defaults};
use veriskein_state_net::StateNet;

use crate::enrich::{enrich_event_from_procfs, env_evidence_for_pid};

pub struct RuntimePipeline {
    collector: CollectorCore,
    agent_config: AgentConfig,
    normalizer: Normalizer,
    state_net: StateNet,
    graph: GraphState,
    detectors: DetectorEngine,
    content: ContentRuntime,
    prompts: PromptStore,
    pending_prompts: BTreeMap<u32, Vec<PendingPrompt>>,
    capi: CapiState,
    alert_throttler: AlertThrottler,
    last_endpoint_refresh: Instant,
}

impl RuntimePipeline {
    pub fn new(config_root: &Path, workspace_inputs: &[PathBuf]) -> Result<Self> {
        let sensitive = SensitiveConfig::load(&config_root.join("config/sensitive.toml"))?;
        let agent_config = AgentConfig::load(&config_root.join("config/agents.toml"))?;
        let injection_keywords =
            InjectionKeywordConfig::load(&config_root.join("config/injection_keywords.toml"))?;
        let workspace_inputs = agent_config.workspace_inputs_with_default(workspace_inputs);
        let workspaces = load_workspaces(&workspace_inputs)?;
        let normalizer = Normalizer::new(sensitive, workspaces);
        let mut graph = GraphState::new(agent_config.clone(), normalizer.workspaces().to_vec())?;
        graph.refresh_endpoint_ips(LlmEndpointResolver::resolve(&agent_config.llm_endpoints));
        for snapshot in normalizer.process_snapshots() {
            let env_evidence = env_evidence_for_pid(snapshot.pid, &agent_config.env_hints);
            graph.seed_from_snapshot(&snapshot, env_evidence);
        }

        Ok(Self {
            collector: CollectorCore::new(),
            agent_config,
            normalizer,
            state_net: StateNet::new(),
            graph,
            detectors: DetectorEngine::new(),
            content: ContentRuntime::new(),
            prompts: PromptStore::default(),
            pending_prompts: BTreeMap::new(),
            capi: CapiState::new(injection_keywords),
            alert_throttler: AlertThrottler::default(),
            last_endpoint_refresh: Instant::now(),
        })
    }

    pub fn process_raw_event_bytes(
        &mut self,
        raw: &[u8],
        sink: &mut dyn Write,
        dry_run: bool,
    ) -> Result<usize> {
        let mut emitted = 0;
        let events = self
            .collector
            .process_bytes(raw)
            .context("process raw BPF event")?;
        for mut collected in events {
            enrich_event_from_procfs(&mut collected.event);
            match &collected.event {
                OwnedEvent::ContentFrag(evt) => self.process_content_fragment(evt),
                _ => {
                    emitted += self.process_owned_event(
                        collected.ingest_seq,
                        &collected.event,
                        sink,
                        dry_run,
                    )?;
                }
            }
        }
        Ok(emitted)
    }

    pub fn seed_startup_snapshot(&mut self, snapshot: &ProcessSnapshot, env_evidence: EnvEvidence) {
        self.graph.seed_from_snapshot(snapshot, env_evidence);
    }

    pub fn apply_env_evidence(&mut self, pid: u32, env_evidence: EnvEvidence, ts_ns: u64) {
        self.graph.apply_env_evidence(pid, env_evidence, ts_ns);
    }

    pub fn process_replay_event(
        &mut self,
        ingest_seq: u64,
        event: &OwnedEvent,
        sink: &mut dyn Write,
        dry_run: bool,
    ) -> Result<usize> {
        match event {
            OwnedEvent::ContentFrag(evt) => {
                self.process_content_fragment(evt);
                Ok(0)
            }
            _ => self.process_owned_event(ingest_seq, event, sink, dry_run),
        }
    }

    pub(crate) fn collector_counters(&self) -> &veriskein_collector::CollectorCounters {
        self.collector.counters()
    }

    pub(crate) fn maybe_refresh_endpoint_ips(&mut self) {
        let interval = Duration::from_secs(defaults::LLM_ENDPOINT_DNS_REFRESH_S);
        if self.last_endpoint_refresh.elapsed() < interval {
            return;
        }
        self.graph
            .refresh_endpoint_ips(LlmEndpointResolver::resolve(
                &self.agent_config.llm_endpoints,
            ));
        self.last_endpoint_refresh = Instant::now();
    }

    fn process_content_fragment(&mut self, evt: &OwnedContentFragEvent) {
        for prompt in handle_content_fragment(evt, &self.graph, &self.state_net, &mut self.content)
        {
            self.observe_extracted_prompt(evt.header.pid, evt.header.ts_ns, prompt);
        }
        self.evict_pending_prompts(evt.header.ts_ns);
    }

    fn process_owned_event(
        &mut self,
        ingest_seq: u64,
        event: &OwnedEvent,
        sink: &mut dyn Write,
        dry_run: bool,
    ) -> Result<usize> {
        let mut emitted = 0;
        for normalized in self.normalizer.apply(ingest_seq, event) {
            self.apply_state(&normalized);
            self.drain_pending_prompts_for_event(&normalized);
            let prompt_evidence =
                prompt_evidence_for_event(&mut self.prompts, &self.graph, &normalized);
            let mut findings = self.detectors.detect_with_prompt_evidence(
                &normalized,
                &self.graph,
                dry_run,
                &prompt_evidence,
            );
            self.observe_capi_file_event(&normalized);
            findings.extend(self.capi_findings_for_event(&normalized, &findings));
            for finding in findings {
                emitted += usize::from(emit_finding(&mut self.alert_throttler, sink, &finding)?);
            }
        }
        Ok(emitted)
    }

    fn apply_state(&mut self, normalized: &NormalizedEvent) {
        self.state_net.apply(normalized);
        if matches!(normalized.data, NormalizedData::ProcExec { .. }) {
            let env_evidence =
                env_evidence_for_pid(normalized.process.pid, &self.agent_config.env_hints);
            self.graph
                .apply_env_evidence(normalized.process.pid, env_evidence, normalized.ts_ns);
        }
        self.graph.apply(normalized);
    }

    fn observe_capi_file_event(&mut self, normalized: &NormalizedEvent) {
        let Some(binding) = self.graph.resolve(normalized.process.pid) else {
            return;
        };
        let NormalizedData::FileOpen {
            path,
            ret_fd,
            flags,
        } = &normalized.data
        else {
            return;
        };
        if *ret_fd < 0 {
            return;
        }
        let access = file_access_mode(*flags);
        let (is_read, is_write) = (access.is_read, access.is_write);
        if !is_write && !is_read {
            return;
        }
        let file_input = FileEventInput {
            session_id: binding.session_id,
            agent_id: Some(binding.agent_id),
            pid: normalized.process.pid,
            path: path.preferred_path_string(),
            ts_ns: normalized.ts_ns,
            is_workspace: path
                .workspace
                .as_ref()
                .is_some_and(|workspace| workspace.id == binding.workspace.id),
            is_write,
            is_read,
            inline_excerpt: None,
        };
        self.capi
            .observe_file_event(file_input, read_artifact_excerpt);
    }

    fn observe_extracted_prompt(&mut self, pid: u32, ts_ns: u64, mut prompt: ExtractedPrompt) {
        if prompt.owner.session_id.is_none()
            && let Some(binding) = self.graph.resolve(pid)
        {
            prompt.owner = StreamOwner::new(Some(binding.session_id), Some(binding.agent_id));
        }
        if !self.insert_prompt(ts_ns, prompt.clone()) {
            self.pending_prompts
                .entry(pid)
                .or_default()
                .push(PendingPrompt { ts_ns, prompt });
        }
    }

    fn drain_pending_prompts_for_event(&mut self, normalized: &NormalizedEvent) {
        self.drain_pending_prompts_for_pid(normalized.process.pid, normalized.ts_ns);
        if let NormalizedData::ProcFork { child_pid, .. } = normalized.data {
            self.drain_pending_prompts_for_pid(child_pid, normalized.ts_ns);
        }
        self.evict_pending_prompts(normalized.ts_ns);
    }

    fn drain_pending_prompts_for_pid(&mut self, pid: u32, now_ns: u64) {
        let Some(binding) = self.graph.resolve(pid).cloned() else {
            return;
        };
        let Some(mut pending) = self.pending_prompts.remove(&pid) else {
            return;
        };
        let owner = StreamOwner::new(Some(binding.session_id), Some(binding.agent_id));
        for mut pending_prompt in pending.drain(..) {
            pending_prompt.prompt.owner = owner.clone();
            if !self.insert_prompt(pending_prompt.ts_ns, pending_prompt.prompt.clone()) {
                self.pending_prompts
                    .entry(pid)
                    .or_default()
                    .push(pending_prompt);
            }
        }
        self.evict_pending_prompts(now_ns);
    }

    fn evict_pending_prompts(&mut self, now_ns: u64) {
        let ttl_ns = defaults::ms_to_ns(defaults::PROMPT_WINDOW_MS);
        self.pending_prompts.retain(|_, prompts| {
            prompts.retain(|prompt| prompt.ts_ns.saturating_add(ttl_ns) >= now_ns);
            !prompts.is_empty()
        });
    }

    fn insert_prompt(&mut self, ts_ns: u64, prompt: ExtractedPrompt) -> bool {
        let Some(input) = prompt_input_from_extraction(ts_ns, prompt) else {
            return false;
        };
        let prompt_id = self.prompts.insert(input);
        if let Some(snapshot) = self.prompts.snapshot(prompt_id) {
            self.capi.observe_prompt(snapshot);
        }
        true
    }

    fn capi_findings_for_event(
        &mut self,
        normalized: &NormalizedEvent,
        base_findings: &[Finding],
    ) -> Vec<Finding> {
        let Some(binding) = self.graph.resolve(normalized.process.pid) else {
            return Vec::new();
        };
        let prompts = &self.prompts;
        base_findings
            .iter()
            .filter_map(|finding| ChainRiskKind::from_alert_type(finding.finding_type.as_str()))
            .flat_map(|risk_kind| {
                self.capi.chains_for_risky_event(
                    binding.session_id,
                    normalized.event_id.clone(),
                    normalized.ts_ns,
                    risk_kind,
                    |prompt_id| prompts.snapshot(prompt_id),
                )
            })
            .filter_map(|chain| detect_cross_agent_prompt_injection(&chain, normalized, binding))
            .collect()
    }
}

#[derive(Debug, Clone)]
struct PendingPrompt {
    ts_ns: u64,
    prompt: ExtractedPrompt,
}

fn handle_content_fragment(
    evt: &OwnedContentFragEvent,
    graph: &GraphState,
    state_net: &StateNet,
    content: &mut ContentRuntime,
) -> Vec<ExtractedPrompt> {
    let binding = graph.resolve(evt.header.pid);
    let owner = StreamOwner::new(
        binding.map(|binding| binding.session_id),
        binding.map(|binding| binding.agent_id),
    );
    let attribution =
        state_net.record_tls_fragment(evt.header.pid, evt.ssl_ctx, evt.direction, evt.header.ts_ns);
    let provenance = StreamProvenance {
        channel: evt.channel,
        direction: evt.direction,
        source: Some(match attribution.endpoint.as_ref() {
            Some(endpoint) => format!(
                "ssl_ctx={:x};dst={}:{}",
                evt.ssl_ctx, endpoint.ip, endpoint.port
            ),
            None => match attribution.degradation_reason {
                Some(reason) => format!("ssl_ctx={:x};tls_attribution={reason}", evt.ssl_ctx),
                None => format!("ssl_ctx={:x}", evt.ssl_ctx),
            },
        }),
    };
    let mut degradation_reasons = Vec::new();
    if evt.byte_len > evt.frag_len {
        degradation_reasons.push("content_truncated".to_string());
    }
    let fragment = ContentFragment::with_degradation(
        TlsStreamKey::new(evt.header.pid, evt.ssl_ctx, evt.direction).stream_id(),
        evt.stream_offset,
        evt.data.clone(),
        owner,
        provenance,
        degradation_reasons,
    );
    content.append(fragment)
}

fn prompt_input_from_extraction(ts_ns: u64, prompt: ExtractedPrompt) -> Option<PromptInput> {
    Some(PromptInput {
        session_id: prompt.owner.session_id?,
        agent_id: prompt.owner.agent_id,
        stream_id: prompt.stream_id,
        capture_mode: prompt.provenance.channel,
        ts_start: ts_ns,
        ts_end: ts_ns,
        excerpt: prompt.text.into_bytes(),
        visibility_state: prompt.visibility,
        degraded: !prompt.degradation_reasons.is_empty(),
    })
}

fn prompt_evidence_for_event(
    prompts: &mut PromptStore,
    graph: &GraphState,
    normalized: &NormalizedEvent,
) -> Vec<PromptEvidence> {
    let Some(binding) = graph.resolve(normalized.process.pid) else {
        return Vec::new();
    };
    prompts.evidence_for_event(
        binding.session_id,
        normalized.event_id.clone(),
        normalized.ts_ns,
        normalized.kind.as_str(),
        normalized.ingest_seq,
    )
}

fn read_artifact_excerpt(path: &str) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(veriskein_proto::defaults::TEXT_EXCERPT_MAX);
    std::io::Read::by_ref(&mut file)
        .take(veriskein_proto::defaults::TEXT_EXCERPT_MAX as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

fn emit_finding(
    throttler: &mut AlertThrottler,
    sink: &mut dyn Write,
    finding: &Finding,
) -> Result<bool> {
    let Some(alert) = throttler.project(finding) else {
        return Ok(false);
    };
    let value = alert.as_value()?;
    validate(&value).context("validate alert against schema")?;
    emit_ndjson_line(sink, &value)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use veriskein_content::ContentDirection;
    use veriskein_graph::{AgentConfig, EnvEvidence, GraphState};
    use veriskein_normalizer::{ProcessSnapshot, WorkspaceRef};
    use veriskein_proto::{
        ContentChannel, EventHeader, OwnedContentFragEvent, VisibilityState, defaults,
    };
    use veriskein_state_net::StateNet;

    use super::handle_content_fragment;

    fn graph() -> GraphState {
        let mut graph = GraphState::new(
            AgentConfig {
                default_workspace: "/tmp/ws".to_string(),
                binary_seeds: vec!["claude".to_string()],
                env_hints: Vec::new(),
                argv_hints: Vec::new(),
                llm_endpoints: Vec::new(),
                shell_allowlist: Vec::new(),
                sensitive_allowlist: Vec::new(),
                delete_allowlist: Vec::new(),
            },
            vec![WorkspaceRef {
                id: "ws-default".to_string(),
                root: "/tmp/ws".into(),
            }],
        )
        .expect("graph");
        graph.seed_from_snapshot(
            &ProcessSnapshot {
                pid: 42,
                tid: 42,
                ppid: 1,
                exe: "/usr/bin/claude".to_string(),
                comm: "claude".to_string(),
                argv: vec!["claude".to_string()],
                cwd: "/tmp/ws".into(),
            },
            EnvEvidence::empty(),
        );
        graph
    }

    fn content_event(data: &[u8]) -> OwnedContentFragEvent {
        OwnedContentFragEvent {
            header: EventHeader {
                ts_ns: 1,
                abi_version: defaults::EVT_ABI_VERSION,
                kind: veriskein_proto::EventKind::ContentFrag as u16,
                total_len: 0,
                pid: 42,
                tid: 42,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                cgroup_id: 0,
                cpu: 0,
                seq: 1,
                mount_ns: 42,
                ret: 0,
                _reserved: 0,
                comm: [0; defaults::TASK_COMM_LEN],
            },
            ssl_ctx: 0xabc,
            stream_offset: 0,
            byte_len: data.len() as u32,
            frag_len: data.len() as u32,
            channel: ContentChannel::Tls,
            direction: ContentDirection::Write,
            flags: 0,
            data: data.to_vec(),
        }
    }

    #[test]
    fn missing_tls_association_attribution_does_not_degrade_prompt_text() {
        let mut content = veriskein_content::ContentRuntime::new();
        let prompts = handle_content_fragment(
            &content_event(br#"{"prompt":"Please inspect /etc/shadow"}"#),
            &graph(),
            &StateNet::new(),
            &mut content,
        );

        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].visibility, VisibilityState::Full);
        assert!(prompts[0].degradation_reasons.is_empty());
    }
}
