use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

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
    NormalizedData, NormalizedEvent, Normalizer, ProcessSnapshot, SensitiveConfig, load_workspaces,
};
use veriskein_proto::{OwnedContentFragEvent, OwnedEvent, defaults};
use veriskein_state_net::StateNet;

use crate::enrich::enrich_event_from_procfs;
use crate::env::env_evidence_for_pid;

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
        let (is_read, is_write) = file_access_modes(*flags);
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
        let ttl_ns = defaults::PROMPT_WINDOW_MS * 1_000_000;
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
            .filter_map(|chain| {
                detect_cross_agent_prompt_injection(
                    &chain,
                    normalized.process.pid,
                    normalized.process.tid,
                )
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
struct PendingPrompt {
    ts_ns: u64,
    prompt: ExtractedPrompt,
}

const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_ACCMODE: u32 = 3;
const O_CREAT: u32 = 64;
const O_TRUNC: u32 = 512;
const O_APPEND: u32 = 1024;

fn file_access_modes(flags: u32) -> (bool, bool) {
    let access_mode = flags & O_ACCMODE;
    let is_read = access_mode == 0 || access_mode == O_RDWR;
    let is_write = access_mode == O_WRONLY
        || access_mode == O_RDWR
        || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0;
    (is_read, is_write)
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
    let attribution = state_net.record_tls_fragment(evt.header.pid, evt.ssl_ctx, evt.header.ts_ns);
    let mut provenance = StreamProvenance {
        channel: evt.channel,
        direction: evt.direction,
        source: Some(match attribution.endpoint.as_ref() {
            Some(endpoint) => format!(
                "ssl_ctx={:x};dst={}:{}",
                evt.ssl_ctx, endpoint.ip, endpoint.port
            ),
            None => format!("ssl_ctx={:x}", evt.ssl_ctx),
        }),
    };
    let mut degradation_reasons = Vec::new();
    if evt.byte_len > evt.frag_len {
        provenance.source = Some(format!("ssl_ctx={:x};truncated", evt.ssl_ctx));
        degradation_reasons.push("content_truncated".to_string());
    }
    if let Some(reason) = attribution.degradation_reason {
        degradation_reasons.push(reason.to_string());
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
    let bytes = std::fs::read(path).ok()?;
    Some(
        bytes
            .into_iter()
            .take(veriskein_proto::defaults::TEXT_EXCERPT_MAX)
            .collect(),
    )
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
