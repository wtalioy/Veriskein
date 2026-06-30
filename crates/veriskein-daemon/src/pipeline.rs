use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use veriskein_alert::{AlertRecord, AlertThrottler, RuntimeHealth, emit_ndjson_line, validate};
use veriskein_collector::CollectorCore;
use veriskein_content::{
    ContentFragment, ContentRuntime, ExtractedPrompt, McpRegistry, McpToolSpoofing, StreamOwner,
    StreamProvenance, TlsStreamKey,
};
use veriskein_correlator::{
    CapiState, ChainRiskKind, FileEventInput, InjectionKeywordConfig, PromptEvidence, PromptInput,
    PromptStore,
};
use veriskein_detectors::{
    DetectorEngine, Finding, McpAnomalyContext, detect_cross_agent_prompt_injection,
    mcp_tool_spoofing_findings_from_content,
};
use veriskein_graph::{AgentConfig, Attribution, EnvEvidence, GraphState, LlmEndpointResolver};
use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, Normalizer, ProcessSnapshot, SensitiveConfig,
    file_access_mode, load_workspaces,
};
use veriskein_proto::{
    ContentChannel, EventId, OwnedContentFragEvent, OwnedEvent, Role, defaults, parse_c_string,
};
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
    mcp_registry: McpRegistry,
    pending_mcp_anomalies: BTreeMap<u32, Vec<McpToolSpoofing>>,
    prompts: PromptStore,
    pending_prompts: BTreeMap<u32, Vec<PendingPrompt>>,
    pending_prompt_total: usize,
    evicted_pending_prompts_total: u64,
    capi: CapiState,
    alert_throttler: AlertThrottler,
    runtime_health: RuntimeHealth,
    last_endpoint_refresh: Instant,
    content_capture: ContentCaptureSettings,
    active_content_capture: BTreeMap<(u32, i32), ActiveContentCapture>,
    content_capture_updates: Vec<ContentCaptureUpdate>,
    ipc_events: Vec<IpcEventProjection>,
    ipc_graph: Vec<IpcGraphProjection>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ContentCaptureSettings {
    pub stdio_enabled: bool,
    pub mcp_stdio_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentCaptureUpdate {
    Upsert {
        pid: u32,
        fd: i32,
        channel: ContentChannel,
        expires_at_ns: u64,
    },
    Delete {
        pid: u32,
        fd: i32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveContentCapture {
    channel: ContentChannel,
    expires_at_ns: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IpcEventProjection {
    pub event_id: String,
    pub ts_ns: u64,
    pub event_kind: String,
    pub pid: u32,
    pub session_id: Option<String>,
    pub event: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IpcGraphProjection {
    pub ts_ns: u64,
    pub graph: Value,
}

impl RuntimePipeline {
    pub fn new(config_root: &Path, workspace_inputs: &[PathBuf]) -> Result<Self> {
        Self::new_with_content_capture(
            config_root,
            workspace_inputs,
            ContentCaptureSettings::default(),
        )
    }

    pub(crate) fn new_with_content_capture(
        config_root: &Path,
        workspace_inputs: &[PathBuf],
        content_capture: ContentCaptureSettings,
    ) -> Result<Self> {
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
            mcp_registry: McpRegistry::new(),
            pending_mcp_anomalies: BTreeMap::new(),
            prompts: PromptStore::default(),
            pending_prompts: BTreeMap::new(),
            pending_prompt_total: 0,
            evicted_pending_prompts_total: 0,
            capi: CapiState::new(injection_keywords),
            alert_throttler: AlertThrottler::default(),
            runtime_health: RuntimeHealth::full(),
            last_endpoint_refresh: Instant::now(),
            content_capture,
            active_content_capture: BTreeMap::new(),
            content_capture_updates: Vec::new(),
            ipc_events: Vec::new(),
            ipc_graph: Vec::new(),
        })
    }

    pub fn set_runtime_health(&mut self, runtime_health: RuntimeHealth) {
        self.runtime_health = runtime_health;
    }

    pub fn process_raw_event_bytes(
        &mut self,
        raw: &[u8],
        sink: &mut dyn Write,
        dry_run: bool,
    ) -> Result<Vec<AlertRecord>> {
        let mut emitted = Vec::new();
        let events = self
            .collector
            .process_bytes(raw)
            .context("process raw BPF event")?;
        for mut collected in events {
            enrich_event_from_procfs(&mut collected.event);
            match &collected.event {
                OwnedEvent::ContentFrag(evt) => {
                    for finding in self.process_content_fragment(collected.ingest_seq, evt) {
                        if let Some(alert) = emit_finding(
                            &mut self.alert_throttler,
                            sink,
                            &finding,
                            &self.runtime_health,
                        )? {
                            emitted.push(alert);
                        }
                    }
                }
                _ => {
                    emitted.extend(self.process_owned_event(
                        collected.ingest_seq,
                        &collected.event,
                        sink,
                        dry_run,
                    )?);
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
    ) -> Result<Vec<AlertRecord>> {
        match event {
            OwnedEvent::ContentFrag(evt) => {
                let mut emitted = Vec::new();
                for finding in self.process_content_fragment(ingest_seq, evt) {
                    if let Some(alert) = emit_finding(
                        &mut self.alert_throttler,
                        sink,
                        &finding,
                        &self.runtime_health,
                    )? {
                        emitted.push(alert);
                    }
                }
                Ok(emitted)
            }
            _ => self.process_owned_event(ingest_seq, event, sink, dry_run),
        }
    }

    pub(crate) fn collector_counters(&self) -> &veriskein_collector::CollectorCounters {
        self.collector.counters()
    }

    pub(crate) fn drain_content_capture_updates(&mut self) -> Vec<ContentCaptureUpdate> {
        std::mem::take(&mut self.content_capture_updates)
    }

    pub(crate) fn drain_ipc_events(&mut self) -> Vec<IpcEventProjection> {
        std::mem::take(&mut self.ipc_events)
    }

    pub(crate) fn drain_ipc_graph(&mut self) -> Vec<IpcGraphProjection> {
        std::mem::take(&mut self.ipc_graph)
    }

    pub(crate) fn retained_detail_evictions_total(&self) -> u64 {
        self.normalizer
            .evicted_process_detail_total()
            .saturating_add(self.content.evicted_streams_total())
            .saturating_add(self.prompts.evicted_prompts_total())
            .saturating_add(self.capi.evicted_detail_total())
            .saturating_add(self.evicted_pending_prompts_total)
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

    fn process_content_fragment(
        &mut self,
        ingest_seq: u64,
        evt: &OwnedContentFragEvent,
    ) -> Vec<Finding> {
        let mcp_anomalies = self.observe_mcp_registry(evt);
        for prompt in handle_content_fragment(evt, &self.graph, &self.state_net, &mut self.content)
        {
            self.observe_extracted_prompt(evt.header.pid, evt.header.ts_ns, prompt);
        }
        self.evict_pending_prompts(evt.header.ts_ns);
        if mcp_anomalies.is_empty() {
            return Vec::new();
        }
        let pid = evt.header.pid;
        let tid = evt.header.tid;
        let ts_ns = evt.header.ts_ns;
        let ssl_ctx = evt.ssl_ctx;
        let comm = parse_c_string(&evt.header.comm);
        let Some(binding) = self.graph.resolve(pid) else {
            self.pending_mcp_anomalies
                .entry(pid)
                .or_default()
                .extend(mcp_anomalies);
            return Vec::new();
        };
        mcp_tool_spoofing_findings_from_content(
            McpAnomalyContext {
                ts_ns,
                pid,
                tid,
                event_id: EventId::from_seed(format!("mcp:{pid}:{ssl_ctx}:{ts_ns}").as_bytes())
                    .hex(),
                ingest_seq,
                argv: Vec::new(),
                process_comm: comm,
                process_binary: String::new(),
            },
            binding,
            &mcp_anomalies,
        )
    }

    fn process_owned_event(
        &mut self,
        ingest_seq: u64,
        event: &OwnedEvent,
        sink: &mut dyn Write,
        dry_run: bool,
    ) -> Result<Vec<AlertRecord>> {
        let mut emitted = Vec::new();
        for normalized in self.normalizer.apply(ingest_seq, event) {
            let graph_projection = self.apply_state(&normalized);
            self.ipc_events.push(ipc_event_projection(
                &normalized,
                self.graph
                    .resolve(normalized.process.pid)
                    .map(|binding| binding.session_id.hex()),
            ));
            if let Some(graph_projection) = graph_projection {
                self.ipc_graph.push(graph_projection);
            }
            self.drain_pending_prompts_for_event(&normalized);
            let prompt_evidence =
                prompt_evidence_for_event(&mut self.prompts, &self.graph, &normalized);
            let mcp_anomalies = self
                .pending_mcp_anomalies
                .remove(&normalized.process.pid)
                .unwrap_or_default();
            let mut findings = self.detectors.detect_with_prompt_and_mcp_evidence(
                &normalized,
                &self.graph,
                dry_run,
                &prompt_evidence,
                &mcp_anomalies,
            );
            self.observe_capi_file_event(&normalized);
            findings.extend(self.capi_findings_for_event(&normalized, &findings));
            for finding in findings {
                if let Some(alert) = emit_finding(
                    &mut self.alert_throttler,
                    sink,
                    &finding,
                    &self.runtime_health,
                )? {
                    emitted.push(alert);
                }
            }
        }
        Ok(emitted)
    }

    fn apply_state(&mut self, normalized: &NormalizedEvent) -> Option<IpcGraphProjection> {
        self.state_net.apply(normalized);
        if matches!(normalized.data, NormalizedData::ProcExec { .. }) {
            let env_evidence =
                env_evidence_for_pid(normalized.process.pid, &self.agent_config.env_hints);
            self.graph
                .apply_env_evidence(normalized.process.pid, env_evidence, normalized.ts_ns);
        }
        let graph_projection = self
            .graph
            .apply(normalized)
            .as_ref()
            .map(|binding| ipc_graph_projection(normalized, binding));
        self.observe_content_capture_policy(normalized);
        graph_projection
    }

    fn observe_content_capture_policy(&mut self, normalized: &NormalizedEvent) {
        match &normalized.data {
            NormalizedData::ProcFork { child_pid, .. } => {
                self.inherit_content_capture(normalized.process.pid, *child_pid)
            }
            NormalizedData::ProcExec { .. } => self.maybe_enable_standard_fds(normalized),
            NormalizedData::ProcExit { .. } => {
                self.delete_all_content_capture(normalized.process.pid)
            }
            NormalizedData::FdDup {
                oldfd,
                newfd,
                dup_ret: 0,
            } if *oldfd < 0 => self.delete_content_capture(normalized.process.pid, *newfd),
            NormalizedData::FdDup {
                oldfd,
                newfd,
                dup_ret,
            } if *dup_ret >= 0 => {
                self.dup_content_capture(normalized.process.pid, *oldfd, *newfd, *dup_ret)
            }
            NormalizedData::FileOpen { ret_fd, .. } if *ret_fd >= 0 => {
                self.delete_content_capture(normalized.process.pid, *ret_fd)
            }
            _ => {}
        }
    }

    fn inherit_content_capture(&mut self, parent_pid: u32, child_pid: u32) {
        let inherited = self
            .active_content_capture
            .iter()
            .filter_map(|(&(pid, fd), policy)| (pid == parent_pid).then_some((fd, *policy)))
            .collect::<Vec<_>>();
        for (fd, policy) in inherited {
            self.upsert_content_capture(child_pid, fd, policy.channel, policy.expires_at_ns);
        }
    }

    fn dup_content_capture(&mut self, pid: u32, oldfd: i32, newfd: i32, dup_ret: i32) {
        let destination = if newfd >= 0 { newfd } else { dup_ret };
        self.delete_content_capture(pid, destination);
        if let Some(policy) = self.active_content_capture.get(&(pid, oldfd)).copied() {
            self.upsert_content_capture(pid, destination, policy.channel, policy.expires_at_ns);
        }
    }

    fn upsert_content_capture(
        &mut self,
        pid: u32,
        fd: i32,
        channel: ContentChannel,
        expires_at_ns: u64,
    ) {
        self.active_content_capture.insert(
            (pid, fd),
            ActiveContentCapture {
                channel,
                expires_at_ns,
            },
        );
        self.content_capture_updates
            .push(ContentCaptureUpdate::Upsert {
                pid,
                fd,
                channel,
                expires_at_ns,
            });
    }

    fn delete_content_capture(&mut self, pid: u32, fd: i32) {
        self.active_content_capture.remove(&(pid, fd));
        self.content_capture_updates
            .push(ContentCaptureUpdate::Delete { pid, fd });
    }

    fn delete_all_content_capture(&mut self, pid: u32) {
        let fds = self
            .active_content_capture
            .keys()
            .filter_map(|(entry_pid, fd)| (*entry_pid == pid).then_some(*fd))
            .collect::<Vec<_>>();
        for fd in fds {
            self.delete_content_capture(pid, fd);
        }
    }

    fn maybe_enable_standard_fds(&mut self, normalized: &NormalizedEvent) {
        let Some(binding) = self.graph.resolve(normalized.process.pid) else {
            return;
        };
        let channel = match binding.role {
            Role::McpServer if self.content_capture.mcp_stdio_enabled => ContentChannel::Mcp,
            Role::RootAgent | Role::SubAgent if self.content_capture.stdio_enabled => {
                ContentChannel::Stdio
            }
            _ => return,
        };
        let expires_at_ns = normalized
            .ts_ns
            .saturating_add(defaults::secs_to_ns(defaults::SESSION_DRAIN_SECS));
        for fd in 0..=2 {
            self.upsert_content_capture(normalized.process.pid, fd, channel, expires_at_ns);
        }
    }

    fn observe_mcp_registry(&mut self, evt: &OwnedContentFragEvent) -> Vec<McpToolSpoofing> {
        if evt.channel != ContentChannel::Mcp {
            return Vec::new();
        }
        let pid = evt.header.pid;
        let server_id = self
            .graph
            .resolve(pid)
            .map(|binding| format!("{}:{}", binding.session_id.hex(), binding.agent_id.hex()))
            .unwrap_or_else(|| format!("pid:{pid}"));
        self.mcp_registry
            .observe_jsonrpc_fragment(server_id, evt.ssl_ctx, &evt.data)
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
            self.queue_pending_prompt(pid, PendingPrompt { ts_ns, prompt });
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
        self.pending_prompt_total = self.pending_prompt_total.saturating_sub(pending.len());
        let owner = StreamOwner::new(Some(binding.session_id), Some(binding.agent_id));
        for mut pending_prompt in pending.drain(..) {
            pending_prompt.prompt.owner = owner.clone();
            if !self.insert_prompt(pending_prompt.ts_ns, pending_prompt.prompt.clone()) {
                self.queue_pending_prompt(pid, pending_prompt);
            }
        }
        self.evict_pending_prompts(now_ns);
    }

    fn evict_pending_prompts(&mut self, now_ns: u64) {
        let ttl_ns = defaults::ms_to_ns(defaults::PROMPT_WINDOW_MS);
        self.pending_prompts.retain(|_, prompts| {
            let before = prompts.len();
            prompts.retain(|prompt| prompt.ts_ns.saturating_add(ttl_ns) >= now_ns);
            self.pending_prompt_total = self
                .pending_prompt_total
                .saturating_sub(before.saturating_sub(prompts.len()));
            !prompts.is_empty()
        });
    }

    fn queue_pending_prompt(&mut self, pid: u32, prompt: PendingPrompt) {
        self.pending_prompts.entry(pid).or_default().push(prompt);
        self.pending_prompt_total = self.pending_prompt_total.saturating_add(1);
        self.enforce_pending_prompt_bound();
    }

    fn enforce_pending_prompt_bound(&mut self) {
        self.enforce_pending_prompt_bound_to(defaults::MAX_PROMPTS);
    }

    fn enforce_pending_prompt_bound_to(&mut self, max_pending: usize) {
        while self.pending_prompt_total > max_pending {
            let Some(pid) = self.oldest_pending_prompt_pid() else {
                self.pending_prompt_total = 0;
                break;
            };
            let Some(prompts) = self.pending_prompts.get_mut(&pid) else {
                continue;
            };
            if prompts.is_empty() {
                self.pending_prompts.remove(&pid);
                continue;
            }
            prompts.remove(0);
            self.pending_prompt_total = self.pending_prompt_total.saturating_sub(1);
            self.evicted_pending_prompts_total =
                self.evicted_pending_prompts_total.saturating_add(1);
            if self.pending_prompts.get(&pid).is_some_and(Vec::is_empty) {
                self.pending_prompts.remove(&pid);
            }
        }
    }

    fn oldest_pending_prompt_pid(&self) -> Option<u32> {
        self.pending_prompts
            .iter()
            .filter_map(|(pid, prompts)| prompts.first().map(|prompt| (*pid, prompt.ts_ns)))
            .min_by_key(|(_, ts_ns)| *ts_ns)
            .map(|(pid, _)| pid)
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
    let (provenance, stream_id) = match evt.channel {
        ContentChannel::Tls => {
            let attribution = state_net.record_tls_fragment(
                evt.header.pid,
                evt.ssl_ctx,
                evt.direction,
                evt.header.ts_ns,
            );
            let source = match attribution.endpoint.as_ref() {
                Some(endpoint) => format!(
                    "ssl_ctx={:x};dst={}:{}",
                    evt.ssl_ctx, endpoint.ip, endpoint.port
                ),
                None => match attribution.degradation_reason {
                    Some(reason) => format!("ssl_ctx={:x};tls_attribution={reason}", evt.ssl_ctx),
                    None => format!("ssl_ctx={:x}", evt.ssl_ctx),
                },
            };
            (
                StreamProvenance {
                    channel: evt.channel,
                    direction: evt.direction,
                    source: Some(source),
                },
                TlsStreamKey::new(evt.header.pid, evt.ssl_ctx, evt.direction).stream_id(),
            )
        }
        ContentChannel::Stdio | ContentChannel::Pipe | ContentChannel::Mcp => (
            StreamProvenance {
                channel: evt.channel,
                direction: evt.direction,
                source: Some(format!(
                    "fd_stream={:x};channel={}",
                    evt.ssl_ctx,
                    evt.channel.as_str()
                )),
            },
            TlsStreamKey::new(evt.header.pid, evt.ssl_ctx, evt.direction).stream_id(),
        ),
    };
    let mut degradation_reasons = Vec::new();
    if evt.byte_len > evt.frag_len {
        degradation_reasons.push("content_truncated".to_string());
    }
    let fragment = ContentFragment::with_degradation(
        stream_id,
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

fn ipc_event_projection(
    normalized: &NormalizedEvent,
    session_id: Option<String>,
) -> IpcEventProjection {
    IpcEventProjection {
        event_id: normalized.event_id.clone(),
        ts_ns: normalized.ts_ns,
        event_kind: normalized.kind.as_str().to_string(),
        pid: normalized.process.pid,
        session_id,
        event: serde_json::to_value(normalized).unwrap_or_else(|err| {
            json!({
                "event_id": normalized.event_id,
                "serialization_error": err.to_string(),
            })
        }),
    }
}

fn ipc_graph_projection(normalized: &NormalizedEvent, binding: &Attribution) -> IpcGraphProjection {
    IpcGraphProjection {
        ts_ns: normalized.ts_ns,
        graph: json!({
            "op": "bind",
            "pid": normalized.process.pid,
            "session_id": binding.session_id.hex(),
            "agent_id": binding.agent_id.hex(),
            "role": binding.role.as_str(),
            "role_version": binding.role_version,
            "attribution_strength": format!("{:?}", binding.attribution_strength).to_ascii_lowercase(),
            "workspace_id": binding.workspace.id,
            "root_pid": binding.root_pid,
        }),
    }
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
    runtime_health: &RuntimeHealth,
) -> Result<Option<AlertRecord>> {
    let Some(alert) = throttler.project_with_health(finding, runtime_health) else {
        return Ok(None);
    };
    let value = alert.as_value()?;
    validate(&value).context("validate alert against schema")?;
    emit_ndjson_line(sink, &value)?;
    Ok(Some(alert))
}

#[cfg(test)]
mod tests {
    use veriskein_content::ContentDirection;
    use veriskein_content::{ExtractedPrompt, StreamOwner, StreamProvenance};
    use veriskein_graph::{AgentConfig, EnvEvidence, GraphState};
    use veriskein_normalizer::{ProcessSnapshot, WorkspaceRef};
    use veriskein_proto::{
        ContentChannel, EventHeader, OwnedContentFragEvent, OwnedEvent, OwnedProcExecEvent,
        VisibilityState, defaults,
    };
    use veriskein_state_net::StateNet;

    use super::{ContentCaptureUpdate, PendingPrompt, RuntimePipeline, handle_content_fragment};

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
        graph.seed_from_snapshot(
            &ProcessSnapshot {
                pid: 43,
                tid: 43,
                ppid: 1,
                exe: "/usr/bin/claude".to_string(),
                comm: "claude".to_string(),
                argv: vec!["claude".to_string(), "mcp-server".to_string()],
                cwd: "/tmp/ws".into(),
            },
            EnvEvidence::empty(),
        );
        graph
    }

    fn content_event(data: &[u8]) -> OwnedContentFragEvent {
        content_event_for_pid(42, ContentChannel::Tls, data)
    }

    fn content_event_for_pid(
        pid: u32,
        channel: ContentChannel,
        data: &[u8],
    ) -> OwnedContentFragEvent {
        OwnedContentFragEvent {
            header: EventHeader {
                ts_ns: 1,
                abi_version: defaults::EVT_ABI_VERSION,
                kind: veriskein_proto::EventKind::ContentFrag as u16,
                total_len: 0,
                pid,
                tid: pid,
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
            channel,
            direction: ContentDirection::Write,
            flags: 0,
            data: data.to_vec(),
        }
    }

    fn proc_exec_event(pid: u32) -> OwnedEvent {
        OwnedEvent::ProcExec(OwnedProcExecEvent {
            header: EventHeader {
                ts_ns: 2,
                abi_version: defaults::EVT_ABI_VERSION,
                kind: veriskein_proto::EventKind::ProcExec as u16,
                total_len: 0,
                pid,
                tid: pid,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                cgroup_id: 0,
                cpu: 0,
                seq: 2,
                mount_ns: 42,
                ret: 0,
                _reserved: 0,
                comm: [0; defaults::TASK_COMM_LEN],
            },
            filename: "/usr/bin/claude".to_string(),
            argv: vec!["claude".to_string(), "mcp-server".to_string()],
        })
    }

    fn pending_prompt(ts_ns: u64, text: &str) -> PendingPrompt {
        PendingPrompt {
            ts_ns,
            prompt: ExtractedPrompt {
                stream_id: ts_ns,
                owner: StreamOwner::new(None, None),
                provenance: StreamProvenance {
                    channel: ContentChannel::Tls,
                    direction: ContentDirection::Write,
                    source: None,
                },
                text: text.to_string(),
                visibility: VisibilityState::Full,
                degradation_reasons: Vec::new(),
            },
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

    #[test]
    fn pending_prompts_are_bounded_oldest_first() {
        let mut pipeline = RuntimePipeline::new(
            &super::super::driver::resolve_config_root().expect("repo root"),
            &["/tmp/ws".into()],
        )
        .expect("pipeline");
        pipeline.queue_pending_prompt(20, pending_prompt(20, "newer"));
        pipeline.queue_pending_prompt(10, pending_prompt(10, "older"));

        pipeline.enforce_pending_prompt_bound_to(1);

        assert_eq!(pipeline.pending_prompt_total, 1);
        assert!(!pipeline.pending_prompts.contains_key(&10));
        assert!(pipeline.pending_prompts.contains_key(&20));
        assert_eq!(pipeline.evicted_pending_prompts_total, 1);
        assert_eq!(pipeline.retained_detail_evictions_total(), 1);
    }

    #[test]
    fn content_capture_policy_tracks_fork_dup_and_exit() {
        let mut pipeline = RuntimePipeline::new_with_content_capture(
            &super::super::driver::resolve_config_root().expect("repo root"),
            &["/tmp/ws".into()],
            super::ContentCaptureSettings {
                stdio_enabled: false,
                mcp_stdio_enabled: true,
            },
        )
        .expect("pipeline");
        let mut sink = Vec::new();
        pipeline
            .process_raw_event_bytes(
                &veriskein_proto::EventFixture::for_pid(1, 700, 1, "claude")
                    .exec("/usr/bin/claude", &["claude", "mcp-server"]),
                &mut sink,
                false,
            )
            .expect("exec");
        let updates = pipeline.drain_content_capture_updates();
        assert_eq!(updates.len(), 3);
        assert!(updates.iter().all(|update| matches!(
            update,
            ContentCaptureUpdate::Upsert {
                pid: 700,
                channel: ContentChannel::Mcp,
                ..
            }
        )));

        pipeline
            .process_raw_event_bytes(
                &veriskein_proto::EventFixture::for_pid(2, 700, 1, "claude").fork(701, 701),
                &mut sink,
                false,
            )
            .expect("fork");
        assert!(
            pipeline
                .drain_content_capture_updates()
                .iter()
                .all(|update| {
                    matches!(
                        update,
                        ContentCaptureUpdate::Upsert {
                            pid: 701,
                            channel: ContentChannel::Mcp,
                            ..
                        }
                    )
                })
        );

        pipeline
            .process_raw_event_bytes(
                &veriskein_proto::EventFixture::for_pid(3, 701, 700, "claude").dup(1, 7, 7),
                &mut sink,
                false,
            )
            .expect("dup");
        let updates = pipeline.drain_content_capture_updates();
        assert!(matches!(
            updates.as_slice(),
            [
                ContentCaptureUpdate::Delete { pid: 701, fd: 7 },
                ContentCaptureUpdate::Upsert {
                    pid: 701,
                    fd: 7,
                    channel: ContentChannel::Mcp,
                    ..
                }
            ]
        ));

        pipeline
            .process_raw_event_bytes(
                &veriskein_proto::EventFixture::for_pid(4, 701, 700, "claude").open(
                    -100,
                    7,
                    "/tmp/reused-fd",
                ),
                &mut sink,
                false,
            )
            .expect("open");
        assert!(matches!(
            pipeline.drain_content_capture_updates().as_slice(),
            [ContentCaptureUpdate::Delete { pid: 701, fd: 7 }]
        ));

        pipeline
            .process_raw_event_bytes(
                &veriskein_proto::EventFixture::for_pid(5, 701, 700, "claude").exit(0),
                &mut sink,
                false,
            )
            .expect("exit");
        assert!(
            pipeline
                .drain_content_capture_updates()
                .iter()
                .all(|update| { matches!(update, ContentCaptureUpdate::Delete { pid: 701, .. }) })
        );
    }

    #[test]
    fn mcp_registry_anomaly_emits_from_content_when_attributed() {
        let mut pipeline = RuntimePipeline::new(
            &super::super::driver::resolve_config_root().expect("repo root"),
            &["/tmp/ws".into()],
        )
        .expect("pipeline");
        pipeline.graph = graph();
        assert!(
            pipeline
                .process_content_fragment(
                    1,
                    &content_event_for_pid(
                        42,
                        ContentChannel::Mcp,
                        br#"{"jsonrpc":"2.0","result":{"tools":[{"name":"read_file"}]}}"#,
                    ),
                )
                .is_empty()
        );
        let findings = pipeline.process_content_fragment(
            2,
            &content_event_for_pid(
                43,
                ContentChannel::Mcp,
                br#"{"jsonrpc":"2.0","result":{"tools":[{"name":"read_file"}]}}"#,
            ),
        );

        assert!(
            findings.iter().any(
                |finding| finding.finding_type == veriskein_proto::FindingType::McpToolSpoofing
            )
        );
        assert!(pipeline.pending_mcp_anomalies.get(&43).is_none());
    }

    #[test]
    fn unattributed_mcp_registry_anomaly_emits_on_next_normalized_event() {
        let mut pipeline = RuntimePipeline::new(
            &super::super::driver::resolve_config_root().expect("repo root"),
            &["/tmp/ws".into()],
        )
        .expect("pipeline");
        pipeline.graph = graph();
        pipeline.process_content_fragment(
            1,
            &content_event_for_pid(
                42,
                ContentChannel::Mcp,
                br#"{"jsonrpc":"2.0","result":{"tools":[{"name":"read_file"}]}}"#,
            ),
        );
        pipeline.process_content_fragment(
            2,
            &content_event_for_pid(
                99,
                ContentChannel::Mcp,
                br#"{"jsonrpc":"2.0","result":{"tools":[{"name":"read_file"}]}}"#,
            ),
        );
        assert_eq!(
            pipeline
                .pending_mcp_anomalies
                .get(&99)
                .map(Vec::len)
                .unwrap_or_default(),
            1
        );

        let mut sink = Vec::new();
        let alerts = pipeline
            .process_replay_event(3, &proc_exec_event(99), &mut sink, false)
            .expect("process event");

        assert!(
            alerts
                .iter()
                .any(|alert| alert.alert_type == "mcp_tool_spoofing")
        );
    }
}
