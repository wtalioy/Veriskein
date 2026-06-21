use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use veriskein_alert::{AlertThrottler, emit_ndjson_line, validate};
use veriskein_bpf::CaptureControl;
use veriskein_capture::{
    AttachSink, CaptureReconciler, CaptureStatus, ProcMapsProvider, RuntimeAttachSink,
    role_allows_capture,
};
use veriskein_collector::CollectorCore;
use veriskein_content::{
    ContentFragment, ContentRuntime, ExtractedPrompt, StreamOwner, StreamProvenance, TlsStreamKey,
};
use veriskein_correlator::{
    CapiState, ChainRiskKind, FileEventInput, InjectionKeywordConfig, PromptEvidence,
    PromptEvidenceKind, PromptInput, PromptStore,
};
use veriskein_detectors::{
    DetectorEngine, Finding, FindingEvidence, FindingType, VisibilityState,
    detect_cross_agent_prompt_injection,
};
use veriskein_graph::{AgentConfig, GraphState, LlmEndpointResolver};
use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, Normalizer, SensitiveConfig, load_workspaces,
};
use veriskein_proto::{OwnedContentFragEvent, OwnedEvent};
use veriskein_state_net::StateNet;

use crate::enrich::enrich_event_from_procfs;
use crate::env::env_evidence_for_pid;

struct NoopAttachSink;

impl AttachSink for NoopAttachSink {
    fn attach_openssl_library(&mut self, _library_path: &Path) -> Result<usize> {
        Ok(0)
    }
}

pub(crate) struct RuntimePipeline {
    collector: CollectorCore,
    agent_config: AgentConfig,
    normalizer: Normalizer,
    state_net: StateNet,
    graph: GraphState,
    detectors: DetectorEngine,
    capture: CaptureReconciler<Box<dyn AttachSink + Send>, ProcMapsProvider>,
    capture_statuses: BTreeMap<u32, CaptureStatus>,
    seen_capture_candidates: usize,
    content: ContentRuntime,
    prompts: PromptStore,
    capi: CapiState,
    alert_throttler: AlertThrottler,
}

impl RuntimePipeline {
    pub(crate) fn new(
        config_root: &Path,
        workspace_inputs: &[PathBuf],
        capture_control: Option<CaptureControl>,
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

        let attach_sink = attach_sink(capture_control);
        let seen_capture_candidates = graph.capture_candidates().len();
        Ok(Self {
            collector: CollectorCore::new(),
            agent_config,
            normalizer,
            state_net: StateNet::new(),
            graph,
            detectors: DetectorEngine::new(),
            capture: CaptureReconciler::new(attach_sink, ProcMapsProvider),
            capture_statuses: BTreeMap::new(),
            seen_capture_candidates,
            content: ContentRuntime::new(),
            prompts: PromptStore::default(),
            capi: CapiState::new(injection_keywords),
            alert_throttler: AlertThrottler::default(),
        })
    }

    pub(crate) fn process_raw_event_bytes(
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

    pub(crate) fn collector_counters(&self) -> &veriskein_collector::CollectorCounters {
        self.collector.counters()
    }

    fn process_content_fragment(&mut self, evt: &OwnedContentFragEvent) {
        for prompt in handle_content_fragment(evt, &self.graph, &self.state_net, &mut self.content)
        {
            if let Some(input) = prompt_input_from_extraction(evt, prompt) {
                let prompt_id = self.prompts.insert(input);
                if let Some(snapshot) = self.prompts.snapshot(prompt_id) {
                    self.capi.observe_prompt(snapshot);
                }
            }
        }
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
            let prompt_evidence =
                prompt_evidence_for_event(&mut self.prompts, &self.graph, &normalized);
            let mut findings = self.detectors.detect_with_prompt_evidence(
                &normalized,
                &self.graph,
                dry_run,
                &prompt_evidence,
            );
            for finding in &mut findings {
                apply_capture_health(
                    finding,
                    &normalized,
                    &prompt_evidence,
                    self.capture_statuses.get(&normalized.process.pid),
                );
            }
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
        self.reconcile_capture(normalized);
    }

    fn reconcile_capture(&mut self, normalized: &NormalizedEvent) {
        for candidate in &self.graph.capture_candidates()[self.seen_capture_candidates..] {
            if let Ok(status) = self.capture.apply_candidate(candidate, normalized.ts_ns) {
                self.capture_statuses.insert(status.pid, status);
            }
        }
        self.seen_capture_candidates = self.graph.capture_candidates().len();
        if let Some(binding) = self.graph.resolve(normalized.process.pid)
            && role_allows_capture(binding.role)
            && let Ok(status) =
                self.capture
                    .reconcile_role(normalized.process.pid, binding.role, normalized.ts_ns)
        {
            self.capture_statuses.insert(status.pid, status);
        }
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

fn attach_sink(capture_control: Option<CaptureControl>) -> Box<dyn AttachSink + Send> {
    capture_control
        .map(RuntimeAttachSink::new)
        .map(|sink| Box::new(sink) as Box<dyn AttachSink + Send>)
        .unwrap_or_else(|| Box::new(NoopAttachSink))
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

fn prompt_input_from_extraction(
    evt: &OwnedContentFragEvent,
    prompt: ExtractedPrompt,
) -> Option<PromptInput> {
    Some(PromptInput {
        session_id: prompt.owner.session_id?,
        agent_id: prompt.owner.agent_id,
        stream_id: prompt.stream_id,
        capture_mode: prompt.provenance.channel,
        ts_start: evt.header.ts_ns,
        ts_end: evt.header.ts_ns,
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

fn apply_capture_health(
    finding: &mut Finding,
    normalized: &NormalizedEvent,
    prompt_evidence: &[PromptEvidence],
    status: Option<&CaptureStatus>,
) {
    let has_risk_link = prompt_evidence
        .iter()
        .any(|evidence| matches!(evidence.kind, PromptEvidenceKind::RiskLink { .. }));
    if has_risk_link || finding.finding_type == FindingType::ExecObserved {
        return;
    }
    let Some(status) = status else {
        return;
    };
    let Some(note) = capture_health_note(status) else {
        return;
    };
    finding.health.visibility_state = status.visibility_state;
    finding.health.prompt_evidence_state = veriskein_detectors::PromptEvidenceState::Unavailable;
    finding.health.capture_lag_ms = Some(status.capture_lag_ms);
    finding.health.push_degradation_source(note.clone());
    if finding.evidence.iter().any(|evidence| {
        evidence.kind == "capture_health" && evidence.note.as_deref() == Some(&note)
    }) {
        return;
    }
    finding
        .evidence
        .push(FindingEvidence::capture_health(normalized, note));
}

fn capture_health_note(status: &CaptureStatus) -> Option<String> {
    match status.visibility_state {
        VisibilityState::Full => None,
        VisibilityState::Unsupported => Some("unsupported_tls".to_string()),
        VisibilityState::Unavailable => Some("capture_unavailable".to_string()),
        VisibilityState::Partial => Some(format!("capture_lag_ms={}", status.capture_lag_ms)),
    }
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
