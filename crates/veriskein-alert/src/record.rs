use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use veriskein_proto::defaults;
use veriskein_proto::{
    Finding, FindingEvidence, FindingObjects, FindingType, PromptEvidenceState, VisibilityState,
};

pub const DEGRADATION_SOURCE_RINGBUF_DROP_RATE: &str = "ringbuf_drop_rate";
pub const DEGRADATION_SOURCE_CONFIGURED_SMALL_RINGBUF: &str = "configured_small_ringbuf";
pub const DEGRADATION_SOURCE_RETENTION_EVICTION: &str = "retention_eviction";
pub(crate) const ALERT_DETECTOR_VERSION: u32 = 1;
pub(crate) const ALERT_POLICY_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PressureLevel {
    Nominal,
    Degraded,
    Critical,
}

impl PressureLevel {
    pub fn is_degraded(self) -> bool {
        !matches!(self, Self::Nominal)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuntimeHealth {
    pub pressure: PressureLevel,
    pub drop_rate: f32,
    pub degradation_sources: Vec<String>,
}

impl RuntimeHealth {
    pub fn full() -> Self {
        Self {
            pressure: PressureLevel::Nominal,
            drop_rate: 0.0,
            degradation_sources: Vec::new(),
        }
    }

    pub fn degraded(source: impl Into<String>, drop_rate: f32) -> Self {
        Self {
            pressure: PressureLevel::Degraded,
            drop_rate,
            degradation_sources: vec![source.into()],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertEvidence {
    pub kind: String,
    pub event_id: String,
    pub ingest_seq: u64,
    pub path: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub score: Option<f32>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub op: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertObjects {
    pub paths: Vec<String>,
    pub ips: Vec<String>,
    pub ports: Vec<u16>,
    pub prompt_ids: Vec<String>,
    pub artifact_ids: Vec<String>,
    pub event_ids: Vec<String>,
    pub chain_id: Option<String>,
    pub workspace_id: Option<String>,
    pub root_session_id: Option<String>,
    pub downstream_session_id: Option<String>,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertFallback {
    pub mode: &'static str,
    pub visibility: &'static str,
    pub prompt_evidence: &'static str,
    pub degradation_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertCapture {
    pub mode: &'static str,
    pub redaction: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertPolicy {
    pub detector_version: u32,
    pub policy_version: u32,
    pub component_scores: BTreeMap<String, f32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertRecord {
    pub schema_version: u32,
    pub alert_id: String,
    pub ts_ns: u64,
    #[serde(rename = "type")]
    pub alert_type: String,
    pub severity: &'static str,
    pub confidence_band: &'static str,
    pub confidence_score: f32,
    pub pid: u32,
    pub tid: u32,
    pub session_id: String,
    pub agent_id: Option<String>,
    pub summary: String,
    pub reason_code: String,
    pub objects: AlertObjects,
    pub evidence: Vec<AlertEvidence>,
    pub fallback: AlertFallback,
    pub policy: AlertPolicy,
    pub capture: AlertCapture,
    pub explanation: Option<String>,
}

impl AlertRecord {
    pub fn try_from_finding(finding: &Finding) -> Option<Self> {
        Self::try_from_finding_with_health(finding, &RuntimeHealth::full())
    }

    pub fn try_from_finding_with_health(
        finding: &Finding,
        runtime: &RuntimeHealth,
    ) -> Option<Self> {
        valid_finding(finding).then(|| Self::build_from_finding_with_health(finding, runtime))
    }

    fn build_from_finding_with_health(finding: &Finding, runtime: &RuntimeHealth) -> Self {
        let (severity, confidence_band, confidence_score) = policy_for(finding, runtime);
        let visibility_state = combined_visibility(finding.health.visibility_state, runtime);
        let visibility = visibility_state.as_str();
        let alert_type = finding.finding_type.as_str().to_string();
        // Alert ids intentionally derive from the primary object instead of
        // the raw event id so duplicate detector outputs can collapse without
        // making distinct CAPI chains collide.
        let primary_object = finding
            .objects
            .chain_id
            .as_deref()
            .or_else(|| finding.objects.paths.first().map(String::as_str))
            .or_else(|| finding.objects.event_ids.first().map(String::as_str))
            .unwrap_or("");
        let alert_id = veriskein_proto::EventId::from_seed(
            format!("{}:{}:{}", finding.session_id, alert_type, primary_object).as_bytes(),
        )
        .hex();
        Self {
            schema_version: defaults::ALERT_SCHEMA_VERSION,
            alert_id,
            ts_ns: finding.ts_ns,
            alert_type,
            severity,
            confidence_band,
            confidence_score,
            pid: finding.pid,
            tid: finding.tid,
            session_id: finding.session_id.clone(),
            agent_id: finding.agent_id.clone(),
            summary: finding.summary.clone(),
            reason_code: finding.reason_code.to_string(),
            objects: AlertObjects::from(&finding.objects),
            evidence: finding.evidence.iter().map(AlertEvidence::from).collect(),
            fallback: AlertFallback {
                mode: fallback_mode(visibility_state),
                visibility,
                prompt_evidence: finding.health.prompt_evidence_state.as_str(),
                degradation_sources: combined_degradation_sources(finding, runtime),
            },
            policy: AlertPolicy {
                detector_version: ALERT_DETECTOR_VERSION,
                policy_version: ALERT_POLICY_VERSION,
                component_scores: finding
                    .component_scores
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), *value))
                    .collect(),
            },
            capture: AlertCapture {
                mode: capture_mode(finding.health.prompt_evidence_state),
                redaction: redaction_mode(finding),
            },
            explanation: finding.explanation.clone(),
        }
    }

    pub fn as_value(&self) -> Result<Value> {
        serde_json::to_value(self).context("serialize alert record")
    }
}

fn capture_mode(prompt_evidence_state: PromptEvidenceState) -> &'static str {
    match prompt_evidence_state {
        PromptEvidenceState::Available | PromptEvidenceState::Partial => "tls",
        PromptEvidenceState::Unavailable => "none",
    }
}

fn fallback_mode(visibility_state: VisibilityState) -> &'static str {
    match visibility_state {
        VisibilityState::Full => "none",
        VisibilityState::Partial => "degraded",
        VisibilityState::Unsupported => "capture_disabled",
        VisibilityState::Unavailable => "prompt_evidence_unavailable",
    }
}

impl From<&FindingObjects> for AlertObjects {
    fn from(objects: &FindingObjects) -> Self {
        Self {
            paths: objects.paths.clone(),
            ips: objects.ips.clone(),
            ports: objects.ports.clone(),
            prompt_ids: objects.prompt_ids.clone(),
            artifact_ids: objects.artifact_ids.clone(),
            event_ids: objects.event_ids.clone(),
            chain_id: objects.chain_id.clone(),
            workspace_id: objects.workspace_id.clone(),
            root_session_id: objects.root_session_id.clone(),
            downstream_session_id: objects.downstream_session_id.clone(),
            argv: objects.argv.clone(),
        }
    }
}

impl From<&FindingEvidence> for AlertEvidence {
    fn from(evidence: &FindingEvidence) -> Self {
        Self {
            kind: evidence.kind.to_string(),
            event_id: evidence.event_id.clone(),
            ingest_seq: evidence.ingest_seq,
            path: evidence.path.clone(),
            ip: evidence.ip.clone(),
            port: evidence.port,
            score: evidence.score,
            src: evidence.src.clone(),
            dst: evidence.dst.clone(),
            op: evidence.op.clone(),
            note: evidence.note.clone(),
        }
    }
}

fn policy_for(finding: &Finding, runtime: &RuntimeHealth) -> (&'static str, &'static str, f32) {
    // The current detector set uses fixed policy metadata so schema consumers
    // can rely on stable severity bands before richer scoring lands.
    let policy = match finding.finding_type {
        FindingType::UnexpectedShell => ("high", "medium", 0.62),
        FindingType::SensitiveFileAccess => ("high", "medium", 0.68),
        FindingType::OutOfWorkspaceDeletion => ("high", "medium", 0.66),
        FindingType::SingleAgentDeadloop => ("medium", "medium", 0.62),
        FindingType::CrossAgentPromptInjection => {
            let score = finding
                .component_scores
                .get("causal_score")
                .copied()
                .unwrap_or(0.0)
                .clamp(0.0, 1.0);
            if finding.reason_code == "capi_cross_session_weak_match" {
                ("high", "medium", score.min(0.79))
            } else if score >= defaults::CAPI_SCORE_THRESHOLD {
                ("critical", "strong", score)
            } else {
                ("high", "medium", score)
            }
        }
        FindingType::McpToolSpoofing => ("high", "medium", 0.72),
        FindingType::ExecObserved => ("low", "strong", 1.0),
    };
    if finding.health.visibility_state == VisibilityState::Full && !runtime.pressure.is_degraded() {
        policy
    } else {
        let score_cap = if runtime.pressure == PressureLevel::Critical {
            0.55
        } else {
            0.70
        };
        (
            downgrade_severity(policy.0),
            cap_band(policy.1),
            policy.2.min(score_cap),
        )
    }
}

fn downgrade_severity(severity: &'static str) -> &'static str {
    match severity {
        "critical" => "high",
        "high" => "medium",
        "medium" => "low",
        _ => severity,
    }
}

fn cap_band(band: &'static str) -> &'static str {
    match band {
        "strong" => "medium",
        _ => band,
    }
}

fn redaction_mode(finding: &Finding) -> &'static str {
    if finding.finding_type == FindingType::CrossAgentPromptInjection {
        "masked"
    } else {
        "none"
    }
}

fn combined_visibility(visibility: VisibilityState, runtime: &RuntimeHealth) -> VisibilityState {
    let runtime_visibility = if runtime.pressure.is_degraded() {
        VisibilityState::Partial
    } else {
        VisibilityState::Full
    };
    visibility.worst(runtime_visibility)
}

fn combined_degradation_sources(finding: &Finding, runtime: &RuntimeHealth) -> Vec<String> {
    let mut out = finding.health.degradation_sources.clone();
    for source in &runtime.degradation_sources {
        if !out.iter().any(|existing| existing == source) {
            out.push(source.clone());
        }
    }
    if runtime.drop_rate >= defaults::DROP_RATE_DEGRADE_THRESHOLD
        && !out
            .iter()
            .any(|source| source == DEGRADATION_SOURCE_RINGBUF_DROP_RATE)
    {
        out.push(DEGRADATION_SOURCE_RINGBUF_DROP_RATE.to_string());
    }
    out
}

#[derive(Debug, Clone)]
struct ThrottleEntry {
    first_alert: AlertRecord,
    merged_event_ids: Vec<String>,
}

#[derive(Debug)]
pub struct AlertThrottler {
    entries: BTreeMap<String, ThrottleEntry>,
    max_entries: usize,
}

impl Default for AlertThrottler {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries: defaults::MAX_ALERT_THROTTLE_ENTRIES,
        }
    }
}

impl AlertThrottler {
    #[cfg(test)]
    pub(crate) fn with_max_entries(max_entries: usize) -> Self {
        Self {
            max_entries,
            ..Self::default()
        }
    }

    pub fn project(&mut self, finding: &Finding) -> Option<AlertRecord> {
        self.project_with_health(finding, &RuntimeHealth::full())
    }

    pub fn project_with_health(
        &mut self,
        finding: &Finding,
        runtime: &RuntimeHealth,
    ) -> Option<AlertRecord> {
        let mut alert = AlertRecord::try_from_finding_with_health(finding, runtime)?;
        let key = throttle_key(&alert);
        let window_ns = defaults::secs_to_ns(defaults::ALERT_DEDUP_SECS);
        self.entries.retain(|entry_key, entry| {
            entry_key == &key || alert.ts_ns.saturating_sub(entry.first_alert.ts_ns) < window_ns
        });
        let Some(entry) = self.entries.get_mut(&key) else {
            self.entries.insert(
                key,
                ThrottleEntry {
                    first_alert: alert.clone(),
                    merged_event_ids: Vec::new(),
                },
            );
            self.prune_capacity();
            return Some(alert);
        };
        if alert.ts_ns.saturating_sub(entry.first_alert.ts_ns) < window_ns {
            for event_id in &alert.objects.event_ids {
                if entry.merged_event_ids.len() < 16
                    && !entry
                        .merged_event_ids
                        .iter()
                        .any(|existing| existing == event_id)
                {
                    entry.merged_event_ids.push(event_id.clone());
                }
            }
            return None;
        }
        for event_id in entry.merged_event_ids.drain(..) {
            if !alert
                .objects
                .event_ids
                .iter()
                .any(|existing| existing == &event_id)
            {
                alert.objects.event_ids.push(event_id);
            }
        }
        entry.first_alert = alert.clone();
        Some(alert)
    }

    fn prune_capacity(&mut self) {
        while self.entries.len() > self.max_entries {
            let Some(key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.first_alert.ts_ns)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&key);
        }
    }
}

fn valid_finding(finding: &Finding) -> bool {
    if finding.reason_code.is_empty() || finding.summary.is_empty() || finding.evidence.is_empty() {
        return false;
    }
    match finding.finding_type {
        FindingType::UnexpectedShell
        | FindingType::SensitiveFileAccess
        | FindingType::OutOfWorkspaceDeletion => finding.objects.paths.len() == 1,
        FindingType::SingleAgentDeadloop => finding
            .evidence
            .iter()
            .any(|evidence| matches!(evidence.kind.as_str(), "net_connect" | "file_access")),
        FindingType::CrossAgentPromptInjection => {
            finding
                .objects
                .chain_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
                && finding.health.prompt_evidence_state != PromptEvidenceState::Unavailable
                && !finding.objects.prompt_ids.is_empty()
                && !finding.objects.artifact_ids.is_empty()
                && finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.kind == "excerpt_match")
                && finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.kind == "prompt_ref")
                && finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.kind == "syscall")
        }
        FindingType::McpToolSpoofing => {
            finding
                .evidence
                .iter()
                .any(|evidence| evidence.kind == "mcp_registry" && evidence.op.is_some())
                && !finding.objects.event_ids.is_empty()
        }
        FindingType::ExecObserved => finding.objects.paths.len() == 1,
    }
}

fn throttle_key(alert: &AlertRecord) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        alert.session_id,
        alert.alert_type,
        alert.reason_code,
        alert.fallback.mode,
        alert.policy.detector_version,
        alert.policy.policy_version,
        alert
            .objects
            .chain_id
            .as_deref()
            .or_else(|| alert.objects.paths.first().map(String::as_str))
            .unwrap_or(&alert.session_id)
    )
}

pub fn emit_ndjson_line<W: Write + ?Sized, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    // Flush per line so scenario assertions and streaming sinks observe alerts
    // promptly without depending on process teardown.
    serde_json::to_writer(&mut *writer, value).context("serialize ndjson line")?;
    writer.write_all(b"\n").context("append ndjson newline")?;
    writer.flush().context("flush ndjson writer")?;
    Ok(())
}

pub fn stdout_sink() -> Box<dyn Write + Send> {
    Box::new(io::BufWriter::new(io::stdout()))
}
