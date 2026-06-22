use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use veriskein_detectors::{
    Finding, FindingEvidence, FindingObjects, FindingType, PromptEvidenceState, VisibilityState,
};
use veriskein_proto::defaults;

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
    pub fn from_finding(finding: &Finding) -> Self {
        let (severity, confidence_band, confidence_score) = policy_for(finding);
        let visibility = finding.health.visibility_state.as_str();
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
            schema_version: defaults::EVT_ABI_VERSION,
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
                mode: fallback_mode(finding.health.visibility_state),
                visibility,
                prompt_evidence: finding.health.prompt_evidence_state.as_str(),
                degradation_sources: finding.health.degradation_sources.clone(),
            },
            policy: AlertPolicy {
                detector_version: 1,
                policy_version: 1,
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

fn policy_for(finding: &Finding) -> (&'static str, &'static str, f32) {
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
            if score >= defaults::CAPI_SCORE_THRESHOLD {
                ("critical", "strong", score)
            } else {
                ("high", "medium", score)
            }
        }
        FindingType::ExecObserved => ("low", "strong", 1.0),
    };
    if finding.health.visibility_state == VisibilityState::Full {
        policy
    } else {
        (
            downgrade_severity(policy.0),
            cap_band(policy.1),
            policy.2.min(0.70),
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

#[derive(Debug, Clone)]
struct ThrottleEntry {
    first_alert: AlertRecord,
    merged_event_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub struct AlertThrottler {
    entries: BTreeMap<String, ThrottleEntry>,
}

impl AlertThrottler {
    pub fn project(&mut self, finding: &Finding) -> Option<AlertRecord> {
        if !valid_finding(finding) {
            debug_assert!(false, "malformed finding rejected before alert projection");
            return None;
        }
        let mut alert = AlertRecord::from_finding(finding);
        let key = throttle_key(&alert);
        let window_ns = defaults::ALERT_DEDUP_SECS * 1_000_000_000;
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
            .any(|evidence| matches!(evidence.kind, "net_connect" | "file_access")),
        FindingType::CrossAgentPromptInjection => {
            finding
                .objects
                .chain_id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
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
        FindingType::ExecObserved => finding.objects.paths.len() == 1,
    }
}

fn throttle_key(alert: &AlertRecord) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        alert.session_id,
        alert.alert_type,
        alert.reason_code,
        alert.fallback.mode,
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
