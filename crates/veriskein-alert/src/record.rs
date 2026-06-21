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
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertObjects {
    pub paths: Vec<String>,
    pub ips: Vec<String>,
    pub ports: Vec<u16>,
    pub event_ids: Vec<String>,
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
    pub lag_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertPolicy {
    pub detector_version: u32,
    pub policy_version: u32,
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
}

impl AlertRecord {
    pub fn from_finding(finding: &Finding) -> Self {
        let (severity, confidence_band, confidence_score) = policy_for(finding.finding_type);
        let visibility = finding.health.visibility_state.as_str();
        let alert_type = finding.finding_type.as_str().to_string();
        // Alert ids intentionally derive from the finding shape instead of the
        // raw event id so duplicate detector outputs can collapse downstream.
        let alert_id = veriskein_proto::EventId::from_seed(
            format!(
                "{}:{}:{}",
                finding.session_id,
                alert_type,
                finding.objects.paths.join("|")
            )
            .as_bytes(),
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
            },
            capture: AlertCapture {
                mode: capture_mode(finding.health.prompt_evidence_state),
                lag_ms: finding.health.capture_lag_ms,
            },
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
            event_ids: objects.event_ids.clone(),
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
            note: evidence.note.clone(),
        }
    }
}

fn policy_for(finding_type: FindingType) -> (&'static str, &'static str, f32) {
    // The current detector set uses fixed policy metadata so schema consumers
    // can rely on stable severity bands before richer scoring lands.
    match finding_type {
        FindingType::UnexpectedShell => ("high", "medium", 0.62),
        FindingType::SensitiveFileAccess => ("high", "medium", 0.68),
        FindingType::OutOfWorkspaceDeletion => ("high", "medium", 0.66),
        FindingType::SingleAgentDeadloop => ("medium", "medium", 0.62),
        FindingType::ExecObserved => ("low", "strong", 1.0),
    }
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
