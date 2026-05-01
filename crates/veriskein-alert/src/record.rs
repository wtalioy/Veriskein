use std::io::{self, Write};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use veriskein_detectors::{Finding, FindingType, VisibilityState};
use veriskein_proto::defaults;

#[derive(Debug, Clone, Serialize)]
pub struct AlertEvidence {
    pub kind: String,
    pub event_id: String,
    pub ingest_seq: u64,
    pub path: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertObjects {
    pub paths: Vec<String>,
    pub event_ids: Vec<String>,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertFallback {
    pub mode: &'static str,
    pub visibility: &'static str,
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
}

impl AlertRecord {
    pub fn from_finding(finding: &Finding) -> Self {
        let (severity, confidence_band, confidence_score) = policy_for(finding.finding_type);
        let visibility = match finding.health.visibility_state {
            VisibilityState::Full => "full",
            VisibilityState::Partial => "partial",
            VisibilityState::Unsupported => "unsupported",
            VisibilityState::Unavailable => "unavailable",
        };
        let alert_type = finding.finding_type.as_str().to_string();
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
            objects: AlertObjects {
                paths: finding.objects.paths.clone(),
                event_ids: finding.objects.event_ids.clone(),
                argv: finding.objects.argv.clone(),
            },
            evidence: finding
                .evidence
                .iter()
                .map(|evidence| AlertEvidence {
                    kind: evidence.kind.to_string(),
                    event_id: evidence.event_id.clone(),
                    ingest_seq: evidence.ingest_seq,
                    path: evidence.path.clone(),
                    note: evidence.note.clone(),
                })
                .collect(),
            fallback: AlertFallback {
                mode: "none",
                visibility,
            },
            policy: AlertPolicy {
                detector_version: 1,
                policy_version: 1,
            },
        }
    }

    pub fn as_value(&self) -> Result<Value> {
        serde_json::to_value(self).context("serialize alert record")
    }
}

fn policy_for(finding_type: FindingType) -> (&'static str, &'static str, f32) {
    match finding_type {
        FindingType::UnexpectedShell => ("high", "medium", 0.62),
        FindingType::SensitiveFileAccess => ("high", "medium", 0.68),
        FindingType::OutOfWorkspaceDeletion => ("high", "medium", 0.66),
        FindingType::ExecObserved => ("low", "strong", 1.0),
    }
}

pub fn emit_ndjson_line<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    serde_json::to_writer(&mut *writer, value).context("serialize ndjson line")?;
    writer.write_all(b"\n").context("append ndjson newline")?;
    writer.flush().context("flush ndjson writer")?;
    Ok(())
}

pub fn stdout_sink() -> Box<dyn Write + Send> {
    Box::new(io::BufWriter::new(io::stdout()))
}
