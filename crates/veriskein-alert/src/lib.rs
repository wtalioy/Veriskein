//! Alert projection, validation, and NDJSON emission.

use std::io::{self, Write};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use jsonschema::{Draft, Validator, options};
use serde::Serialize;
use serde_json::{Value, json};
use veriskein_detectors::{Finding, FindingType, VisibilityState};
use veriskein_proto::defaults;

static VALIDATOR: OnceLock<Validator> = OnceLock::new();
const SCHEMA_SRC: &str = include_str!("../../../proto/alert.schema.json");

pub fn validator() -> &'static Validator {
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(SCHEMA_SRC).expect("schema must parse");
        options()
            .with_draft(Draft::Draft202012)
            .build(&schema)
            .expect("schema must compile")
    })
}

pub fn validate(value: &Value) -> Result<()> {
    if let Err(error) = validator().validate(value) {
        bail!("{error}");
    }
    Ok(())
}

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
            format!("{}:{}:{}", finding.session_id, alert_type, finding.objects.paths.join("|")).as_bytes(),
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

pub fn sample_alert_value() -> Value {
    json!({
        "schema_version": 1,
        "alert_id": "abc123abc123abc123abc123abc123ab",
        "ts_ns": 1,
        "type": "unexpected_shell",
        "severity": "high",
        "confidence_band": "medium",
        "confidence_score": 0.62,
        "pid": 100,
        "tid": 100,
        "session_id": "00112233445566778899aabbccddeeff",
        "agent_id": "00112233445566778899aabbccddeeff",
        "summary": "session spawned unexpected shell /bin/sh",
        "reason_code": "shell_exec_unapproved",
        "objects": {
            "paths": ["/bin/sh"],
            "event_ids": ["f00d"],
            "argv": ["sh", "-lc", "true"]
        },
        "evidence": [{
            "kind": "syscall",
            "event_id": "f00d",
            "ingest_seq": 1,
            "path": "/bin/sh",
            "note": null
        }],
        "fallback": {
            "mode": "none",
            "visibility": "full"
        },
        "policy": {
            "detector_version": 1,
            "policy_version": 1
        }
    })
}

pub fn stdout_sink() -> Box<dyn Write + Send> {
    Box::new(io::BufWriter::new(io::stdout()))
}

#[cfg(test)]
mod tests {
    use veriskein_detectors::{Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, VisibilityState};

    use super::*;

    #[test]
    fn schema_roundtrip() {
        let sample = sample_alert_value();
        validate(&sample).expect("sample alert must validate");
    }

    #[test]
    fn malformed_payload_is_rejected() {
        let mut sample = sample_alert_value();
        sample["severity"] = Value::String("banana".to_string());
        assert!(validate(&sample).is_err());
    }

    #[test]
    fn finding_projection_is_schema_valid() {
        let finding = Finding {
            finding_type: FindingType::SensitiveFileAccess,
            ts_ns: 1,
            pid: 100,
            tid: 100,
            session_id: "00112233445566778899aabbccddeeff".to_string(),
            agent_id: Some("00112233445566778899aabbccddeeff".to_string()),
            reason_code: "sensitive_file_open",
            summary: "opened /etc/shadow".to_string(),
            process_comm: "claude".to_string(),
            process_binary: "/usr/bin/claude".to_string(),
            workspace: "/tmp/ws".to_string(),
            objects: FindingObjects {
                paths: vec!["/etc/shadow".to_string()],
                event_ids: vec!["deadbeef".to_string()],
                argv: vec!["claude".to_string()],
            },
            evidence: vec![FindingEvidence {
                kind: "file_access",
                event_id: "deadbeef".to_string(),
                ingest_seq: 1,
                path: Some("/etc/shadow".to_string()),
                note: None,
            }],
            health: FindingHealth {
                visibility_state: VisibilityState::Full,
            },
        };
        let value = AlertRecord::from_finding(&finding).as_value().expect("value");
        validate(&value).expect("schema valid");
    }
}
