//! Phase 0 alert validation and NDJSON emission.
//! This crate owns the outward JSON contract and sink helpers.

use std::io::{self, Write};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use jsonschema::{Draft, Validator, options};
use serde::Serialize;
use serde_json::{Value, json};
use veriskein_proto::{OwnedEvent, defaults};

static VALIDATOR: OnceLock<Validator> = OnceLock::new();
const SCHEMA_SRC: &str = include_str!("../../../proto/alert.schema.json");

pub fn validator() -> &'static Validator {
    VALIDATOR.get_or_init(|| {
        // Compile the schema once and share it across the process so every sink
        // path validates against the same contract without repeated setup cost.
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
    // Keep evidence references shallow in the outward schema: ids and ordering
    // metadata are enough for Phase 0, while richer explanation fields can be
    // layered on later without changing how sinks consume alerts.
    pub kind: String,
    pub event_id: String,
    pub ingest_seq: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertProcess {
    pub pid: u32,
    pub tgid: u32,
    pub tid: u32,
    pub comm: String,
    pub binary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertSession {
    pub session_id: String,
    pub workspace: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertObjects {
    pub event_kind: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertFallback {
    pub mode: &'static str,
    pub visibility: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertRecord {
    // This is the runtime-owned alert shape before serialization, intentionally
    // close to the JSON schema so validation is a simple projection check.
    pub schema_version: u32,
    #[serde(rename = "type")]
    pub alert_type: String,
    pub severity: &'static str,
    pub confidence_band: &'static str,
    pub timestamp: String,
    pub process: AlertProcess,
    pub session: AlertSession,
    pub evidence: Vec<AlertEvidence>,
    pub objects: AlertObjects,
    pub fallback: AlertFallback,
}

impl AlertRecord {
    pub fn from_exec_event(
        event: &OwnedEvent,
        ingest_seq: u64,
        workspace: &str,
        timestamp: String,
    ) -> Option<Self> {
        match event {
            OwnedEvent::ProcExec(exec) => {
                // Phase 0 intentionally projects a minimal "exec observed" alert:
                // enough to prove the wire->analysis->schema path before detector
                // semantics become more sophisticated in later phases.
                let event_id = event.event_id().hex();
                Some(Self {
                    schema_version: defaults::EVT_ABI_VERSION,
                    alert_type: "exec_observed".to_string(),
                    severity: "low",
                    confidence_band: "strong",
                    timestamp,
                    process: AlertProcess {
                        pid: exec.pid,
                        tgid: exec.tgid,
                        tid: exec.pid,
                        comm: exec.comm.clone(),
                        binary: exec.filename.clone(),
                    },
                    session: AlertSession {
                        session_id: format!("phase0-{}", exec.tgid),
                        workspace: workspace.to_string(),
                    },
                    evidence: vec![AlertEvidence {
                        kind: "syscall".to_string(),
                        event_id,
                        ingest_seq,
                    }],
                    objects: AlertObjects {
                        event_kind: "proc_exec".to_string(),
                        argv: exec.argv.clone(),
                    },
                    fallback: AlertFallback {
                        mode: "none",
                        visibility: "full",
                    },
                })
            }
            OwnedEvent::MetaDrop(_) => None,
        }
    }

    pub fn as_value(&self) -> Result<Value> {
        serde_json::to_value(self).context("serialize alert record")
    }
}

pub fn emit_ndjson_line<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    // NDJSON is the phase-0 external contract, so we flush each line eagerly to
    // keep dry-run behavior simple and visible during smoke testing.
    serde_json::to_writer(&mut *writer, value).context("serialize ndjson line")?;
    writer.write_all(b"\n").context("append ndjson newline")?;
    writer.flush().context("flush ndjson writer")?;
    Ok(())
}

pub fn sample_alert_value() -> Value {
    // Test helper for the schema boundary: keep one canonical "good" payload so
    // malformed-field tests can mutate it instead of rebuilding alerts ad hoc.
    json!({
        "schema_version": 1,
        "type": "exec_observed",
        "severity": "low",
        "confidence_band": "strong",
        "timestamp": "2026-05-01T00:00:00Z",
        "process": {
            "pid": 100,
            "tgid": 100,
            "tid": 100,
            "comm": "bash",
            "binary": "/bin/bash"
        },
        "session": {
            "session_id": "phase0-100",
            "workspace": "/tmp/ws"
        },
        "evidence": [{
            "kind": "syscall",
            "event_id": "abc123",
            "ingest_seq": 1
        }],
        "objects": {
            "event_kind": "proc_exec",
            "argv": ["bash", "-lc", "true"]
        },
        "fallback": {
            "mode": "none",
            "visibility": "full"
        }
    })
}

pub fn stdout_sink() -> Box<dyn Write + Send> {
    // Wrap stdout in a buffered writer so the rest of the sink API can treat
    // file and console outputs the same way.
    Box::new(io::BufWriter::new(io::stdout()))
}

#[cfg(test)]
mod tests {
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
    fn ndjson_writer_adds_one_line() {
        let sample = sample_alert_value();
        let mut bytes = Vec::new();
        emit_ndjson_line(&mut bytes, &sample).expect("ndjson should serialize");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.ends_with('\n'));
        let line: Value = serde_json::from_str(text.trim_end()).expect("json line");
        assert_eq!(line["type"], "exec_observed");
    }
}
