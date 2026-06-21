use std::sync::OnceLock;

use anyhow::{Result, bail};
use jsonschema::{Draft, Validator, options};
use serde_json::{Value, json};

static VALIDATOR: OnceLock<Validator> = OnceLock::new();
const SCHEMA_SRC: &str = include_str!("../../../proto/alert.schema.json");

pub fn validator() -> &'static Validator {
    VALIDATOR.get_or_init(|| {
        // The validator is expensive enough to cache, but the schema remains
        // compiled from the checked-in source of truth on first use.
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
            "ips": [],
            "ports": [],
            "prompt_ids": [],
            "artifact_ids": [],
            "event_ids": ["f00d"],
            "chain_id": null,
            "workspace_id": null,
            "root_session_id": null,
            "downstream_session_id": null,
            "argv": ["sh", "-lc", "true"]
        },
        "evidence": [{
            "kind": "syscall",
            "event_id": "f00d",
            "ingest_seq": 1,
            "path": "/bin/sh",
            "ip": null,
            "port": null,
            "score": null,
            "src": null,
            "dst": null,
            "op": null,
            "note": null
        }],
        "fallback": {
            "mode": "none",
            "visibility": "full",
            "prompt_evidence": "unavailable",
            "degradation_sources": []
        },
        "policy": {
            "detector_version": 1,
            "policy_version": 1,
            "component_scores": {}
        },
        "capture": {
            "mode": "none",
            "redaction": "none"
        },
        "explanation": null
    })
}
