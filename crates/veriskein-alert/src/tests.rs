use serde_json::Value;
use veriskein_detectors::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, VisibilityState,
};

use crate::{AlertRecord, sample_alert_value, validate};

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
    let value = AlertRecord::from_finding(&finding)
        .as_value()
        .expect("value");
    validate(&value).expect("schema valid");
}
