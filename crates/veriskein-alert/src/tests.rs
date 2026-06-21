use serde_json::Value;
use veriskein_detectors::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, PromptEvidenceState,
    VisibilityState,
};

use crate::{AlertRecord, sample_alert_value, validate};

fn finding(finding_type: FindingType) -> Finding {
    Finding {
        finding_type,
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
            ips: Vec::new(),
            ports: Vec::new(),
            event_ids: vec!["deadbeef".to_string()],
            argv: vec!["claude".to_string()],
        },
        evidence: vec![FindingEvidence {
            kind: "file_access",
            event_id: "deadbeef".to_string(),
            ingest_seq: 1,
            path: Some("/etc/shadow".to_string()),
            ip: None,
            port: None,
            note: None,
        }],
        health: FindingHealth::full(),
        component_scores: Default::default(),
    }
}

#[test]
fn malformed_payload_is_rejected() {
    let mut sample = sample_alert_value();
    sample["severity"] = Value::String("banana".to_string());
    assert!(validate(&sample).is_err());
}

#[test]
fn schema_accepts_alert_without_optional_network_fields() {
    let mut sample = sample_alert_value();
    sample["objects"]
        .as_object_mut()
        .expect("objects")
        .remove("ips");
    sample["objects"]
        .as_object_mut()
        .expect("objects")
        .remove("ports");
    sample["evidence"][0]
        .as_object_mut()
        .expect("evidence")
        .remove("ip");
    sample["evidence"][0]
        .as_object_mut()
        .expect("evidence")
        .remove("port");

    validate(&sample).expect("alert without network fields must validate");
}

#[test]
fn finding_projection_is_schema_valid() {
    let finding = finding(FindingType::SensitiveFileAccess);
    let value = AlertRecord::from_finding(&finding)
        .as_value()
        .expect("value");
    validate(&value).expect("schema valid");
}

#[test]
fn deadloop_projection_is_schema_valid() {
    let finding = Finding {
        reason_code: "deadloop_core_no_progress",
        summary: "session stuck in a loop".to_string(),
        process_comm: "claude".to_string(),
        process_binary: "/usr/bin/claude".to_string(),
        objects: FindingObjects {
            paths: vec!["/tmp/loopfile".to_string()],
            ips: vec!["127.0.0.1".to_string()],
            ports: vec![443],
            event_ids: vec!["net-1".to_string(), "file-1".to_string()],
            argv: vec!["claude".to_string()],
        },
        evidence: vec![
            FindingEvidence {
                kind: "net_connect",
                event_id: "net-1".to_string(),
                ingest_seq: 1,
                path: None,
                ip: Some("127.0.0.1".to_string()),
                port: Some(443),
                note: None,
            },
            FindingEvidence {
                kind: "file_access",
                event_id: "file-1".to_string(),
                ingest_seq: 2,
                path: Some("/tmp/loopfile".to_string()),
                ip: None,
                port: None,
                note: None,
            },
        ],
        health: FindingHealth::full(),
        ..finding(FindingType::SingleAgentDeadloop)
    };
    let value = AlertRecord::from_finding(&finding)
        .as_value()
        .expect("value");
    validate(&value).expect("schema valid");
}

#[test]
fn visibility_state_mapping_is_centralized() {
    let mut finding = finding(FindingType::SensitiveFileAccess);

    for (state, expected_visibility, expected_mode) in [
        (VisibilityState::Full, "full", "none"),
        (VisibilityState::Partial, "partial", "degraded"),
        (
            VisibilityState::Unsupported,
            "unsupported",
            "capture_disabled",
        ),
        (
            VisibilityState::Unavailable,
            "unavailable",
            "prompt_evidence_unavailable",
        ),
    ] {
        finding.health.visibility_state = state;
        let value = AlertRecord::from_finding(&finding)
            .as_value()
            .expect("value");
        assert_eq!(value["fallback"]["visibility"], expected_visibility);
        assert_eq!(value["fallback"]["mode"], expected_mode);
        assert_eq!(value["fallback"]["prompt_evidence"], "unavailable");
        assert_eq!(value["capture"]["mode"], "none");
        validate(&value).expect("schema valid");
    }
}

#[test]
fn prompt_health_projects_capture_metadata() {
    let mut finding = finding(FindingType::SensitiveFileAccess);
    finding.health.visibility_state = VisibilityState::Partial;
    finding.health.prompt_evidence_state = PromptEvidenceState::Partial;
    finding.health.capture_lag_ms = Some(750);
    finding
        .health
        .degradation_sources
        .push("capture_lag_ms=750".to_string());

    let value = AlertRecord::from_finding(&finding)
        .as_value()
        .expect("value");

    assert_eq!(value["fallback"]["prompt_evidence"], "partial");
    assert_eq!(
        value["fallback"]["degradation_sources"][0],
        "capture_lag_ms=750"
    );
    assert_eq!(value["capture"]["mode"], "tls");
    assert_eq!(value["capture"]["lag_ms"], 750);
    validate(&value).expect("schema valid");
}
