use serde_json::Value;
use veriskein_detectors::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, PromptEvidenceState,
    VisibilityState,
};

use crate::{AlertRecord, AlertThrottler, sample_alert_value, validate};

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
            event_ids: vec!["deadbeef".to_string()],
            argv: vec!["claude".to_string()],
            ..FindingObjects::default()
        },
        evidence: vec![FindingEvidence {
            kind: "file_access",
            event_id: "deadbeef".to_string(),
            ingest_seq: 1,
            path: Some("/etc/shadow".to_string()),
            ip: None,
            port: None,
            score: None,
            src: None,
            dst: None,
            op: None,
            note: None,
        }],
        health: FindingHealth::full(),
        component_scores: Default::default(),
        explanation: None,
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
            ..FindingObjects::default()
        },
        evidence: vec![
            FindingEvidence {
                kind: "net_connect",
                event_id: "net-1".to_string(),
                ingest_seq: 1,
                path: None,
                ip: Some("127.0.0.1".to_string()),
                port: Some(443),
                score: None,
                src: None,
                dst: None,
                op: None,
                note: None,
            },
            FindingEvidence {
                kind: "file_access",
                event_id: "file-1".to_string(),
                ingest_seq: 2,
                path: Some("/tmp/loopfile".to_string()),
                ip: None,
                port: None,
                score: None,
                src: None,
                dst: None,
                op: None,
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

#[test]
fn capi_projection_is_schema_valid_and_strong() {
    let mut finding = finding(FindingType::CrossAgentPromptInjection);
    finding.reason_code = "capi_cross_session_prompt_to_syscall";
    finding.summary = "cross-session prompt injection".to_string();
    finding.objects = FindingObjects {
        prompt_ids: vec!["00112233445566778899aabbccddeeff".to_string()],
        artifact_ids: vec!["11112233445566778899aabbccddeeff".to_string()],
        event_ids: vec!["evt-risk".to_string()],
        chain_id: Some("22222233445566778899aabbccddeeff".to_string()),
        root_session_id: Some("33333333445566778899aabbccddeeff".to_string()),
        downstream_session_id: Some("00112233445566778899aabbccddeeff".to_string()),
        ..FindingObjects::default()
    };
    finding.evidence = vec![FindingEvidence {
        kind: "excerpt_match",
        event_id: "22222233445566778899aabbccddeeff".to_string(),
        ingest_seq: 0,
        path: None,
        ip: None,
        port: None,
        score: Some(0.40),
        src: Some("upstream".to_string()),
        dst: Some("downstream".to_string()),
        op: None,
        note: Some("exact".to_string()),
    }];
    finding.component_scores.insert("causal_score", 0.90);
    finding.health.prompt_evidence_state = PromptEvidenceState::Available;
    finding.explanation = Some("upstream excerpt -> downstream prompt -> risky action".to_string());

    let value = AlertRecord::from_finding(&finding)
        .as_value()
        .expect("value");

    assert_eq!(value["type"], "cross_agent_prompt_injection");
    assert_eq!(value["severity"], "critical");
    assert_eq!(value["confidence_band"], "strong");
    assert_eq!(value["capture"]["redaction"], "masked");
    validate(&value).expect("schema valid");
}

#[test]
fn throttler_suppresses_and_merges_inside_window() {
    let mut throttler = AlertThrottler::default();
    let mut first = finding(FindingType::SensitiveFileAccess);
    first.ts_ns = 1_000;
    first.objects.event_ids = vec!["evt-1".to_string()];
    let mut second = first.clone();
    second.ts_ns = first.ts_ns + 10_000_000_000;
    second.objects.event_ids = vec!["evt-2".to_string()];
    let mut third = first.clone();
    third.ts_ns = first.ts_ns + 61_000_000_000;
    third.objects.event_ids = vec!["evt-3".to_string()];

    assert!(throttler.project(&first).is_some());
    assert!(throttler.project(&second).is_none());
    let emitted = throttler.project(&third).expect("outside window emits");

    assert!(emitted.objects.event_ids.contains(&"evt-2".to_string()));
    assert!(emitted.objects.event_ids.contains(&"evt-3".to_string()));
}
