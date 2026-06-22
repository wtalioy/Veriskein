use serde_json::Value;
use veriskein_proto::defaults;
use veriskein_proto::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, PromptEvidenceState,
    VisibilityState,
};

use crate::{
    AlertRecord, AlertThrottler, DEGRADATION_SOURCE_RINGBUF_DROP_RATE, RuntimeHealth,
    sample_alert_value, validate,
};

fn finding(finding_type: FindingType) -> Finding {
    Finding {
        finding_type,
        ts_ns: 1,
        pid: 100,
        tid: 100,
        session_id: "00112233445566778899aabbccddeeff".to_string(),
        agent_id: Some("00112233445566778899aabbccddeeff".to_string()),
        reason_code: "sensitive_file_open".to_string(),
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
            kind: "file_access".to_string(),
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
fn finding_projection_is_schema_valid() {
    let finding = finding(FindingType::SensitiveFileAccess);
    let value = AlertRecord::try_from_finding(&finding)
        .expect("valid finding")
        .as_value()
        .expect("value");
    validate(&value).expect("schema valid");
}

#[test]
fn mcp_tool_spoofing_projection_is_schema_valid() {
    let mut finding = finding(FindingType::McpToolSpoofing);
    finding.reason_code = "mcp_tool_name_collision".to_string();
    finding.summary =
        "MCP server browser advertised tool read_file already registered by filesystem".to_string();
    finding.objects = FindingObjects {
        event_ids: vec!["mcp-evt".to_string()],
        argv: vec!["mcp-server".to_string()],
        ..FindingObjects::default()
    };
    finding.evidence = vec![FindingEvidence {
        kind: "mcp_registry".to_string(),
        event_id: "mcp-evt".to_string(),
        ingest_seq: 1,
        path: None,
        ip: None,
        port: None,
        score: Some(0.72),
        src: Some("filesystem".to_string()),
        dst: Some("browser".to_string()),
        op: Some("read_file".to_string()),
        note: Some("mcp_tool_name_collision".to_string()),
    }];

    let value = AlertRecord::try_from_finding(&finding)
        .expect("valid finding")
        .as_value()
        .expect("value");

    assert_eq!(value["type"], "mcp_tool_spoofing");
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
        let value = AlertRecord::try_from_finding(&finding)
            .expect("valid finding")
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
fn prompt_health_projects_prompt_metadata() {
    let mut finding = finding(FindingType::SensitiveFileAccess);
    finding.health.visibility_state = VisibilityState::Partial;
    finding.health.prompt_evidence_state = PromptEvidenceState::Partial;
    finding
        .health
        .degradation_sources
        .push("prompt_excerpt_masked".to_string());

    let value = AlertRecord::try_from_finding(&finding)
        .expect("valid finding")
        .as_value()
        .expect("value");

    assert_eq!(value["fallback"]["prompt_evidence"], "partial");
    assert_eq!(
        value["fallback"]["degradation_sources"][0],
        "prompt_excerpt_masked"
    );
    assert_eq!(value["capture"]["mode"], "tls");
    validate(&value).expect("schema valid");
}

#[test]
fn runtime_pressure_degrades_alert_policy_once() {
    let finding = finding(FindingType::CrossAgentPromptInjection);
    let mut finding = finding;
    finding.reason_code = "capi_cross_session_prompt_to_syscall".to_string();
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
    finding.evidence = vec![
        FindingEvidence {
            kind: "excerpt_match".to_string(),
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
        },
        FindingEvidence {
            kind: "prompt_ref".to_string(),
            event_id: "00112233445566778899aabbccddeeff".to_string(),
            ingest_seq: 0,
            path: None,
            ip: None,
            port: None,
            score: None,
            src: None,
            dst: None,
            op: None,
            note: Some("downstream_prompt".to_string()),
        },
        FindingEvidence {
            kind: "syscall".to_string(),
            event_id: "evt-risk".to_string(),
            ingest_seq: 1,
            path: None,
            ip: None,
            port: None,
            score: None,
            src: None,
            dst: None,
            op: Some("proc_exec".to_string()),
            note: Some("risky_action_after_prompt".to_string()),
        },
    ];
    finding
        .component_scores
        .insert("causal_score".to_string(), 0.90);
    finding.health.prompt_evidence_state = PromptEvidenceState::Available;

    let value = AlertRecord::try_from_finding_with_health(
        &finding,
        &RuntimeHealth::degraded("test_pressure", 0.02),
    )
    .expect("valid finding")
    .as_value()
    .expect("value");

    assert_eq!(value["severity"], "high");
    assert_eq!(value["confidence_band"], "medium");
    assert_eq!(value["fallback"]["mode"], "degraded");
    assert_eq!(value["fallback"]["visibility"], "partial");
    assert!(
        value["fallback"]["degradation_sources"]
            .as_array()
            .expect("sources")
            .iter()
            .any(|source| source == DEGRADATION_SOURCE_RINGBUF_DROP_RATE)
    );
    validate(&value).expect("schema valid");
}

#[test]
fn capi_projection_is_schema_valid_and_strong() {
    let mut finding = finding(FindingType::CrossAgentPromptInjection);
    finding.reason_code = "capi_cross_session_prompt_to_syscall".to_string();
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
    finding.evidence = vec![
        FindingEvidence::chain_ref(
            "excerpt_match",
            "22222233445566778899aabbccddeeff".to_string(),
            Some(0.40),
            Some("upstream".to_string()),
            Some("downstream".to_string()),
            Some("exact".to_string()),
        ),
        FindingEvidence::chain_ref(
            "prompt_ref",
            "00112233445566778899aabbccddeeff".to_string(),
            None,
            None,
            None,
            Some("downstream_prompt".to_string()),
        ),
        FindingEvidence {
            kind: "syscall".to_string(),
            event_id: "evt-risk".to_string(),
            ingest_seq: 1,
            path: None,
            ip: None,
            port: None,
            score: None,
            src: None,
            dst: None,
            op: Some("proc_exec".to_string()),
            note: Some("risky_action_after_prompt".to_string()),
        },
    ];
    finding
        .component_scores
        .insert("causal_score".to_string(), 0.90);
    finding.health.prompt_evidence_state = PromptEvidenceState::Available;
    finding.explanation = Some("upstream excerpt -> downstream prompt -> risky action".to_string());

    let value = AlertRecord::try_from_finding(&finding)
        .expect("valid finding")
        .as_value()
        .expect("value");

    assert_eq!(value["type"], "cross_agent_prompt_injection");
    assert_eq!(value["severity"], "critical");
    assert_eq!(value["confidence_band"], "strong");
    assert_eq!(value["capture"]["redaction"], "masked");
    validate(&value).expect("schema valid");
}

#[test]
fn capi_without_prompt_evidence_is_rejected_before_projection() {
    let mut throttler = AlertThrottler::default();
    let mut finding = finding(FindingType::CrossAgentPromptInjection);
    finding.reason_code = "capi_cross_session_prompt_to_syscall".to_string();
    finding.objects = FindingObjects {
        prompt_ids: vec!["00112233445566778899aabbccddeeff".to_string()],
        artifact_ids: vec!["11112233445566778899aabbccddeeff".to_string()],
        event_ids: vec!["evt-risk".to_string()],
        chain_id: Some("22222233445566778899aabbccddeeff".to_string()),
        ..FindingObjects::default()
    };
    finding.evidence = vec![
        FindingEvidence::chain_ref(
            "excerpt_match",
            "22222233445566778899aabbccddeeff".to_string(),
            Some(0.40),
            None,
            None,
            None,
        ),
        FindingEvidence::chain_ref(
            "prompt_ref",
            "00112233445566778899aabbccddeeff".to_string(),
            None,
            None,
            None,
            None,
        ),
        FindingEvidence {
            kind: "syscall".to_string(),
            event_id: "evt-risk".to_string(),
            ingest_seq: 1,
            path: None,
            ip: None,
            port: None,
            score: None,
            src: None,
            dst: None,
            op: Some("proc_exec".to_string()),
            note: None,
        },
    ];

    assert!(throttler.project(&finding).is_none());
    assert!(AlertRecord::try_from_finding(&finding).is_none());
}

#[test]
fn substring_capi_never_projects_as_critical() {
    let mut finding = finding(FindingType::CrossAgentPromptInjection);
    finding.reason_code = "capi_cross_session_weak_match".to_string();
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
    finding.evidence = vec![
        FindingEvidence::chain_ref(
            "excerpt_match",
            "22222233445566778899aabbccddeeff".to_string(),
            Some(0.15),
            None,
            None,
            Some("substring".to_string()),
        ),
        FindingEvidence::chain_ref(
            "prompt_ref",
            "00112233445566778899aabbccddeeff".to_string(),
            None,
            None,
            None,
            None,
        ),
        FindingEvidence {
            kind: "syscall".to_string(),
            event_id: "evt-risk".to_string(),
            ingest_seq: 1,
            path: None,
            ip: None,
            port: None,
            score: None,
            src: None,
            dst: None,
            op: Some("proc_exec".to_string()),
            note: None,
        },
    ];
    finding.health.prompt_evidence_state = PromptEvidenceState::Available;
    finding
        .component_scores
        .insert("causal_score".to_string(), 0.95);

    let value = AlertRecord::try_from_finding(&finding)
        .expect("valid finding")
        .as_value()
        .expect("value");

    assert_eq!(value["severity"], "high");
    assert_eq!(value["confidence_band"], "medium");
    assert!(value["confidence_score"].as_f64().expect("score") < 0.8);
}

#[test]
fn throttler_suppresses_and_merges_inside_window() {
    let mut throttler = AlertThrottler::default();
    let mut first = finding(FindingType::SensitiveFileAccess);
    first.ts_ns = 1_000;
    first.objects.event_ids = vec!["evt-1".to_string()];
    let mut second = first.clone();
    second.ts_ns = first.ts_ns + defaults::secs_to_ns(10);
    second.objects.event_ids = vec!["evt-2".to_string()];
    let mut third = first.clone();
    third.ts_ns = first.ts_ns + defaults::secs_to_ns(61);
    third.objects.event_ids = vec!["evt-3".to_string()];

    assert!(throttler.project(&first).is_some());
    assert!(throttler.project(&second).is_none());
    let emitted = throttler.project(&third).expect("outside window emits");

    assert!(emitted.objects.event_ids.contains(&"evt-2".to_string()));
    assert!(emitted.objects.event_ids.contains(&"evt-3".to_string()));
}

#[test]
fn throttler_does_not_merge_across_fallback_modes() {
    let mut throttler = AlertThrottler::default();
    let mut first = finding(FindingType::SensitiveFileAccess);
    first.ts_ns = 1_000;
    let mut second = first.clone();
    second.ts_ns = first.ts_ns + defaults::secs_to_ns(10);

    assert!(throttler.project(&first).is_some());
    let emitted = throttler
        .project_with_health(
            &second,
            &RuntimeHealth::degraded("test_pressure", defaults::DROP_RATE_DEGRADE_THRESHOLD),
        )
        .expect("degraded explanation gets a distinct throttle key");

    assert_eq!(emitted.fallback.mode, "degraded");
}

#[test]
fn throttler_evicts_oldest_entry_when_capacity_is_exceeded() {
    let mut throttler = AlertThrottler::with_max_entries(1);
    let mut first = finding(FindingType::SensitiveFileAccess);
    first.ts_ns = 1_000;
    first.objects.paths = vec!["/etc/shadow".to_string()];
    let mut second = first.clone();
    second.ts_ns = 1_001;
    second.objects.paths = vec!["/etc/passwd".to_string()];
    let mut repeated_first = first.clone();
    repeated_first.ts_ns = 1_002;

    assert!(throttler.project(&first).is_some());
    assert!(throttler.project(&second).is_some());
    assert!(throttler.project(&repeated_first).is_some());
}
