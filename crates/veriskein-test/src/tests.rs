use super::*;
use serde_json::{Value, json};

fn parse_match(value: Value) -> MatchSpec {
    serde_json::from_value(value).expect("match spec parses")
}

fn alert() -> Value {
    json!({
        "type": "unexpected_shell",
        "severity": "high",
        "confidence_band": "medium",
        "objects": {
            "paths": ["/bin/sh", "/tmp/run-123/outside/file.txt", "/usr/bin/env"],
            "ips": ["192.0.2.10"],
            "ports": [22, 443],
            "argv": ["sh", "-lc", "true"]
        },
        "evidence": [
            {"kind": "syscall"},
            {"kind": "file_access"}
        ],
        "fallback": {
            "mode": "none",
            "visibility": "full"
        }
    })
}

#[test]
fn matches_phase_two_fields() {
    let spec = parse_match(json!({
        "type": "unexpected_shell",
        "severity_in": ["high"],
        "confidence_band_in": ["medium", "strong"],
        "objects.paths_include": ["/bin/sh"],
        "objects": {
            "ips_include": ["192.0.2.10"],
            "argv": {"length_gte": 3}
        },
        "evidence.has_kind": "syscall",
        "fallback": {
            "mode_in": ["none"],
            "visibility_in": ["full", "partial"]
        }
    }));

    assert!(spec.matches(&alert()));
}

#[test]
fn evidence_kind_array_requires_all_listed_kinds() {
    let present = parse_match(json!({
        "evidence.has_kind": ["syscall", "file_access"]
    }));
    let missing = parse_match(json!({
        "evidence.has_kind": ["syscall", "net_connect"]
    }));

    assert!(present.matches(&alert()));
    assert!(!missing.matches(&alert()));
}

#[test]
fn serialized_text_can_be_forbidden() {
    let absent = parse_match(json!({
        "not_contains_text": ["sk-test", "root-password"]
    }));
    let present = parse_match(json!({
        "not_contains_text": ["unexpected_shell"]
    }));

    assert!(absent.matches(&alert()));
    assert!(!present.matches(&alert()));
}

#[test]
fn rejects_non_matching_fields() {
    let spec = parse_match(json!({
        "type": "unexpected_shell",
        "severity_in": ["low"],
        "objects.paths_include": ["/etc/shadow"],
        "objects.argv.length_gte": 4,
        "evidence.has_kind": "audit",
        "fallback.visibility_in": ["partial"]
    }));

    assert!(!spec.matches(&alert()));
}

#[test]
fn positive_assertion_reports_missing_expectation() {
    let expectation: Expectation = serde_json::from_value(json!({
        "match": {"type": "unexpected_shell", "severity_in": ["low"]}
    }))
    .expect("expectation parses");
    let error = assert_expectations(&[expectation], &[alert()])
        .expect_err("low severity expectation should be missing");

    assert!(error.to_string().contains("missing expected alert"));
    assert!(error.to_string().contains("severity_in"));
    assert!(error.to_string().contains("closest mismatches"));
}

#[test]
fn negative_assertion_reports_forbidden_expectation() {
    let expectation: Expectation = serde_json::from_value(json!({
        "negate": true,
        "match": {"type": "unexpected_shell", "evidence.has_kind": "syscall"}
    }))
    .expect("expectation parses");
    let error = assert_expectations(&[expectation], &[alert()])
        .expect_err("negated syscall expectation should be forbidden");

    assert!(error.to_string().contains("forbidden expectation matched"));
    assert!(error.to_string().contains("type=unexpected_shell"));
}
