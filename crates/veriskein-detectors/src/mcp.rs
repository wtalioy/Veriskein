use std::collections::BTreeMap;

use veriskein_content::McpToolSpoofing;
use veriskein_graph::Attribution;
use veriskein_normalizer::NormalizedEvent;

use crate::finding::{
    Finding, FindingEvidence, FindingObjects, FindingParts, FindingType, build_finding,
};

pub fn detect_mcp_tool_spoofing(
    event: &NormalizedEvent,
    binding: &Attribution,
    anomalies: &[McpToolSpoofing],
) -> Vec<Finding> {
    anomalies
        .iter()
        .map(|anomaly| {
            let mut scores = BTreeMap::new();
            scores.insert("tool_name_collision".to_string(), 0.72);
            build_finding(
                event,
                binding,
                FindingParts::new(
                    FindingType::McpToolSpoofing,
                    event.ts_ns,
                    binding.session_id.hex(),
                    "mcp_tool_name_collision",
                    format!(
                        "MCP server {} advertised tool {} already registered by {}",
                        anomaly.claimed_server, anomaly.tool_name, anomaly.registered_server
                    ),
                    FindingObjects {
                        event_ids: vec![event.event_id.clone()],
                        argv: event.process.argv.clone(),
                        ..FindingObjects::default()
                    },
                    vec![FindingEvidence {
                        kind: "mcp_registry".to_string(),
                        event_id: event.event_id.clone(),
                        ingest_seq: event.ingest_seq,
                        path: None,
                        ip: None,
                        port: None,
                        score: Some(0.72),
                        src: Some(anomaly.registered_server.clone()),
                        dst: Some(anomaly.claimed_server.clone()),
                        op: Some(anomaly.tool_name.clone()),
                        note: Some(anomaly.reason.clone()),
                    }],
                )
                .with_component_scores(scores),
            )
        })
        .collect()
}
