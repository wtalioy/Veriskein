use std::collections::BTreeMap;

use veriskein_content::McpToolSpoofing;
use veriskein_graph::Attribution;
use veriskein_normalizer::NormalizedEvent;

use crate::finding::{
    Finding, FindingEvidence, FindingObjects, FindingParts, FindingType, build_finding,
};

#[derive(Debug, Clone)]
pub struct McpAnomalyContext {
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub event_id: String,
    pub ingest_seq: u64,
    pub argv: Vec<String>,
    pub process_comm: String,
    pub process_binary: String,
}

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
                        kind: "heuristic".to_string(),
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

pub fn mcp_tool_spoofing_findings_from_content(
    context: McpAnomalyContext,
    binding: &Attribution,
    anomalies: &[McpToolSpoofing],
) -> Vec<Finding> {
    anomalies
        .iter()
        .map(|anomaly| {
            let mut scores = BTreeMap::new();
            scores.insert("tool_name_collision".to_string(), 0.72);
            Finding {
                finding_type: FindingType::McpToolSpoofing,
                ts_ns: context.ts_ns,
                pid: context.pid,
                tid: context.tid,
                session_id: binding.session_id.hex(),
                agent_id: Some(binding.agent_id.hex()),
                reason_code: "mcp_tool_name_collision".to_string(),
                summary: format!(
                    "MCP server {} advertised tool {} already registered by {}",
                    anomaly.claimed_server, anomaly.tool_name, anomaly.registered_server
                ),
                process_comm: context.process_comm.clone(),
                process_binary: context.process_binary.clone(),
                workspace: binding.workspace.root.display().to_string(),
                objects: FindingObjects {
                    event_ids: vec![context.event_id.clone()],
                    argv: context.argv.clone(),
                    ..FindingObjects::default()
                },
                evidence: vec![FindingEvidence {
                    kind: "heuristic".to_string(),
                    event_id: context.event_id.clone(),
                    ingest_seq: context.ingest_seq,
                    path: None,
                    ip: None,
                    port: None,
                    score: Some(0.72),
                    src: Some(anomaly.registered_server.clone()),
                    dst: Some(anomaly.claimed_server.clone()),
                    op: Some(anomaly.tool_name.clone()),
                    note: Some(anomaly.reason.clone()),
                }],
                health: veriskein_proto::FindingHealth::full(),
                component_scores: scores,
                explanation: None,
            }
        })
        .collect()
}
