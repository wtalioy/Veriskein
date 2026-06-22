use std::collections::BTreeMap;

use veriskein_correlator::{EvidenceChain, MatchTier};
use veriskein_graph::Attribution;
use veriskein_normalizer::NormalizedEvent;

use crate::finding::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, PromptEvidenceState,
};

pub fn detect_cross_agent_prompt_injection(
    chain: &EvidenceChain,
    event: &NormalizedEvent,
    binding: &Attribution,
) -> Option<Finding> {
    if chain.root_session == chain.downstream_session {
        return None;
    }
    if chain.prompt_ids.is_empty()
        || chain.artifact_ids.is_empty()
        || chain.risky_event_ids.is_empty()
    {
        return None;
    }
    if chain.causal_score < 0.55 {
        return None;
    }
    let chain_id = chain.id.hex();
    let prompt_ids = chain
        .prompt_ids
        .iter()
        .map(|id| id.hex())
        .collect::<Vec<_>>();
    let artifact_ids = chain
        .artifact_ids
        .iter()
        .map(|id| id.hex())
        .collect::<Vec<_>>();
    let mut component_scores = BTreeMap::new();
    for (key, value) in &chain.component_scores {
        component_scores.insert((*key).to_string(), *value);
    }
    let mut health = FindingHealth::full();
    health.visibility_state = chain.visibility_state;
    health.prompt_evidence_state = PromptEvidenceState::Available;

    Some(Finding {
        finding_type: FindingType::CrossAgentPromptInjection,
        ts_ns: chain.ts_ns,
        pid: event.process.pid,
        tid: event.process.tid,
        session_id: chain.downstream_session.hex(),
        agent_id: Some(binding.agent_id.hex()),
        reason_code: reason_code(chain.match_tier).to_string(),
        summary: format!(
            "cross-session prompt injection chain {} matched upstream artifact to downstream risky action",
            &chain_id[..8]
        ),
        process_comm: event.process.comm.clone(),
        process_binary: event.process.exe.clone(),
        workspace: binding.workspace.root.display().to_string(),
        objects: FindingObjects {
            paths: Vec::new(),
            ips: Vec::new(),
            ports: Vec::new(),
            prompt_ids,
            artifact_ids,
            event_ids: chain.risky_event_ids.clone(),
            chain_id: Some(chain_id.clone()),
            workspace_id: Some(binding.workspace.id.clone()),
            root_session_id: Some(chain.root_session.hex()),
            downstream_session_id: Some(chain.downstream_session.hex()),
            argv: event.process.argv.clone(),
        },
        evidence: vec![
            FindingEvidence::chain_ref(
                "excerpt_match",
                chain_id.clone(),
                Some(chain.match_score),
                Some(chain.redacted_artifact_excerpt.clone()),
                Some(chain.redacted_prompt_excerpt.clone()),
                Some(chain.match_tier.as_str().to_string()),
            ),
            FindingEvidence::chain_ref(
                "artifact_ref",
                chain.artifact_ids[0].hex(),
                None,
                None,
                None,
                Some("workspace_file_lineage".to_string()),
            ),
            FindingEvidence::chain_ref(
                "prompt_ref",
                chain.prompt_ids[0].hex(),
                None,
                None,
                None,
                Some("downstream_prompt".to_string()),
            ),
            FindingEvidence {
                kind: "syscall".to_string(),
                event_id: chain.risky_event_ids[0].clone(),
                ingest_seq: event.ingest_seq,
                path: None,
                ip: None,
                port: None,
                score: None,
                src: None,
                dst: None,
                op: Some(event.kind.as_str().to_string()),
                note: Some("risky_action_after_prompt".to_string()),
            },
        ],
        health,
        component_scores,
        explanation: Some(chain.explanation.clone()),
    })
}

fn reason_code(tier: MatchTier) -> &'static str {
    match tier {
        MatchTier::Substring => "capi_cross_session_weak_match",
        _ => "capi_cross_session_prompt_to_syscall",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use veriskein_correlator::{EvidenceChain, MatchTier, PropagationFact};
    use veriskein_graph::{Attribution, RootEvidence, SessionState};
    use veriskein_normalizer::{NormalizedData, NormalizedEvent, ProcessSnapshot};
    use veriskein_proto::{
        AgentId, ArtifactId, AttributionStrength, ChainId, EventKind, PromptId, Role, SessionId,
        VisibilityState,
    };

    use super::detect_cross_agent_prompt_injection;

    #[test]
    fn capi_finding_carries_chain_objects() {
        let downstream = SessionId::from_seed(b"b");
        let chain = EvidenceChain {
            id: ChainId::from_seed(b"chain"),
            ts_ns: 99,
            root_session: SessionId::from_seed(b"a"),
            downstream_session: downstream,
            prompt_ids: vec![PromptId::from_seed(b"prompt")],
            artifact_ids: vec![ArtifactId::from_seed(b"artifact")],
            risky_event_ids: vec!["evt".to_string()],
            causal_score: 0.90,
            component_scores: [("causal_score", 0.90)].into_iter().collect(),
            visibility_state: VisibilityState::Full,
            propagation_fact: PropagationFact::WorkspaceFileLineage {
                artifact_path: "/tmp/ws/report.md".to_string(),
                downstream_path: "/tmp/ws/report.md".to_string(),
            },
            match_tier: MatchTier::Exact,
            match_score: 0.40,
            explanation: "explanation".to_string(),
            redacted_artifact_excerpt: "upstream".to_string(),
            redacted_prompt_excerpt: "downstream".to_string(),
        };
        let event = NormalizedEvent {
            ingest_seq: 42,
            event_id: "evt".to_string(),
            ts_ns: 99,
            kind: EventKind::ProcExec,
            process: ProcessSnapshot {
                pid: 7,
                tid: 7,
                ppid: 1,
                exe: "/bin/sh".to_string(),
                comm: "sh".to_string(),
                argv: vec!["sh".to_string()],
                cwd: PathBuf::from("/tmp/ws"),
            },
            data: NormalizedData::ProcExec {
                filename: "/bin/sh".to_string(),
                argv: vec!["sh".to_string()],
            },
        };
        let binding = Attribution {
            session_id: downstream,
            agent_id: AgentId::from_seed(b"agent"),
            lineage_id: "lineage".to_string(),
            workspace: veriskein_normalizer::WorkspaceRef {
                id: "ws-1".to_string(),
                root: PathBuf::from("/tmp/ws"),
            },
            root_pid: 7,
            state: SessionState::ConfirmedRoot,
            role: Role::RootAgent,
            role_version: 1,
            role_tags: Vec::new(),
            attribution_strength: AttributionStrength::Strong,
            root_evidence: Vec::<RootEvidence>::new(),
            revocable_until_ns: None,
        };

        let finding =
            detect_cross_agent_prompt_injection(&chain, &event, &binding).expect("finding");

        assert_eq!(finding.objects.chain_id, Some(chain.id.hex()));
        assert_eq!(finding.objects.prompt_ids.len(), 1);
        assert_eq!(finding.evidence[0].kind, "excerpt_match");
        assert_eq!(finding.agent_id, Some(binding.agent_id.hex()));
        assert_eq!(finding.evidence[3].ingest_seq, 42);
    }
}
