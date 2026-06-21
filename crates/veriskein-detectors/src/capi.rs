use std::collections::BTreeMap;

use veriskein_correlator::{EvidenceChain, MatchTier};

use crate::finding::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, PromptEvidenceState,
};

pub fn detect_cross_agent_prompt_injection(
    chain: &EvidenceChain,
    pid: u32,
    tid: u32,
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
        component_scores.insert(*key, *value);
    }
    let mut health = FindingHealth::full();
    health.visibility_state = chain.visibility_state;
    health.prompt_evidence_state = PromptEvidenceState::Available;

    Some(Finding {
        finding_type: FindingType::CrossAgentPromptInjection,
        ts_ns: chain.ts_ns,
        pid,
        tid,
        session_id: chain.downstream_session.hex(),
        agent_id: None,
        reason_code: reason_code(chain.match_tier),
        summary: format!(
            "cross-session prompt injection chain {} matched upstream artifact to downstream risky action",
            &chain_id[..8]
        ),
        process_comm: String::new(),
        process_binary: String::new(),
        workspace: String::new(),
        objects: FindingObjects {
            paths: Vec::new(),
            ips: Vec::new(),
            ports: Vec::new(),
            prompt_ids,
            artifact_ids,
            event_ids: chain.risky_event_ids.clone(),
            chain_id: Some(chain_id.clone()),
            workspace_id: None,
            root_session_id: Some(chain.root_session.hex()),
            downstream_session_id: Some(chain.downstream_session.hex()),
            argv: Vec::new(),
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
            FindingEvidence::chain_ref(
                "syscall",
                chain.risky_event_ids[0].clone(),
                None,
                None,
                None,
                Some("risky_action_after_prompt".to_string()),
            ),
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
    use veriskein_correlator::{EvidenceChain, MatchTier, PropagationFact};
    use veriskein_proto::{ArtifactId, ChainId, PromptId, SessionId, VisibilityState};

    use super::detect_cross_agent_prompt_injection;

    #[test]
    fn capi_finding_carries_chain_objects() {
        let chain = EvidenceChain {
            id: ChainId::from_seed(b"chain"),
            ts_ns: 99,
            root_session: SessionId::from_seed(b"a"),
            downstream_session: SessionId::from_seed(b"b"),
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

        let finding = detect_cross_agent_prompt_injection(&chain, 7, 7).expect("finding");

        assert_eq!(finding.objects.chain_id, Some(chain.id.hex()));
        assert_eq!(finding.objects.prompt_ids.len(), 1);
        assert_eq!(finding.evidence[0].kind, "excerpt_match");
    }
}
