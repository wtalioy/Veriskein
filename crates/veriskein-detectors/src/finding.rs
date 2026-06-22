use std::collections::BTreeMap;

use veriskein_graph::Attribution;
use veriskein_normalizer::NormalizedEvent;

pub use veriskein_proto::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, PromptEvidenceState,
    VisibilityState,
};

pub(crate) struct FindingParts {
    pub(crate) finding_type: FindingType,
    pub(crate) ts_ns: u64,
    pub(crate) session_id: String,
    pub(crate) reason_code: String,
    pub(crate) summary: String,
    pub(crate) objects: FindingObjects,
    pub(crate) evidence: Vec<FindingEvidence>,
    pub(crate) health: FindingHealth,
    pub(crate) component_scores: BTreeMap<String, f32>,
    pub(crate) explanation: Option<String>,
}

impl FindingParts {
    pub(crate) fn new(
        finding_type: FindingType,
        ts_ns: u64,
        session_id: impl Into<String>,
        reason_code: impl Into<String>,
        summary: impl Into<String>,
        objects: FindingObjects,
        evidence: Vec<FindingEvidence>,
    ) -> Self {
        Self {
            finding_type,
            ts_ns,
            session_id: session_id.into(),
            reason_code: reason_code.into(),
            summary: summary.into(),
            objects,
            evidence,
            health: FindingHealth::full(),
            component_scores: BTreeMap::new(),
            explanation: None,
        }
    }

    pub(crate) fn with_health(mut self, health: FindingHealth) -> Self {
        self.health = health;
        self
    }

    pub(crate) fn with_component_scores(mut self, component_scores: BTreeMap<String, f32>) -> Self {
        self.component_scores = component_scores;
        self
    }

    pub(crate) fn with_explanation(mut self, explanation: impl Into<String>) -> Self {
        self.explanation = Some(explanation.into());
        self
    }
}

pub(crate) fn build_finding(
    event: &NormalizedEvent,
    binding: &Attribution,
    parts: FindingParts,
) -> Finding {
    Finding {
        finding_type: parts.finding_type,
        ts_ns: parts.ts_ns,
        pid: event.process.pid,
        tid: event.process.tid,
        session_id: parts.session_id,
        agent_id: Some(binding.agent_id.hex()),
        reason_code: parts.reason_code,
        summary: parts.summary,
        process_comm: event.process.comm.clone(),
        process_binary: event.process.exe.clone(),
        workspace: binding.workspace.root.display().to_string(),
        objects: parts.objects,
        evidence: parts.evidence,
        health: parts.health,
        component_scores: parts.component_scores,
        explanation: parts.explanation,
    }
}
