use veriskein_correlator::{PromptEvidence, PromptEvidenceKind};
use veriskein_graph::GraphState;
use veriskein_normalizer::NormalizedEvent;
use veriskein_proto::VisibilityState;

use crate::base::{
    detect_exec_observed, detect_out_of_workspace_deletion, detect_sensitive_file_access,
    detect_unexpected_shell,
};
use crate::deadloop::DeadloopDetector;
use crate::finding::{Finding, FindingEvidence, PromptEvidenceState};
use crate::signals::materialize_signals;

#[derive(Debug, Default)]
pub struct DetectorEngine {
    deadloop: DeadloopDetector,
}

impl DetectorEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn detect(
        &mut self,
        event: &NormalizedEvent,
        graph: &GraphState,
        dry_run_exec_observed: bool,
    ) -> Vec<Finding> {
        self.detect_with_prompt_evidence(event, graph, dry_run_exec_observed, &[])
    }

    pub fn detect_with_prompt_evidence(
        &mut self,
        event: &NormalizedEvent,
        graph: &GraphState,
        dry_run_exec_observed: bool,
        prompt_evidence: &[PromptEvidence],
    ) -> Vec<Finding> {
        let Some(binding) = graph
            .resolve(event.process.pid)
            .filter(|binding| binding.is_confirmed())
        else {
            return Vec::new();
        };
        let signals = materialize_signals(event, binding);
        let mut out = Vec::new();
        if let Some(finding) = detect_unexpected_shell(event, graph, binding) {
            out.push(finding);
        }
        if let Some(finding) = detect_sensitive_file_access(event, graph, binding, &signals) {
            out.push(finding);
        }
        if let Some(finding) = detect_out_of_workspace_deletion(event, graph, binding, &signals) {
            out.push(finding);
        }
        if let Some(finding) = self
            .deadloop
            .apply(event, binding, &signals, prompt_evidence)
        {
            out.push(finding);
        }
        if out.is_empty() && dry_run_exec_observed {
            if let Some(finding) = detect_exec_observed(event, binding) {
                out.push(finding);
            }
        }
        for finding in &mut out {
            attach_prompt_evidence(finding, prompt_evidence);
        }
        out
    }
}

fn attach_prompt_evidence(finding: &mut Finding, prompt_evidence: &[PromptEvidence]) {
    for prompt in prompt_evidence {
        if !matches!(prompt.kind, PromptEvidenceKind::RiskLink { .. }) {
            continue;
        }
        if finding
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "prompt_ref" && evidence.event_id == prompt.prompt_id)
        {
            continue;
        }
        finding.evidence.push(FindingEvidence::prompt_ref(
            prompt.prompt_id.clone(),
            prompt.ingest_seq,
            Some(prompt.kind.note()),
        ));
        finding.objects.event_ids.push(prompt.prompt_id.clone());
        finding.health.prompt_evidence_state = match prompt.visibility_state {
            VisibilityState::Full => PromptEvidenceState::Available,
            _ => PromptEvidenceState::Partial,
        };
        if prompt.visibility_state != VisibilityState::Full {
            finding.health.visibility_state = prompt.visibility_state;
            finding
                .health
                .push_degradation_source("prompt_evidence_partial");
        }
    }
}
