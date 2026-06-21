use veriskein_graph::GraphState;
use veriskein_normalizer::NormalizedEvent;

use crate::base::{
    detect_exec_observed, detect_out_of_workspace_deletion, detect_sensitive_file_access,
    detect_unexpected_shell,
};
use crate::deadloop::DeadloopDetector;
use crate::finding::Finding;
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
        let binding = graph.resolve(event.process.pid);
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
        if let Some(finding) = self.deadloop.apply(event, binding, &signals) {
            out.push(finding);
        }
        if out.is_empty() && dry_run_exec_observed {
            if let Some(finding) = detect_exec_observed(event, binding) {
                out.push(finding);
            }
        }
        out
    }
}

pub fn detect(
    event: &NormalizedEvent,
    graph: &GraphState,
    dry_run_exec_observed: bool,
) -> Vec<Finding> {
    let binding = graph.resolve(event.process.pid);
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
    if out.is_empty() && dry_run_exec_observed {
        if let Some(finding) = detect_exec_observed(event, binding) {
            out.push(finding);
        }
    }
    out
}
