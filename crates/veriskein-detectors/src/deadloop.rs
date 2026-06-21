use std::collections::{BTreeMap, VecDeque};

use veriskein_graph::Attribution;
use veriskein_normalizer::{NormalizedData, NormalizedEvent};
use veriskein_proto::defaults;

use crate::base::session_binding;
use crate::finding::{
    Finding, FindingEvidence, FindingHealth, FindingObjects, FindingType, VisibilityState,
};
use crate::signals::{DetectorSignal, preferred_path};

#[derive(Debug, Default)]
pub(crate) struct DeadloopDetector {
    sessions: BTreeMap<String, DeadloopSession>,
    cooldown_until_ns: BTreeMap<String, u64>,
}

impl DeadloopDetector {
    pub(crate) fn apply(
        &mut self,
        event: &NormalizedEvent,
        binding: Option<&Attribution>,
        signals: &[DetectorSignal],
    ) -> Option<Finding> {
        let binding = session_binding(binding)?;
        let session_id = binding.session_id.hex();
        let window_ns = defaults::DEADLOOP_WINDOW_S * 1_000_000_000;
        let session = self.sessions.entry(session_id.clone()).or_default();
        let progress = signals.iter().any(|signal| match signal {
            DetectorSignal::SessionProgressSignal(progress) => !progress.path.is_empty(),
            _ => false,
        });
        let loop_event = match signals.iter().find_map(|signal| match signal {
            DetectorSignal::SessionActivity(activity) => Some(activity),
            _ => None,
        }) {
            Some(activity) => {
                let crate::signals::SessionActivity {
                    ip,
                    port,
                    path,
                    evidence_kind,
                } = activity;
                LoopEvent {
                    ts_ns: event.ts_ns,
                    event_id: event.event_id.clone(),
                    ingest_seq: event.ingest_seq,
                    ip: ip.clone(),
                    port: *port,
                    path: path.clone(),
                    evidence_kind,
                    progress,
                }
            }
            _ => match &event.data {
                NormalizedData::FileOpen { path, ret_fd, .. } if *ret_fd >= 0 => LoopEvent {
                    ts_ns: event.ts_ns,
                    event_id: event.event_id.clone(),
                    ingest_seq: event.ingest_seq,
                    ip: None,
                    port: None,
                    path: Some(preferred_path(path)),
                    evidence_kind: "file_access",
                    progress,
                },
                _ => return None,
            },
        };

        session.push(loop_event);
        while session
            .events
            .front()
            .is_some_and(|entry| entry.ts_ns.saturating_add(window_ns) < event.ts_ns)
        {
            session.pop_front();
        }

        if self
            .cooldown_until_ns
            .get(&session_id)
            .is_some_and(|until| *until > event.ts_ns)
        {
            return None;
        }

        let connect_threshold =
            defaults::DEADLOOP_CONNECT_RATE_PMIN * (defaults::DEADLOOP_WINDOW_S as u32 / 60);
        let top_connect = session
            .connect_counts
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|((ip, port), count)| (ip.clone(), *port, *count));
        let top_file = session
            .file_counts
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(path, count)| (path.clone(), *count));
        let activity_attempts = session.events.len() as u32;
        let low_progress = activity_attempts >= defaults::DEADLOOP_FILE_REPEAT
            && (session.progress_signals as f32 / activity_attempts.max(1) as f32) < 0.05;

        let core_match = match (top_connect, top_file) {
            (Some((endpoint_ip, endpoint_port, connect_count)), Some((path, file_count)))
                if connect_count >= connect_threshold
                    && file_count >= defaults::DEADLOOP_FILE_REPEAT
                    && low_progress =>
            {
                DeadloopCoreMatch {
                    endpoint_ip,
                    endpoint_port,
                    path,
                    connect_count,
                    file_count,
                    low_progress,
                }
            }
            _ => return None,
        };

        self.cooldown_until_ns.insert(
            session_id.clone(),
            event.ts_ns + defaults::DEADLOOP_ALERT_COOLDOWN_S * 1_000_000_000,
        );
        Some(deadloop_finding(
            event,
            binding,
            &session_id,
            &session.events,
            &core_match,
        ))
    }
}

#[derive(Debug, Clone)]
struct LoopEvent {
    ts_ns: u64,
    event_id: String,
    ingest_seq: u64,
    ip: Option<String>,
    port: Option<u16>,
    path: Option<String>,
    evidence_kind: &'static str,
    progress: bool,
}

#[derive(Debug, Clone)]
struct DeadloopCoreMatch {
    endpoint_ip: String,
    endpoint_port: u16,
    path: String,
    connect_count: u32,
    file_count: u32,
    low_progress: bool,
}

#[derive(Debug, Default)]
struct DeadloopSession {
    events: VecDeque<LoopEvent>,
    progress_signals: u32,
    connect_counts: BTreeMap<(String, u16), u32>,
    file_counts: BTreeMap<String, u32>,
}

impl DeadloopSession {
    fn push(&mut self, event: LoopEvent) {
        if let (Some(ip), Some(port)) = (&event.ip, event.port) {
            *self.connect_counts.entry((ip.clone(), port)).or_default() += 1;
        }
        if let Some(path) = &event.path {
            *self.file_counts.entry(path.clone()).or_default() += 1;
        }
        if event.progress {
            self.progress_signals = self.progress_signals.saturating_add(1);
        }
        self.events.push_back(event);
    }

    fn pop_front(&mut self) {
        let Some(event) = self.events.pop_front() else {
            return;
        };
        if let (Some(ip), Some(port)) = (&event.ip, event.port) {
            decrement_count(&mut self.connect_counts, &(ip.clone(), port));
        }
        if let Some(path) = &event.path {
            decrement_count(&mut self.file_counts, path);
        }
        if event.progress {
            self.progress_signals = self.progress_signals.saturating_sub(1);
        }
    }
}

fn decrement_count<K>(counts: &mut BTreeMap<K, u32>, key: &K)
where
    K: Ord,
{
    let Some(count) = counts.get_mut(key) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        counts.remove(key);
    }
}

fn deadloop_finding(
    event: &NormalizedEvent,
    binding: &Attribution,
    session_id: &str,
    events: &VecDeque<LoopEvent>,
    core_match: &DeadloopCoreMatch,
) -> Finding {
    let mut paths = Vec::new();
    let mut ips = Vec::new();
    let mut ports = Vec::new();
    let mut evidence = Vec::new();
    for entry in events {
        let matches_top_connect = entry.ip.as_ref() == Some(&core_match.endpoint_ip)
            && entry.port == Some(core_match.endpoint_port);
        if entry.evidence_kind == "net_connect"
            && matches_top_connect
            && evidence
                .iter()
                .all(|e: &FindingEvidence| e.kind != "net_connect")
        {
            if let Some(ip) = &entry.ip {
                ips.push(ip.clone());
            }
            if let Some(port) = entry.port {
                ports.push(port);
            }
            evidence.push(FindingEvidence {
                kind: "net_connect",
                event_id: entry.event_id.clone(),
                ingest_seq: entry.ingest_seq,
                path: None,
                ip: entry.ip.clone(),
                port: entry.port,
                note: None,
            });
        }
        let matches_top_file = entry.path.as_ref() == Some(&core_match.path);
        if entry.evidence_kind == "file_access"
            && matches_top_file
            && evidence.iter().all(|e| e.kind != "file_access")
        {
            if let Some(path) = &entry.path {
                paths.push(path.clone());
            }
            evidence.push(FindingEvidence {
                kind: "file_access",
                event_id: entry.event_id.clone(),
                ingest_seq: entry.ingest_seq,
                path: entry.path.clone(),
                ip: None,
                port: None,
                note: None,
            });
        }
        if evidence.iter().any(|e| e.kind == "net_connect")
            && evidence.iter().any(|e| e.kind == "file_access")
        {
            break;
        }
    }

    let mut scores = BTreeMap::new();
    scores.insert("connect_rate", core_match.connect_count as f32);
    scores.insert("file_repeat", core_match.file_count as f32);
    scores.insert(
        "low_progress",
        if core_match.low_progress { 1.0 } else { 0.0 },
    );

    Finding {
        finding_type: FindingType::SingleAgentDeadloop,
        ts_ns: event.ts_ns,
        pid: event.process.pid,
        tid: event.process.tid,
        session_id: session_id.to_string(),
        agent_id: Some(binding.agent_id.hex()),
        reason_code: "deadloop_core_no_progress",
        summary: format!(
            "session stuck in a {}s loop: {} connects, {} repeated file accesses",
            defaults::DEADLOOP_WINDOW_S,
            core_match.connect_count,
            core_match.file_count
        ),
        process_comm: event.process.comm.clone(),
        process_binary: event.process.exe.clone(),
        workspace: binding.workspace.root.display().to_string(),
        objects: FindingObjects {
            paths,
            ips,
            ports,
            event_ids: evidence
                .iter()
                .map(|entry| entry.event_id.clone())
                .collect(),
            argv: event.process.argv.clone(),
        },
        evidence,
        health: FindingHealth {
            visibility_state: VisibilityState::Full,
        },
        component_scores: scores,
    }
}
