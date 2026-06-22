use std::collections::{BTreeMap, VecDeque};

use veriskein_correlator::{PromptEvidence, PromptEvidenceKind};
use veriskein_graph::Attribution;
use veriskein_normalizer::{NormalizedData, NormalizedEvent};
use veriskein_proto::defaults;
use veriskein_retention::BoundedMap;

use crate::finding::{
    Finding, FindingEvidence, FindingObjects, FindingParts, FindingType, build_finding,
};
use crate::signals::DetectorSignal;

#[derive(Debug)]
pub(crate) struct DeadloopDetector {
    sessions: BoundedMap<String, DeadloopSession>,
    cooldown_until_ns: BTreeMap<String, u64>,
}

impl Default for DeadloopDetector {
    fn default() -> Self {
        Self {
            sessions: BoundedMap::new(defaults::MAX_DEADLOOP_SESSIONS.max(1)),
            cooldown_until_ns: BTreeMap::new(),
        }
    }
}

impl DeadloopDetector {
    pub(crate) fn apply(
        &mut self,
        event: &NormalizedEvent,
        binding: &Attribution,
        signals: &[DetectorSignal],
        prompt_evidence: &[PromptEvidence],
    ) -> Option<Finding> {
        let session_id = binding.session_id.hex();
        let window_ns = defaults::secs_to_ns(defaults::DEADLOOP_WINDOW_S);
        self.prune_expired(event.ts_ns, window_ns);
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
                    path: Some(path.preferred_path_string()),
                    evidence_kind: "file_access",
                    progress,
                },
                _ => return None,
            },
        };

        let mut session = self.sessions.remove(&session_id).unwrap_or_default();
        session.push(loop_event);
        session.prune_before(event.ts_ns, window_ns);
        self.insert_session(session_id.clone(), session);

        if self
            .cooldown_until_ns
            .get(&session_id)
            .is_some_and(|until| *until > event.ts_ns)
        {
            return None;
        }

        let session = self.sessions.get(&session_id)?;
        let core_match = session.match_rules(prompt_evidence)?;
        let finding = deadloop_finding(
            event,
            binding,
            &session_id,
            &session.events,
            &core_match,
            prompt_evidence,
        );
        self.cooldown_until_ns.insert(
            session_id,
            event.ts_ns + defaults::secs_to_ns(defaults::DEADLOOP_ALERT_COOLDOWN_S),
        );
        Some(finding)
    }

    pub(crate) fn prune_expired(&mut self, now_ns: u64, window_ns: u64) {
        let expired = self
            .sessions
            .iter()
            .filter(|(_, session)| session.is_expired(now_ns, window_ns))
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();
        for session_id in expired {
            self.sessions.remove(&session_id);
            self.cooldown_until_ns.remove(&session_id);
        }
        self.cooldown_until_ns.retain(|_, until| *until > now_ns);
    }

    fn insert_session(&mut self, session_id: String, session: DeadloopSession) {
        for (session_id, _) in self.sessions.insert(session_id, session) {
            self.cooldown_until_ns.remove(&session_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn tracked_session_count(&self) -> usize {
        self.sessions.iter().count()
    }

    #[cfg(test)]
    pub(crate) fn cooldown_count(&self) -> usize {
        self.cooldown_until_ns.len()
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
    connect: Option<ConnectMatch>,
    file: Option<FileMatch>,
    prompt: Option<PromptMatch>,
    low_progress: bool,
}

#[derive(Debug, Clone)]
struct ConnectMatch {
    ip: String,
    port: u16,
    count: u32,
}

#[derive(Debug, Clone)]
struct FileMatch {
    path: String,
    count: u32,
}

#[derive(Debug, Clone)]
struct PromptMatch {
    prompt_id: String,
    count: u32,
}

#[derive(Debug, Clone, Default)]
struct DeadloopSession {
    events: VecDeque<LoopEvent>,
    last_ts_ns: u64,
    progress_signals: u32,
    connect_counts: BTreeMap<(String, u16), u32>,
    file_counts: BTreeMap<String, u32>,
}

impl DeadloopSession {
    fn push(&mut self, event: LoopEvent) {
        self.last_ts_ns = event.ts_ns;
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

    fn prune_before(&mut self, now_ns: u64, window_ns: u64) {
        while self
            .events
            .front()
            .is_some_and(|entry| entry.ts_ns.saturating_add(window_ns) < now_ns)
        {
            self.pop_front();
        }
    }

    fn is_expired(&self, now_ns: u64, window_ns: u64) -> bool {
        self.events
            .back()
            .is_none_or(|entry| entry.ts_ns.saturating_add(window_ns) < now_ns)
    }

    fn match_rules(&self, prompt_evidence: &[PromptEvidence]) -> Option<DeadloopCoreMatch> {
        let connect_threshold =
            defaults::DEADLOOP_CONNECT_RATE_PMIN * (defaults::DEADLOOP_WINDOW_S as u32 / 60);
        let connect = self
            .connect_counts
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|((ip, port), count)| ConnectMatch {
                ip: ip.clone(),
                port: *port,
                count: *count,
            })
            .filter(|connect| connect.count >= connect_threshold);
        let file = self
            .file_counts
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(path, count)| FileMatch {
                path: path.clone(),
                count: *count,
            })
            .filter(|file| file.count >= defaults::DEADLOOP_FILE_REPEAT);
        let prompt = prompt_evidence
            .iter()
            .find_map(|evidence| match evidence.kind {
                PromptEvidenceKind::RepeatedPrompt { count } => Some(PromptMatch {
                    prompt_id: evidence.prompt_id.clone(),
                    count,
                }),
                PromptEvidenceKind::RiskLink { .. } => None,
            })
            .filter(|prompt| prompt.count >= defaults::DEADLOOP_PROMPT_DUP);
        let activity_attempts = self.events.len() as u32;
        let low_progress = activity_attempts >= defaults::DEADLOOP_FILE_REPEAT
            && (self.progress_signals as f32 / activity_attempts.max(1) as f32) < 0.05;
        let activity_rule_count =
            u32::from(connect.is_some()) + u32::from(file.is_some()) + u32::from(prompt.is_some());
        (low_progress && activity_rule_count >= 2).then_some(DeadloopCoreMatch {
            connect,
            file,
            prompt,
            low_progress,
        })
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
    prompt_evidence: &[PromptEvidence],
) -> Finding {
    let mut paths = Vec::new();
    let mut ips = Vec::new();
    let mut ports = Vec::new();
    let mut evidence = Vec::new();
    let mut has_connect = false;
    let mut has_file = false;
    for entry in events {
        let matches_top_connect = core_match.connect.as_ref().is_some_and(|connect| {
            entry.ip.as_ref() == Some(&connect.ip) && entry.port == Some(connect.port)
        });
        if entry.evidence_kind == "net_connect" && matches_top_connect && !has_connect {
            if let Some(ip) = &entry.ip {
                ips.push(ip.clone());
            }
            if let Some(port) = entry.port {
                ports.push(port);
            }
            evidence.push(FindingEvidence::net_connect(
                entry.event_id.clone(),
                entry.ingest_seq,
                entry.ip.clone(),
                entry.port,
            ));
            has_connect = true;
        }
        let matches_top_file = core_match
            .file
            .as_ref()
            .is_some_and(|file| entry.path.as_ref() == Some(&file.path));
        if entry.evidence_kind == "file_access" && matches_top_file && !has_file {
            if let Some(path) = &entry.path {
                paths.push(path.clone());
            }
            evidence.push(FindingEvidence::file_access_ref(
                entry.event_id.clone(),
                entry.ingest_seq,
                entry.path.clone(),
            ));
            has_file = true;
        }
        if has_connect && has_file {
            break;
        }
    }
    if let Some(prompt) = &core_match.prompt
        && evidence.iter().all(|e| e.kind != "prompt_ref")
    {
        evidence.push(FindingEvidence::prompt_ref(
            prompt.prompt_id.clone(),
            event.ingest_seq,
            Some(format!("repeated_prompt_count={}", prompt.count)),
        ));
    }

    let mut scores = BTreeMap::new();
    scores.insert(
        "connect_rate".to_string(),
        core_match
            .connect
            .as_ref()
            .map(|connect| connect.count as f32)
            .unwrap_or(0.0),
    );
    scores.insert(
        "file_repeat".to_string(),
        core_match
            .file
            .as_ref()
            .map(|file| file.count as f32)
            .unwrap_or(0.0),
    );
    scores.insert(
        "prompt_repeat".to_string(),
        core_match
            .prompt
            .as_ref()
            .map(|prompt| prompt.count as f32)
            .unwrap_or(0.0),
    );
    scores.insert(
        "low_progress".to_string(),
        if core_match.low_progress { 1.0 } else { 0.0 },
    );
    if !prompt_evidence.is_empty() {
        scores.insert("prompt_refs".to_string(), prompt_evidence.len() as f32);
    }

    build_finding(
        event,
        binding,
        FindingParts::new(
            FindingType::SingleAgentDeadloop,
            event.ts_ns,
            session_id,
            "deadloop_core_no_progress",
            format!(
                "session stuck in a {}s loop: {} connects, {} repeated file accesses, {} repeated prompts",
                defaults::DEADLOOP_WINDOW_S,
                core_match
                    .connect
                    .as_ref()
                    .map(|connect| connect.count)
                    .unwrap_or(0),
                core_match.file.as_ref().map(|file| file.count).unwrap_or(0),
                core_match
                    .prompt
                    .as_ref()
                    .map(|prompt| prompt.count)
                    .unwrap_or(0)
            ),
            FindingObjects {
                paths,
                ips,
                ports,
                event_ids: evidence
                    .iter()
                    .map(|entry| entry.event_id.clone())
                    .collect(),
                argv: event.process.argv.clone(),
                ..FindingObjects::default()
            },
            evidence,
        )
        .with_component_scores(scores),
    )
}
