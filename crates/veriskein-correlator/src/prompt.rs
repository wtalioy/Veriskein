use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;
use veriskein_proto::{AgentId, ContentChannel, PromptId, SessionId, VisibilityState, defaults};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptInput {
    pub session_id: SessionId,
    pub agent_id: Option<AgentId>,
    pub stream_id: u64,
    pub capture_mode: ContentChannel,
    pub ts_start: u64,
    pub ts_end: u64,
    pub excerpt: Vec<u8>,
    pub visibility_state: VisibilityState,
    pub degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PromptObject {
    pub id: PromptId,
    pub session_id: SessionId,
    pub agent_id: Option<AgentId>,
    pub stream_id: u64,
    pub capture_mode: ContentChannel,
    pub ts_start: u64,
    pub ts_end: u64,
    pub excerpt: Vec<u8>,
    pub hash_exact: [u8; 16],
    pub hash_norm: [u8; 16],
    pub visibility_state: VisibilityState,
    pub degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PromptRiskLink {
    pub prompt_id: PromptId,
    pub event_id: String,
    pub session_id: SessionId,
    pub risk_kind: String,
    pub prompt_ts_ns: u64,
    pub event_ts_ns: u64,
    pub visibility_state: VisibilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepeatedPromptSignal {
    pub prompt_id: PromptId,
    pub session_id: SessionId,
    pub normalized_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptEvidence {
    pub prompt_id: String,
    pub ingest_seq: u64,
    pub visibility_state: VisibilityState,
    pub kind: PromptEvidenceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptEvidenceKind {
    RiskLink { risk_kind: String },
    RepeatedPrompt { count: u32 },
}

impl PromptEvidenceKind {
    pub fn note(&self) -> String {
        match self {
            Self::RiskLink { risk_kind } => risk_kind.clone(),
            Self::RepeatedPrompt { count } => format!("repeated_prompt_count={count}"),
        }
    }
}

#[derive(Debug, Default)]
pub struct PromptStore {
    prompts: BTreeMap<PromptId, PromptObject>,
    by_session: BTreeMap<SessionId, VecDeque<PromptId>>,
}

impl PromptStore {
    pub fn insert(&mut self, input: PromptInput) -> PromptId {
        let hash_exact = hash16(&input.excerpt);
        let normalized = normalize_text(&input.excerpt);
        let hash_norm = hash16(normalized.as_bytes());
        let session_id = input.session_id;
        let ts_end = input.ts_end;
        let id = PromptId::from_seed(
            format!(
                "{}:{}:{}:{}",
                session_id.hex(),
                input.stream_id,
                input.ts_start,
                hex16(hash_norm)
            )
            .as_bytes(),
        );
        let prompt = PromptObject {
            id,
            session_id: input.session_id,
            agent_id: input.agent_id,
            stream_id: input.stream_id,
            capture_mode: input.capture_mode,
            ts_start: input.ts_start,
            ts_end: input.ts_end,
            excerpt: input.excerpt,
            hash_exact,
            hash_norm,
            visibility_state: input.visibility_state,
            degraded: input.degraded,
        };
        let id = prompt.id;
        self.prompts.insert(id, prompt);
        self.by_session.entry(session_id).or_default().push_back(id);
        self.evict_session(session_id, ts_end);
        id
    }

    pub fn link_risky_event(
        &mut self,
        session_id: SessionId,
        event_id: impl Into<String>,
        event_ts_ns: u64,
        risk_kind: impl Into<String>,
    ) -> Vec<PromptRiskLink> {
        self.evict_session(session_id, event_ts_ns);
        let event_id = event_id.into();
        let risk_kind = risk_kind.into();
        let Some(window_ns) = risk_window_ns(&risk_kind) else {
            return Vec::new();
        };
        self.by_session
            .get(&session_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.prompts.get(id))
            .filter(|prompt| prompt.ts_end <= event_ts_ns)
            .filter(|prompt| event_ts_ns.saturating_sub(prompt.ts_end) <= window_ns)
            .max_by_key(|prompt| prompt.ts_end)
            .map(|prompt| PromptRiskLink {
                prompt_id: prompt.id,
                event_id,
                session_id,
                risk_kind,
                prompt_ts_ns: prompt.ts_end,
                event_ts_ns,
                visibility_state: prompt.visibility_state,
            })
            .into_iter()
            .collect()
    }

    pub fn repeated_prompt_signals(
        &mut self,
        session_id: SessionId,
        now_ns: u64,
    ) -> Vec<RepeatedPromptSignal> {
        self.evict_session(session_id, now_ns);
        let mut counts = BTreeMap::<[u8; 16], u32>::new();
        let mut latest = BTreeMap::<[u8; 16], PromptId>::new();
        for prompt in self
            .by_session
            .get(&session_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.prompts.get(id))
            .filter(|prompt| {
                prompt
                    .ts_end
                    .saturating_add(defaults::PROMPT_WINDOW_MS * 1_000_000)
                    >= now_ns
            })
        {
            *counts.entry(prompt.hash_norm).or_default() += 1;
            latest.insert(prompt.hash_norm, prompt.id);
        }
        counts
            .into_iter()
            .filter_map(|(hash, count)| {
                if count >= defaults::DEADLOOP_PROMPT_DUP {
                    Some(RepeatedPromptSignal {
                        prompt_id: latest[&hash],
                        session_id,
                        normalized_count: count,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn evidence_for_event(
        &mut self,
        session_id: SessionId,
        event_id: impl Into<String>,
        event_ts_ns: u64,
        risk_kind: impl Into<String>,
        ingest_seq: u64,
    ) -> Vec<PromptEvidence> {
        let mut out = self
            .link_risky_event(session_id, event_id, event_ts_ns, risk_kind)
            .into_iter()
            .map(|link| PromptEvidence {
                prompt_id: link.prompt_id.hex(),
                ingest_seq,
                visibility_state: link.visibility_state,
                kind: PromptEvidenceKind::RiskLink {
                    risk_kind: link.risk_kind,
                },
            })
            .collect::<Vec<_>>();
        out.extend(
            self.repeated_prompt_signals(session_id, event_ts_ns)
                .into_iter()
                .map(|signal| PromptEvidence {
                    prompt_id: signal.prompt_id.hex(),
                    ingest_seq,
                    visibility_state: VisibilityState::Full,
                    kind: PromptEvidenceKind::RepeatedPrompt {
                        count: signal.normalized_count,
                    },
                }),
        );

        let mut seen = BTreeSet::new();
        out.retain(|evidence| {
            seen.insert((
                evidence.prompt_id.clone(),
                prompt_evidence_kind_key(&evidence.kind),
            ))
        });
        out
    }

    fn evict_session(&mut self, session_id: SessionId, now_ns: u64) {
        let Some(ids) = self.by_session.get_mut(&session_id) else {
            return;
        };
        let window_ns = max_prompt_retention_ns();
        while ids.front().is_some_and(|id| {
            self.prompts
                .get(id)
                .is_some_and(|prompt| prompt.ts_end.saturating_add(window_ns) < now_ns)
        }) {
            if let Some(id) = ids.pop_front() {
                self.prompts.remove(&id);
            }
        }
    }
}

fn prompt_evidence_kind_key(kind: &PromptEvidenceKind) -> u8 {
    match kind {
        PromptEvidenceKind::RiskLink { .. } => 0,
        PromptEvidenceKind::RepeatedPrompt { .. } => 1,
    }
}

fn risk_window_ns(risk_kind: &str) -> Option<u64> {
    let seconds = match risk_kind {
        "proc_exec" | "unexpected_shell" => 30,
        "file_open"
        | "file_unlink"
        | "file_rename"
        | "sensitive_file_access"
        | "out_of_workspace_deletion" => 60,
        "net_connect" | "single_agent_deadloop" => 180,
        _ => return None,
    };
    Some(seconds * 1_000_000_000)
}

fn max_prompt_retention_ns() -> u64 {
    180 * 1_000_000_000
}

fn normalize_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn hash16(bytes: &[u8]) -> [u8; 16] {
    let hash = blake3::hash(bytes);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    out
}

fn hex16(bytes: [u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use veriskein_proto::{ContentChannel, SessionId, VisibilityState};

    use super::{PromptEvidenceKind, PromptInput, PromptStore};

    fn input(session_id: SessionId, ts: u64, text: &[u8]) -> PromptInput {
        PromptInput {
            session_id,
            agent_id: None,
            stream_id: 7,
            capture_mode: ContentChannel::Tls,
            ts_start: ts,
            ts_end: ts,
            excerpt: text.to_vec(),
            visibility_state: VisibilityState::Full,
            degraded: false,
        }
    }

    #[test]
    fn links_prompt_to_later_same_session_risk() {
        let session_id = SessionId::from_seed(b"s1");
        let mut store = PromptStore::default();
        let prompt_id = store.insert(input(session_id, 10, b"run shell"));

        let links = store.link_risky_event(session_id, "evt-risk", 20, "unexpected_shell");

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].prompt_id, prompt_id);
        assert_eq!(links[0].event_id, "evt-risk");
    }

    #[test]
    fn nearest_prompt_wins() {
        let session_id = SessionId::from_seed(b"s1");
        let mut store = PromptStore::default();
        store.insert(input(session_id, 10, b"older"));
        let newer_id = store.insert(input(session_id, 20, b"newer"));

        let links = store.link_risky_event(session_id, "evt-risk", 30, "file_open");

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].prompt_id, newer_id);
    }

    #[test]
    fn risk_specific_windows_are_enforced() {
        let session_id = SessionId::from_seed(b"s1");
        let mut store = PromptStore::default();
        store.insert(input(session_id, 0, b"old"));

        assert!(
            store
                .link_risky_event(session_id, "shell", 31_000_000_000, "proc_exec")
                .is_empty()
        );
        assert_eq!(
            store
                .link_risky_event(session_id, "sensitive", 60_000_000_000, "file_open")
                .len(),
            1
        );
        assert_eq!(
            store
                .link_risky_event(session_id, "loop", 180_000_000_000, "net_connect")
                .len(),
            1
        );
    }

    #[test]
    fn repeated_prompt_signal_uses_normalized_hash() {
        let session_id = SessionId::from_seed(b"s1");
        let mut store = PromptStore::default();
        for i in 0..5 {
            store.insert(input(session_id, i, b"Same  Prompt"));
        }

        let signals = store.repeated_prompt_signals(session_id, 5);

        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].normalized_count, 5);
    }

    #[test]
    fn evidence_for_event_assembles_risk_and_repeated_prompt_evidence() {
        let session_id = SessionId::from_seed(b"s1");
        let mut store = PromptStore::default();
        let mut latest_id = None;
        for i in 0..5 {
            latest_id = Some(store.insert(input(session_id, i, b"Same  Prompt")));
        }

        let evidence = store.evidence_for_event(session_id, "evt-risk", 5, "net_connect", 99);

        assert_eq!(evidence.len(), 2);
        assert!(evidence.iter().all(|entry| entry.ingest_seq == 99));
        assert!(
            evidence
                .iter()
                .any(|entry| matches!(entry.kind, PromptEvidenceKind::RiskLink { .. }))
        );
        assert!(evidence.iter().any(|entry| {
            matches!(entry.kind, PromptEvidenceKind::RepeatedPrompt { count: 5 })
        }));
        let latest_hex = latest_id.expect("latest prompt id").hex();
        assert!(evidence.iter().all(|entry| entry.prompt_id == latest_hex));
    }
}
