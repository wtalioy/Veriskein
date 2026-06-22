use std::collections::BTreeMap;

use veriskein_proto::VisibilityState;
use veriskein_retention::BoundedMap;

use crate::{
    ContentFragment, ExtractedPrompt, StreamOwner, StreamProvenance,
    extract::{JsonFrame, extract_candidates_from_json, extract_from_body, parse_json_frame},
    http::{BodyFrame, parse_body_frame},
};

const COMPACT_CONSUMED_THRESHOLD: usize = 4096;

#[derive(Debug)]
pub struct ContentRuntime {
    streams: BoundedMap<u64, StreamState>,
    evicted_streams_total: u64,
}

impl ContentRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, fragment: ContentFragment) -> Vec<ExtractedPrompt> {
        if !self.streams.contains_key(&fragment.stream_id) {
            self.evicted_streams_total = self.evicted_streams_total.saturating_add(
                self.streams
                    .insert(
                        fragment.stream_id,
                        StreamState::new(fragment.owner.clone(), fragment.provenance.clone()),
                    )
                    .len() as u64,
            );
        }
        let stream = self
            .streams
            .get_mut(&fragment.stream_id)
            .expect("stream was inserted above");
        stream.append(fragment);
        stream.extract_ready()
    }

    pub fn finish_stream(&mut self, stream_id: u64) -> Vec<ExtractedPrompt> {
        let Some(mut stream) = self.streams.remove(&stream_id) else {
            return Vec::new();
        };
        let mut out = stream.extract_ready();
        out.extend(stream.extract_remainder());
        out
    }

    pub fn evicted_streams_total(&self) -> u64 {
        self.evicted_streams_total
    }
}

impl Default for ContentRuntime {
    fn default() -> Self {
        Self {
            streams: BoundedMap::new(veriskein_proto::defaults::MAX_STREAMS),
            evicted_streams_total: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct StreamState {
    stream_id: u64,
    owner: StreamOwner,
    provenance: StreamProvenance,
    base_offset: u64,
    next_offset: u64,
    buf: Vec<u8>,
    pending: BTreeMap<u64, Vec<u8>>,
    consumed: usize,
    degraded_reasons: Vec<String>,
}

impl StreamState {
    fn new(owner: StreamOwner, provenance: StreamProvenance) -> Self {
        Self {
            stream_id: 0,
            owner,
            provenance,
            base_offset: 0,
            next_offset: 0,
            buf: Vec::new(),
            pending: BTreeMap::new(),
            consumed: 0,
            degraded_reasons: Vec::new(),
        }
    }

    fn append(&mut self, fragment: ContentFragment) {
        self.stream_id = fragment.stream_id;
        if self.owner != fragment.owner
            || provenance_conflicts(&self.provenance, &fragment.provenance)
        {
            push_unique_reason(&mut self.degraded_reasons, "stream_metadata_conflict");
        }
        for reason in fragment.degradation_reasons {
            push_unique_reason(&mut self.degraded_reasons, reason);
        }

        self.append_bytes(fragment.offset, fragment.bytes);
        self.drain_pending();
    }

    fn extract_ready(&mut self) -> Vec<ExtractedPrompt> {
        let mut out = Vec::new();
        loop {
            if self.buf.len() <= self.consumed {
                break;
            }
            let available = &self.buf[self.consumed..];

            match parse_body_frame(available) {
                BodyFrame::Complete { body, consumed } => {
                    self.consumed += consumed;
                    out.extend(self.prompts_from_body(&body));
                    continue;
                }
                BodyFrame::Incomplete => break,
                BodyFrame::NotHttp => {}
            }

            match parse_json_frame(available) {
                JsonFrame::Complete { value, consumed } => {
                    self.consumed += consumed;
                    let candidates =
                        extract_candidates_from_json(&value, self.degraded_reasons.clone());
                    if candidates.is_empty() {
                        out.extend(self.prompts_from_body(&available[..consumed]));
                    } else {
                        out.extend(candidates.into_iter().map(|candidate| {
                            self.prompt(candidate.text, candidate.degradation_reasons)
                        }));
                    }
                    continue;
                }
                JsonFrame::Incomplete => break,
                JsonFrame::NotJson => break,
            }
        }
        self.compact_consumed();
        out
    }

    fn extract_remainder(&mut self) -> Vec<ExtractedPrompt> {
        if self.buf.len() <= self.consumed {
            return Vec::new();
        }
        let remainder = self.buf[self.consumed..].to_vec();
        self.consumed = self.buf.len();
        self.compact_consumed();
        self.prompts_from_body(&remainder)
    }

    fn prompts_from_body(&self, body: &[u8]) -> Vec<ExtractedPrompt> {
        extract_from_body(body)
            .into_iter()
            .map(|candidate| {
                self.prompt(
                    candidate.text,
                    merged_reasons(&self.degraded_reasons, &candidate.degradation_reasons),
                )
            })
            .collect()
    }

    fn prompt(&self, text: String, reasons: Vec<String>) -> ExtractedPrompt {
        let visibility = if reasons.is_empty() {
            VisibilityState::Full
        } else {
            VisibilityState::Partial
        };
        ExtractedPrompt::new(
            self.stream_id,
            self.owner.clone(),
            self.provenance.clone(),
            text,
            visibility,
            reasons,
        )
    }

    fn append_bytes(&mut self, mut offset: u64, mut bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let Ok(byte_len) = u64::try_from(bytes.len()) else {
            push_unique_reason(&mut self.degraded_reasons, "fragment_offset_overflow");
            return;
        };
        let Some(end_offset) = offset.checked_add(byte_len) else {
            push_unique_reason(&mut self.degraded_reasons, "fragment_offset_overflow");
            return;
        };
        if end_offset <= self.base_offset {
            return;
        }
        if offset < self.base_offset {
            let trim_len = usize::try_from(self.base_offset - offset)
                .unwrap_or(bytes.len())
                .min(bytes.len());
            bytes.drain(..trim_len);
            offset = self.base_offset;
            push_unique_reason(&mut self.degraded_reasons, "fragment_behind_compaction");
        }
        if offset > self.next_offset {
            self.insert_pending(offset, bytes);
            return;
        }

        let overlap = self.next_offset.saturating_sub(offset);
        let Ok(overlap_len) = usize::try_from(overlap) else {
            push_unique_reason(&mut self.degraded_reasons, "fragment_offset_overflow");
            return;
        };
        if overlap_len > bytes.len() {
            self.compare_overlap(offset, &bytes);
            return;
        }

        self.compare_overlap(offset, &bytes[..overlap_len]);
        self.extend_contiguous(&bytes[overlap_len..]);
    }

    fn insert_pending(&mut self, offset: u64, bytes: Vec<u8>) {
        match self.pending.get(&offset) {
            Some(existing) if existing == &bytes => {}
            Some(_) => push_unique_reason(&mut self.degraded_reasons, "overlap_conflict"),
            None => {
                self.pending.insert(offset, bytes);
            }
        }
    }

    fn drain_pending(&mut self) {
        loop {
            let Some((&offset, _)) = self.pending.first_key_value() else {
                return;
            };
            if offset > self.next_offset {
                return;
            }
            let Some(bytes) = self.pending.remove(&offset) else {
                return;
            };
            self.append_bytes(offset, bytes);
        }
    }

    fn compare_overlap(&mut self, offset: u64, bytes: &[u8]) {
        if offset < self.base_offset {
            return;
        }
        let Ok(start) = usize::try_from(offset - self.base_offset) else {
            push_unique_reason(&mut self.degraded_reasons, "fragment_offset_overflow");
            return;
        };
        let Some(end) = start.checked_add(bytes.len()) else {
            push_unique_reason(&mut self.degraded_reasons, "fragment_offset_overflow");
            return;
        };
        if end > self.buf.len() {
            push_unique_reason(&mut self.degraded_reasons, "fragment_offset_overflow");
            return;
        }
        if self.buf[start..end] != *bytes {
            push_unique_reason(&mut self.degraded_reasons, "overlap_conflict");
        }
    }

    fn extend_contiguous(&mut self, bytes: &[u8]) {
        let Ok(len) = u64::try_from(bytes.len()) else {
            push_unique_reason(&mut self.degraded_reasons, "fragment_offset_overflow");
            return;
        };
        let Some(next_offset) = self.next_offset.checked_add(len) else {
            push_unique_reason(&mut self.degraded_reasons, "fragment_offset_overflow");
            return;
        };
        self.buf.extend_from_slice(bytes);
        self.next_offset = next_offset;
    }

    fn compact_consumed(&mut self) {
        if self.consumed == 0 {
            return;
        }
        if self.consumed < COMPACT_CONSUMED_THRESHOLD && self.consumed < self.buf.len() {
            return;
        }
        let consumed = self.consumed;
        self.buf.drain(..consumed);
        self.base_offset = self
            .base_offset
            .saturating_add(u64::try_from(consumed).unwrap_or(u64::MAX));
        self.consumed = 0;
    }
}

fn merged_reasons(stream_reasons: &[String], candidate_reasons: &[String]) -> Vec<String> {
    let mut out = stream_reasons.to_vec();
    for reason in candidate_reasons {
        push_unique_reason(&mut out, reason);
    }
    out
}

fn provenance_conflicts(left: &StreamProvenance, right: &StreamProvenance) -> bool {
    left.channel != right.channel || left.direction != right.direction
}

fn push_unique_reason(reasons: &mut Vec<String>, reason: impl AsRef<str>) {
    let reason = reason.as_ref();
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_string());
    }
}
