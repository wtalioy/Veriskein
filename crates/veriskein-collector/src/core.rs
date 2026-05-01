use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;
use veriskein_proto::{
    DropReason, EventKind, EventRef, OwnedEvent, ParseError, build_meta_drop_event_bytes, parse,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CollectorCounters {
    pub reorder_or_drop_total: u64,
    pub raw_events_total: u64,
    pub emitted_events_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollectedEvent {
    pub ingest_seq: u64,
    pub event: OwnedEvent,
}

#[derive(Debug, Default)]
pub struct CollectorCore {
    // Kernel ordering is only meaningful within a CPU stream here, so we track
    // the last seen seq independently per CPU and synthesize loss/reorder facts
    // before assigning the daemon-wide ingest sequence.
    per_cpu_last_seq: BTreeMap<u32, u64>,
    next_ingest_seq: u64,
    counters: CollectorCounters,
}

impl CollectorCore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn counters(&self) -> &CollectorCounters {
        &self.counters
    }

    pub fn process_bytes(&mut self, bytes: &[u8]) -> Result<Vec<CollectedEvent>, ParseError> {
        self.counters.raw_events_total += 1;
        let parsed = parse(bytes)?;
        Ok(self.process_parsed(parsed))
    }

    pub fn process_parsed(&mut self, parsed: EventRef<'_>) -> Vec<CollectedEvent> {
        let mut out = Vec::new();
        let header = parsed.header();
        let cpu = header.cpu;
        let seq = header.seq;
        let last_seq = self.per_cpu_last_seq.get(&cpu).copied();

        if let Some(last_seq) = last_seq {
            if seq > last_seq + 1 {
                // A forward jump means the kernel stream advanced past events we
                // never observed in user space, so downstream code gets an
                // explicit synthetic drop event instead of silent data loss.
                self.counters.reorder_or_drop_total += 1;
                let missing = seq - (last_seq + 1);
                let drop_bytes = build_meta_drop_event_bytes(
                    cpu,
                    seq,
                    last_seq + 1,
                    seq,
                    missing,
                    DropReason::SeqGap,
                );
                let drop_event = parse(&drop_bytes)
                    .expect("synthesized drop event must parse")
                    .to_owned();
                out.push(self.wrap(drop_event));
            } else if seq <= last_seq {
                // Replayed or stale events are surfaced the same way: preserve
                // visibility into the ordering problem rather than pretending the
                // stream was strictly monotonic.
                self.counters.reorder_or_drop_total += 1;
                let drop_bytes = build_meta_drop_event_bytes(
                    cpu,
                    seq,
                    last_seq + 1,
                    seq,
                    0,
                    DropReason::Reordered,
                );
                let drop_event = parse(&drop_bytes)
                    .expect("synthesized reorder event must parse")
                    .to_owned();
                out.push(self.wrap(drop_event));
            }
        }

        self.per_cpu_last_seq.insert(cpu, seq);
        out.push(self.wrap(parsed.to_owned()));
        self.counters.emitted_events_total += out.len() as u64;
        out
    }

    fn wrap(&mut self, event: OwnedEvent) -> CollectedEvent {
        self.next_ingest_seq += 1;
        CollectedEvent {
            ingest_seq: self.next_ingest_seq,
            event,
        }
    }
}

pub fn is_exec_event(event: &CollectedEvent) -> bool {
    matches!(&event.event, OwnedEvent::ProcExec(_))
        && event.event.header().kind == EventKind::ProcExec as u16
}
