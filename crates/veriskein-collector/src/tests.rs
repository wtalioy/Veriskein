use veriskein_proto::{DropReason, EventKind, OwnedEvent, build_exec_event_bytes};

use crate::CollectorCore;

#[test]
fn emits_ordered_event_without_drop() {
    let mut collector = CollectorCore::new();
    let raw = build_exec_event_bytes(0, 1, 100, 100, 1, "bash", "/bin/bash", &["bash"]);
    let events = collector.process_bytes(&raw).expect("parse");
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].event, OwnedEvent::ProcExec(_)));
    assert_eq!(collector.counters().reorder_or_drop_total, 0);
}

#[test]
fn synthesizes_gap_drop_event() {
    let mut collector = CollectorCore::new();
    let first = build_exec_event_bytes(1, 1, 101, 101, 1, "a", "/bin/a", &["a"]);
    let third = build_exec_event_bytes(1, 3, 103, 103, 1, "c", "/bin/c", &["c"]);
    collector.process_bytes(&first).expect("first");
    let events = collector.process_bytes(&third).expect("third");
    assert_eq!(events.len(), 2);
    match &events[0].event {
        OwnedEvent::MetaDrop(drop_evt) => {
            assert_eq!(drop_evt.reason, DropReason::SeqGap);
            assert_eq!(drop_evt.missing, 1);
        }
        _ => panic!("expected meta drop"),
    }
    assert_eq!(collector.counters().reorder_or_drop_total, 1);
}

#[test]
fn synthesizes_reorder_event() {
    let mut collector = CollectorCore::new();
    let second = build_exec_event_bytes(2, 2, 102, 102, 1, "b", "/bin/b", &["b"]);
    let first = build_exec_event_bytes(2, 1, 101, 101, 1, "a", "/bin/a", &["a"]);
    collector.process_bytes(&second).expect("second");
    let events = collector.process_bytes(&first).expect("first");
    assert_eq!(events.len(), 2);
    match &events[0].event {
        OwnedEvent::MetaDrop(drop_evt) => {
            let kind = drop_evt.header.kind;
            assert_eq!(drop_evt.reason, DropReason::Reordered);
            assert_eq!(kind, EventKind::MetaDrop as u16);
        }
        _ => panic!("expected meta drop"),
    }
    assert_eq!(collector.counters().reorder_or_drop_total, 1);
}
