use veriskein_proto::{DropReason, EventFixture, EventKind, OwnedEvent};

use crate::CollectorCore;

#[test]
fn synthesizes_gap_drop_event() {
    let mut collector = CollectorCore::new();
    let first = EventFixture::new(1, 1, 101, 101, 1, "a").exec("/bin/a", &["a"]);
    let third = EventFixture::new(1, 3, 103, 103, 1, "c").exec("/bin/c", &["c"]);
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
    let second = EventFixture::new(2, 2, 102, 102, 1, "b").exec("/bin/b", &["b"]);
    let first = EventFixture::new(2, 1, 101, 101, 1, "a").exec("/bin/a", &["a"]);
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

#[test]
fn independent_bpf_sources_do_not_create_false_reorders() {
    let mut collector = CollectorCore::new();
    let proc_exec = EventFixture::new(1, 10, 101, 101, 1, "a").exec("/bin/a", &["a"]);
    let file_open = EventFixture::new(1, 1, 101, 101, 1, "a").open(-100, 3, "/tmp/a");
    let net_connect = EventFixture::new(1, 1, 101, 101, 1, "a").connect(3, 443, true);

    assert_eq!(collector.process_bytes(&proc_exec).expect("proc").len(), 1);
    assert_eq!(collector.process_bytes(&file_open).expect("fs").len(), 1);
    assert_eq!(collector.process_bytes(&net_connect).expect("net").len(), 1);
    assert_eq!(collector.counters().reorder_or_drop_total, 0);
}
