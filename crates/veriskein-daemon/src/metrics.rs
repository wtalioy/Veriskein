use std::time::{Duration, Instant};

use tracing::info;
use veriskein_collector::CollectorCounters;

pub(crate) struct MetricsTick {
    last_at: Instant,
    last_raw_events: u64,
    last_drops: u64,
    last_detector_fires: u64,
    detector_fires_total: u64,
}

impl MetricsTick {
    pub(crate) fn new() -> Self {
        Self {
            last_at: Instant::now(),
            last_raw_events: 0,
            last_drops: 0,
            last_detector_fires: 0,
            detector_fires_total: 0,
        }
    }

    pub(crate) fn add_detector_fires(&mut self, count: usize) {
        self.detector_fires_total += count as u64;
    }

    pub(crate) fn maybe_log(&mut self, counters: &CollectorCounters) {
        let elapsed = self.last_at.elapsed();
        if elapsed < Duration::from_secs(1) {
            return;
        }
        let secs = elapsed.as_secs_f64();
        let raw_delta = counters
            .raw_events_total
            .saturating_sub(self.last_raw_events);
        let drop_delta = counters
            .reorder_or_drop_total
            .saturating_sub(self.last_drops);
        let fire_delta = self
            .detector_fires_total
            .saturating_sub(self.last_detector_fires);
        info!(
            events_per_s = raw_delta as f64 / secs,
            drops_per_s = drop_delta as f64 / secs,
            detector_fires_per_s = fire_delta as f64 / secs,
            "veriskein metrics"
        );
        self.last_at = Instant::now();
        self.last_raw_events = counters.raw_events_total;
        self.last_drops = counters.reorder_or_drop_total;
        self.last_detector_fires = self.detector_fires_total;
    }
}
