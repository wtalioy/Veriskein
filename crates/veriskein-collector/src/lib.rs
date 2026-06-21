//! Phase 0 ring buffer event sequencing and drop synthesis.
//! This crate owns per-CPU ordering and ingest sequence assignment.

mod core;
#[cfg(test)]
mod tests;

pub use core::{CollectedEvent, CollectorCore, CollectorCounters};
