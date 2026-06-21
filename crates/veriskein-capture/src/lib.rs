//! Capture attachment reconciliation for Phase 3 TLS prompt capture.

mod maps;
mod reconcile;

pub use maps::{LibraryMapping, MapsProvider, ProcMapsProvider};
pub use reconcile::{
    AttachSink, CaptureReconciler, CaptureStatus, CaptureStatusKind, RuntimeAttachSink,
    role_allows_capture,
};
