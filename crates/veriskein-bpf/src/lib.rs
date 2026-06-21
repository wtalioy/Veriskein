//! BPF loading, attachment, and raw event delivery.

mod runtime;

pub use runtime::{CaptureControl, RuntimeEventSource};
