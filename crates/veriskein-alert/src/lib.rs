//! Alert projection, validation, and NDJSON emission.

mod record;
mod schema;
#[cfg(test)]
mod tests;

pub use record::{
    AlertCapture, AlertEvidence, AlertFallback, AlertObjects, AlertPolicy, AlertRecord,
    emit_ndjson_line, stdout_sink,
};
pub use schema::{sample_alert_value, validate, validator};
