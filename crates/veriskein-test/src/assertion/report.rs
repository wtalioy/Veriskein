use std::fmt;

use serde_json::Value;

use super::spec::{Criterion, MatchSpec};

impl fmt::Display for MatchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, criterion) in self.criteria.iter().enumerate() {
            if index > 0 {
                write!(formatter, ", ")?;
            }
            write!(formatter, "{criterion}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Criterion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(alert_type) => write!(formatter, "type={alert_type}"),
            Self::FieldIn { label, values, .. } => write!(formatter, "{label} in {:?}", values),
            Self::ArrayIncludes { label, values, .. } => {
                write!(formatter, "{label} includes {:?}", values)
            }
            Self::LengthGte { label, min, .. } => write!(formatter, "{label} >= {min}"),
            Self::EvidenceHasKind(kind) => write!(formatter, "evidence.has_kind={kind}"),
            Self::EvidenceHasKinds(kinds) => {
                write!(formatter, "evidence.has_kind includes {:?}", kinds)
            }
        }
    }
}

pub(super) fn describe_actual(actual: &[Value]) -> String {
    if actual.is_empty() {
        return "no alerts".to_string();
    }
    actual
        .iter()
        .map(describe_alert)
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn describe_mismatches(spec: &MatchSpec, actual: &[Value]) -> String {
    if actual.is_empty() {
        return "no alerts to compare".to_string();
    }
    actual
        .iter()
        .take(5)
        .map(|value| {
            let mismatches = spec.mismatches(value);
            if mismatches.is_empty() {
                format!("{} matched", describe_alert(value))
            } else {
                format!(
                    "{} failed [{}]",
                    describe_alert(value),
                    mismatches.join(", ")
                )
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn describe_alert(value: &Value) -> String {
    let alert_type = value["type"].as_str().unwrap_or("<missing type>");
    let severity = value["severity"].as_str().unwrap_or("<missing severity>");
    let confidence = value["confidence_band"]
        .as_str()
        .unwrap_or("<missing confidence_band>");
    format!("type={alert_type}, severity={severity}, confidence_band={confidence}")
}
