use serde_json::Value;

use super::spec::{Criterion, MatchSpec};

impl MatchSpec {
    pub(crate) fn matches(&self, actual: &Value) -> bool {
        self.criteria
            .iter()
            .all(|criterion| criterion.matches(actual))
    }

    pub(super) fn mismatches(&self, actual: &Value) -> Vec<String> {
        self.criteria
            .iter()
            .filter(|criterion| !criterion.matches(actual))
            .map(ToString::to_string)
            .collect()
    }
}

impl Criterion {
    fn matches(&self, actual: &Value) -> bool {
        match self {
            Self::Type(expected) => actual["type"].as_str() == Some(expected),
            Self::FieldIn { path, values, .. } => get_path(actual, path)
                .and_then(Value::as_str)
                .is_some_and(|actual| values.iter().any(|expected| expected == actual)),
            Self::ArrayIncludes { path, values, .. } => get_path(actual, path)
                .and_then(Value::as_array)
                .is_some_and(|actual| {
                    values
                        .iter()
                        .all(|expected| array_contains(actual, expected))
                }),
            Self::LengthGte { path, min, .. } => get_owned_path(actual, path)
                .and_then(Value::as_array)
                .is_some_and(|actual| actual.len() >= *min),
            Self::EvidenceHasKind(expected) => actual["evidence"].as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["kind"].as_str() == Some(expected))
            }),
            Self::EvidenceHasKinds(expected) => {
                actual["evidence"].as_array().is_some_and(|items| {
                    expected.iter().all(|kind| {
                        items
                            .iter()
                            .any(|item| item["kind"].as_str() == Some(kind.as_str()))
                    })
                })
            }
            Self::Present { path, .. } => get_owned_path(actual, path).is_some_and(|value| {
                !value.is_null() && value.as_str().map(|text| !text.is_empty()).unwrap_or(true)
            }),
            Self::NumericGte { path, min, .. } => get_owned_path(actual, path)
                .and_then(Value::as_f64)
                .is_some_and(|actual| actual >= *min),
            Self::NotContainsText(forbidden) => serde_json::to_string(actual).is_ok_and(|text| {
                forbidden
                    .iter()
                    .all(|needle| !needle.is_empty() && !text.contains(needle))
            }),
            Self::SessionsDiffer => {
                let root =
                    get_path(actual, &["objects", "root_session_id"]).and_then(Value::as_str);
                let downstream =
                    get_path(actual, &["objects", "downstream_session_id"]).and_then(Value::as_str);
                root.zip(downstream)
                    .is_some_and(|(root, downstream)| root != downstream)
            }
        }
    }
}

fn get_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |current, key| current.get(key))
}

fn get_owned_path<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(key.as_str()))
}

fn array_contains(actual: &[Value], expected: &Value) -> bool {
    if let Some(expected) = expected.as_str() {
        return actual
            .iter()
            .filter_map(Value::as_str)
            .any(|actual| actual == expected || actual.contains(expected));
    }
    actual.contains(expected)
}
