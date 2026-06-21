use serde_json::Value;

use super::spec::{ArrayMatchMode, Criterion, MatchSpec};

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
            Self::ArrayIncludes {
                path,
                values,
                match_mode,
                ..
            } => get_path(actual, path)
                .and_then(Value::as_array)
                .is_some_and(|actual| {
                    values
                        .iter()
                        .all(|expected| array_contains(actual, expected, *match_mode))
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

fn array_contains(actual: &[Value], expected: &Value, match_mode: ArrayMatchMode) -> bool {
    if let Some(expected) = expected.as_str() {
        return actual
            .iter()
            .filter_map(Value::as_str)
            .any(|actual| string_matches(actual, expected, match_mode));
    }
    actual.contains(expected)
}

fn string_matches(actual: &str, expected: &str, match_mode: ArrayMatchMode) -> bool {
    match match_mode {
        ArrayMatchMode::Exact => actual == expected,
        ArrayMatchMode::Path => {
            actual == expected
                || actual.contains(expected)
                || (contains_glob_meta(expected) && globish_matches(expected, actual))
        }
    }
}

fn contains_glob_meta(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

fn globish_matches(pattern: &str, actual: &str) -> bool {
    let pattern = pattern.as_bytes();
    let actual = actual.as_bytes();
    let mut matched = vec![vec![false; actual.len() + 1]; pattern.len() + 1];
    matched[0][0] = true;
    for pidx in 1..=pattern.len() {
        if pattern[pidx - 1] == b'*' {
            matched[pidx][0] = matched[pidx - 1][0];
        }
    }
    for pidx in 1..=pattern.len() {
        for aidx in 1..=actual.len() {
            matched[pidx][aidx] = match pattern[pidx - 1] {
                b'*' => matched[pidx - 1][aidx] || matched[pidx][aidx - 1],
                b'?' => matched[pidx - 1][aidx - 1],
                byte => matched[pidx - 1][aidx - 1] && byte == actual[aidx - 1],
            };
        }
    }
    matched[pattern.len()][actual.len()]
}
