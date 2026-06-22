use std::fmt;

use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

mod parse;

pub fn assert_expectations(expectations: &[Expectation], actual: &[Value]) -> Result<()> {
    for expectation in expectations {
        let found = actual
            .iter()
            .find(|value| expectation.match_.matches(value));
        if expectation.is_forbidden() {
            if let Some(value) = found {
                bail!(
                    "forbidden expectation matched: {}; matched alert {}",
                    expectation.match_,
                    describe_alert(value)
                );
            }
        } else if found.is_none() {
            bail!(
                "missing expected alert: {}; checked {}; closest mismatches: {}",
                expectation.match_,
                describe_actual(actual),
                describe_mismatches(&expectation.match_, actual)
            );
        }
    }
    Ok(())
}

fn get_path<'a, S>(value: &'a Value, path: &[S]) -> Option<&'a Value>
where
    S: AsRef<str>,
{
    path.iter()
        .try_fold(value, |current, key| current.get(key.as_ref()))
}

fn get_map_path<'a, S>(root: &'a Map<String, Value>, path: &[S]) -> Option<&'a Value>
where
    S: AsRef<str>,
{
    let (first, rest) = path.split_first()?;
    get_path(root.get(first.as_ref())?, rest)
}

#[derive(Debug, Deserialize)]
pub struct Expectation {
    #[serde(default)]
    pub negate: bool,
    #[serde(rename = "match")]
    pub match_: MatchSpec,
}

#[derive(Debug)]
pub struct MatchSpec {
    criteria: Vec<Criterion>,
}

#[derive(Debug)]
enum Criterion {
    Type(String),
    FieldIn {
        path: &'static [&'static str],
        label: &'static str,
        values: Vec<String>,
    },
    ArrayIncludes {
        path: &'static [&'static str],
        label: &'static str,
        values: Vec<Value>,
    },
    LengthGte {
        path: Vec<String>,
        label: String,
        min: usize,
    },
    EvidenceHasKind(String),
    EvidenceHasKinds(Vec<String>),
    Present {
        path: Vec<String>,
        label: String,
    },
    NumericGte {
        path: Vec<String>,
        label: String,
        min: f64,
    },
    NotContainsText(Vec<String>),
    SessionsDiffer,
}

impl Expectation {
    fn is_forbidden(&self) -> bool {
        self.negate
    }
}

impl MatchSpec {
    fn new(criteria: Vec<Criterion>) -> Self {
        Self { criteria }
    }

    pub(crate) fn matches(&self, actual: &Value) -> bool {
        self.criteria
            .iter()
            .all(|criterion| criterion.matches(actual))
    }

    fn mismatches(&self, actual: &Value) -> Vec<String> {
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
            Self::LengthGte { path, min, .. } => get_path(actual, path)
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
            Self::Present { path, .. } => get_path(actual, path).is_some_and(|value| {
                !value.is_null() && value.as_str().map(|text| !text.is_empty()).unwrap_or(true)
            }),
            Self::NumericGte { path, min, .. } => get_path(actual, path)
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
            Self::Present { label, .. } => write!(formatter, "{label} present"),
            Self::NumericGte { label, min, .. } => write!(formatter, "{label} >= {min}"),
            Self::NotContainsText(values) => write!(formatter, "not_contains_text {:?}", values),
            Self::SessionsDiffer => write!(
                formatter,
                "objects.root_session_id != objects.downstream_session_id"
            ),
        }
    }
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

fn describe_actual(actual: &[Value]) -> String {
    if actual.is_empty() {
        return "no alerts".to_string();
    }
    actual
        .iter()
        .map(describe_alert)
        .collect::<Vec<_>>()
        .join("; ")
}

fn describe_mismatches(spec: &MatchSpec, actual: &[Value]) -> String {
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

fn describe_alert(value: &Value) -> String {
    let alert_type = value["type"].as_str().unwrap_or("<missing type>");
    let severity = value["severity"].as_str().unwrap_or("<missing severity>");
    let confidence = value["confidence_band"]
        .as_str()
        .unwrap_or("<missing confidence_band>");
    format!("type={alert_type}, severity={severity}, confidence_band={confidence}")
}
