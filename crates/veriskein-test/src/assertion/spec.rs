use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct Expectation {
    #[serde(default)]
    pub negate: bool,
    #[serde(rename = "match")]
    pub match_: MatchSpec,
}

#[derive(Debug)]
pub struct MatchSpec {
    pub(super) criteria: Vec<Criterion>,
}

#[derive(Debug)]
pub(super) enum Criterion {
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
    pub(super) fn is_forbidden(&self) -> bool {
        self.negate
    }
}

impl MatchSpec {
    pub(super) fn new(criteria: Vec<Criterion>) -> Self {
        Self { criteria }
    }
}
