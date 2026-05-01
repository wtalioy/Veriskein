//! Lightweight scenario assertion helpers.

use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct Expectation {
    #[serde(default)]
    pub negate: bool,
    #[serde(rename = "match")]
    pub match_: MatchSpec,
}

#[derive(Debug, Deserialize)]
pub struct MatchSpec {
    #[serde(rename = "type")]
    pub alert_type: String,
}

pub fn assert_expectations(expectations: &[Expectation], actual: &[Value]) -> Result<()> {
    for expectation in expectations {
        // Scenario expectations currently match only by alert type on purpose:
        // the fixtures describe behavior, not every incidental payload field.
        let found = actual
            .iter()
            .any(|value| value["type"] == expectation.match_.alert_type);
        if expectation.negate && found {
            bail!("unexpected alert type {}", expectation.match_.alert_type);
        }
        if !expectation.negate && !found {
            bail!("missing alert type {}", expectation.match_.alert_type);
        }
    }
    Ok(())
}
