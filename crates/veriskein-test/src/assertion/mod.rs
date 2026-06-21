use anyhow::{Result, bail};
use serde_json::Value;

mod matchers;
mod parse;
mod report;
mod spec;

pub use spec::{Expectation, MatchSpec};

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
                    report::describe_alert(value)
                );
            }
        } else if found.is_none() {
            bail!(
                "missing expected alert: {}; checked {}; closest mismatches: {}",
                expectation.match_,
                report::describe_actual(actual),
                report::describe_mismatches(&expectation.match_, actual)
            );
        }
    }
    Ok(())
}
