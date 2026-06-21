//! Lightweight scenario assertion helpers.

mod assertion;

pub use assertion::{Expectation, MatchSpec, assert_expectations};

#[cfg(test)]
mod tests;
