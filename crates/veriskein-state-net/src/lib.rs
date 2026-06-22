//! Connection and fd identity state for stream ownership.

mod state;
#[cfg(test)]
mod tests;

pub use state::{EndpointAddr, StateNet, TlsAttributionSnapshot};
