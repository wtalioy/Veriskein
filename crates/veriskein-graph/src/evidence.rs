use std::collections::BTreeSet;
use std::net::{IpAddr, ToSocketAddrs};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvEvidence {
    hits: Vec<String>,
}

impl EnvEvidence {
    pub fn new(hits: Vec<String>) -> Self {
        let mut hits = hits;
        hits.sort();
        hits.dedup();
        Self { hits }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn hits(&self) -> &[String] {
        &self.hits
    }

    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }
}

pub struct LlmEndpointResolver;

impl LlmEndpointResolver {
    pub fn resolve(endpoints: &[String]) -> BTreeSet<IpAddr> {
        let mut out = BTreeSet::new();
        for endpoint in endpoints {
            let endpoint = endpoint.trim();
            let endpoint = endpoint
                .strip_prefix("https://")
                .or_else(|| endpoint.strip_prefix("http://"))
                .unwrap_or(endpoint);
            let authority = endpoint.split('/').next().unwrap_or_default();
            if authority.is_empty() {
                continue;
            }
            if let Ok(ip) = authority.parse::<IpAddr>() {
                out.insert(ip);
                continue;
            }

            let socket_target = if authority.contains(':') {
                authority.to_string()
            } else {
                format!("{authority}:443")
            };
            if let Ok(addrs) = socket_target.to_socket_addrs() {
                out.extend(addrs.map(|addr| addr.ip()));
            }
        }
        out
    }
}
