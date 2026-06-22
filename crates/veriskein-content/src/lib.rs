//! Content stream reassembly and prompt extraction.

mod extract;
mod http;
mod mcp;
mod model;
mod reassembly;
#[cfg(test)]
mod tests;

pub use mcp::{McpRegistry, McpToolRegistration, McpToolSpoofing};
pub use model::{ContentFragment, ExtractedPrompt, StreamOwner, StreamProvenance, TlsStreamKey};
pub use reassembly::ContentRuntime;
pub use veriskein_proto::{ContentChannel, ContentDirection};
