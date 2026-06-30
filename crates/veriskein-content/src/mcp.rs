use std::collections::BTreeMap;

use serde_json::Value;
use veriskein_retention::BoundedMap;

const MAX_MCP_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_MCP_BUFFERS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolRegistration {
    pub server_id: String,
    pub tool_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolSpoofing {
    pub tool_name: String,
    pub claimed_server: String,
    pub registered_server: String,
    pub reason: String,
}

#[derive(Debug)]
pub struct McpRegistry {
    owners_by_tool: BTreeMap<String, McpToolRegistration>,
    pending_by_stream: BoundedMap<(String, u64), Vec<u8>>,
}

impl Default for McpRegistry {
    fn default() -> Self {
        Self {
            owners_by_tool: BTreeMap::new(),
            pending_by_stream: BoundedMap::new(MAX_MCP_BUFFERS),
        }
    }
}

impl McpRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_jsonrpc(
        &mut self,
        server_id: impl Into<String>,
        payload: &[u8],
    ) -> Vec<McpToolSpoofing> {
        let server_id = server_id.into();
        let Ok(value) = serde_json::from_slice::<Value>(payload) else {
            return Vec::new();
        };
        self.observe_tools(server_id, tool_names_from_value(&value))
    }

    pub fn observe_jsonrpc_fragment(
        &mut self,
        server_id: impl Into<String>,
        stream_id: u64,
        payload: &[u8],
    ) -> Vec<McpToolSpoofing> {
        let server_id = server_id.into();
        let key = (server_id.clone(), stream_id);
        let mut buffered = self.pending_by_stream.remove(&key).unwrap_or_default();
        buffered.extend_from_slice(payload);
        if buffered.len() > MAX_MCP_MESSAGE_BYTES {
            return Vec::new();
        }
        match serde_json::from_slice::<Value>(&buffered) {
            Ok(value) => self.observe_tools(server_id, tool_names_from_value(&value)),
            Err(_) => {
                self.pending_by_stream.insert(key, buffered);
                Vec::new()
            }
        }
    }

    pub fn observe_tools(
        &mut self,
        server_id: impl Into<String>,
        tool_names: impl IntoIterator<Item = String>,
    ) -> Vec<McpToolSpoofing> {
        let server_id = server_id.into();
        let mut anomalies = Vec::new();
        for tool_name in tool_names {
            let key = canonical_tool_name(&tool_name);
            if key.is_empty() {
                continue;
            }
            match self.owners_by_tool.get(&key) {
                Some(owner) if owner.server_id != server_id => {
                    anomalies.push(McpToolSpoofing {
                        tool_name,
                        claimed_server: server_id.clone(),
                        registered_server: owner.server_id.clone(),
                        reason: "mcp_tool_name_collision".to_string(),
                    });
                }
                Some(_) => {}
                None => {
                    self.owners_by_tool.insert(
                        key,
                        McpToolRegistration {
                            server_id: server_id.clone(),
                            tool_name,
                        },
                    );
                }
            }
        }
        anomalies
    }
}

fn tool_names_from_value(value: &Value) -> Vec<String> {
    value
        .get("result")
        .or(Some(value))
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn canonical_tool_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::McpRegistry;

    #[test]
    fn jsonrpc_tools_list_claims_first_owner() {
        let mut registry = McpRegistry::new();
        let anomalies = registry.observe_jsonrpc(
            "filesystem",
            br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"}]}}"#,
        );

        assert!(anomalies.is_empty());
    }

    #[test]
    fn duplicate_tool_name_from_different_server_is_spoofing() {
        let mut registry = McpRegistry::new();
        assert!(
            registry
                .observe_tools("filesystem", ["read_file".to_string()])
                .is_empty()
        );

        let anomalies = registry.observe_tools("browser", ["READ_FILE".to_string()]);

        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].claimed_server, "browser");
        assert_eq!(anomalies[0].registered_server, "filesystem");
        assert_eq!(anomalies[0].reason, "mcp_tool_name_collision");
    }

    #[test]
    fn split_jsonrpc_tools_list_is_reassembled_by_stream() {
        let mut registry = McpRegistry::new();
        assert!(
            registry
                .observe_jsonrpc_fragment(
                    "filesystem",
                    1,
                    br#"{"jsonrpc":"2.0","result":{"tools":["#
                )
                .is_empty()
        );
        assert!(
            registry
                .observe_jsonrpc_fragment("filesystem", 1, br#"{"name":"read_file"}]}}"#)
                .is_empty()
        );

        let anomalies =
            registry.observe_jsonrpc("browser", br#"{"result":{"tools":[{"name":"read_file"}]}}"#);

        assert_eq!(anomalies.len(), 1);
    }
}
