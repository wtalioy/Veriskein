use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VisibilityState {
    Full,
    Partial,
    Unsupported,
    Unavailable,
}

impl VisibilityState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionStrength {
    Strong,
    Medium,
    Weak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    RootAgent,
    SubAgent,
    ShellTool,
    ToolWorker,
    McpServer,
    Unknown,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootAgent => "root_agent",
            Self::SubAgent => "sub_agent",
            Self::ShellTool => "shell_tool",
            Self::ToolWorker => "tool_worker",
            Self::McpServer => "mcp_server",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoleTag {
    McpVisible,
    ShellLike,
    ToolLike,
}
