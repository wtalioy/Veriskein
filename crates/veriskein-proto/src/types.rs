use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SessionId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AgentId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PromptId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtifactId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChainId([u8; 16]);

macro_rules! impl_id {
    ($name:ident) => {
        impl $name {
            pub fn from_seed(seed: &[u8]) -> Self {
                // Truncating blake3 keeps ids compact for schemas and logs while
                // still being deterministic across components.
                let digest = blake3::hash(seed);
                let mut bytes = [0_u8; 16];
                bytes.copy_from_slice(&digest.as_bytes()[..16]);
                Self(bytes)
            }

            pub fn hex(&self) -> String {
                let mut out = String::with_capacity(32);
                for byte in self.0 {
                    use core::fmt::Write as _;
                    let _ = write!(&mut out, "{byte:02x}");
                }
                out
            }
        }
    };
}

impl_id!(EventId);
impl_id!(SessionId);
impl_id!(AgentId);
impl_id!(PromptId);
impl_id!(ArtifactId);
impl_id!(ChainId);

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

    pub fn worst(self, other: Self) -> Self {
        use VisibilityState::{Full, Partial, Unavailable, Unsupported};
        match (self, other) {
            (Unavailable, _) | (_, Unavailable) => Unavailable,
            (Unsupported, _) | (_, Unsupported) => Unsupported,
            (Partial, _) | (_, Partial) => Partial,
            (Full, Full) => Full,
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
