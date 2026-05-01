use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainId([u8; 16]);

macro_rules! impl_id {
    ($name:ident) => {
        impl $name {
            pub fn from_seed(seed: &[u8]) -> Self {
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

#[cfg(test)]
mod tests {
    use super::EventId;

    #[test]
    fn id_generation_is_stable() {
        let left = EventId::from_seed(b"same");
        let right = EventId::from_seed(b"same");
        assert_eq!(left, right);
        assert_eq!(left.hex().len(), 32);
    }
}
