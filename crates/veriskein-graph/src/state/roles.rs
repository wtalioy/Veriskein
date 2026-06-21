use veriskein_normalizer::NormalizedEvent;
use veriskein_proto::Role;

use super::{Attribution, GraphState, basename};

impl GraphState {
    pub(super) fn apply_role(
        &self,
        attribution: &mut Attribution,
        event: &NormalizedEvent,
        filename: &str,
    ) {
        let next = self.classify_role(attribution, event, filename);
        if role_rank(next) > role_rank(attribution.role) {
            attribution.role = next;
            attribution.role_version += 1;
        }
    }

    fn classify_role(
        &self,
        attribution: &Attribution,
        event: &NormalizedEvent,
        filename: &str,
    ) -> Role {
        if event.process.pid == attribution.root_pid {
            return Role::RootAgent;
        }
        let name = basename(filename);
        if matches!(name, "sh" | "bash" | "zsh" | "dash" | "fish")
            && self
                .resolve(event.process.ppid)
                .is_some_and(|parent| parent.role == Role::RootAgent)
        {
            return Role::ShellTool;
        }
        if matches!(
            name,
            "python"
                | "python3"
                | "node"
                | "ruby"
                | "go"
                | "cargo"
                | "rustc"
                | "gcc"
                | "clang"
                | "make"
                | "npm"
                | "pip"
        ) {
            return Role::ToolWorker;
        }
        if self
            .resolve(event.process.ppid)
            .is_some_and(|parent| parent.role == Role::RootAgent)
        {
            return Role::SubAgent;
        }
        Role::Unknown
    }
}

fn role_rank(role: Role) -> u8 {
    match role {
        Role::Unknown => 0,
        Role::SubAgent => 1,
        Role::ToolWorker => 2,
        Role::ShellTool => 3,
        Role::McpServer => 4,
        Role::RootAgent => 5,
    }
}
