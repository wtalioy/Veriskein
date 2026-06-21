use veriskein_graph::EnvEvidence;

pub(crate) fn env_evidence_for_pid(pid: u32, env_hints: &[String]) -> EnvEvidence {
    if env_hints.is_empty() {
        return EnvEvidence::empty();
    }
    let Ok(bytes) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return EnvEvidence::empty();
    };
    let entries = veriskein_proto::parse_arg_vector(&bytes[..bytes.len().min(8192)]);
    EnvEvidence::new(
        env_hints
            .iter()
            .filter(|hint| {
                entries
                    .iter()
                    .any(|entry| entry.starts_with(&format!("{hint}=")))
            })
            .cloned()
            .collect(),
    )
}
