use std::path::PathBuf;

use veriskein_graph::EnvEvidence;
use veriskein_proto::{OwnedEvent, OwnedProcExecEvent, parse_arg_vector};

const PROCFS_ENVIRON_READ_MAX: usize = 8192;

pub(crate) fn enrich_event_from_procfs(event: &mut OwnedEvent) {
    if let OwnedEvent::ProcExec(exec) = event {
        let pid = exec.header.pid;
        if let Some(snapshot) = ProcfsExecSnapshot::read(pid) {
            apply_procfs_snapshot(exec, snapshot);
        }
    }
}

pub(crate) fn env_evidence_for_pid(pid: u32, env_hints: &[String]) -> EnvEvidence {
    if env_hints.is_empty() {
        return EnvEvidence::empty();
    }
    let Ok(bytes) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return EnvEvidence::empty();
    };
    let entries = parse_arg_vector(&bytes[..bytes.len().min(PROCFS_ENVIRON_READ_MAX)]);
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcfsExecSnapshot {
    exe_path: String,
    argv: Vec<String>,
}

impl ProcfsExecSnapshot {
    fn read(pid: u32) -> Option<Self> {
        let proc_root = PathBuf::from("/proc").join(pid.to_string());
        // Best-effort enrichment only: if the process has already exited or procfs
        // visibility is limited, we keep the original event payload unchanged.
        let exe_path = std::fs::read_link(proc_root.join("exe"))
            .ok()
            .map(|path| path.display().to_string())?;
        let argv_bytes = std::fs::read(proc_root.join("cmdline")).ok()?;
        let argv = parse_arg_vector(&argv_bytes);
        Some(Self { exe_path, argv })
    }
}

fn apply_procfs_snapshot(exec: &mut OwnedProcExecEvent, snapshot: ProcfsExecSnapshot) {
    if exec.filename.is_empty() && !snapshot.exe_path.is_empty() {
        exec.filename = snapshot.exe_path;
    }
    if exec.argv.is_empty() && !snapshot.argv.is_empty() {
        exec.argv = snapshot.argv;
    }
}

#[cfg(test)]
mod tests {
    use veriskein_proto::EventHeader;

    use super::{ProcfsExecSnapshot, apply_procfs_snapshot};

    #[test]
    fn procfs_snapshot_applies_real_exec_details() {
        let mut event = veriskein_proto::OwnedProcExecEvent {
            header: EventHeader::default(),
            filename: String::new(),
            argv: Vec::new(),
        };
        apply_procfs_snapshot(
            &mut event,
            ProcfsExecSnapshot {
                exe_path: "/bin/bash".to_string(),
                argv: vec!["bash".to_string(), "-lc".to_string(), "true".to_string()],
            },
        );
        assert_eq!(event.filename, "/bin/bash");
        assert_eq!(event.argv[1], "-lc");
    }
}
