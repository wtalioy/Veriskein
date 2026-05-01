use std::path::PathBuf;

use veriskein_proto::{OwnedEvent, OwnedProcExecEvent, parse_arg_vector};

pub fn enrich_event_from_procfs(event: &mut OwnedEvent) {
    if let OwnedEvent::ProcExec(exec) = event {
        let pid = exec.header.pid;
        if let Some(snapshot) = ProcfsExecSnapshot::read(pid) {
            apply_procfs_snapshot(exec, snapshot);
        }
    }
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
    if !snapshot.exe_path.is_empty() {
        exec.filename = snapshot.exe_path;
    }
    if !snapshot.argv.is_empty() {
        exec.argv = snapshot.argv;
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use veriskein_proto::{EventHeader, parse_arg_vector};

    use super::{ProcfsExecSnapshot, apply_procfs_snapshot};

    #[test]
    fn proc_cmdline_parser_splits_nul_bytes() {
        let argv = parse_arg_vector(b"bash\0-lc\0true\0");
        assert_eq!(argv, vec!["bash", "-lc", "true"]);
    }

    #[test]
    fn procfs_snapshot_applies_real_exec_details() {
        let mut event = veriskein_proto::OwnedProcExecEvent {
            header: EventHeader::default(),
            filename: "bash".to_string(),
            argv: vec!["bash".to_string()],
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

    #[test]
    fn procfs_snapshot_reads_current_process() {
        let pid = std::process::id();
        let snapshot = ProcfsExecSnapshot::read(pid).expect("current process should exist");
        assert!(!snapshot.exe_path.is_empty());
        assert!(!snapshot.argv.is_empty());
        let current = env::current_exe().expect("current exe");
        assert!(
            snapshot.exe_path.ends_with(
                current
                    .file_name()
                    .expect("exe file")
                    .to_string_lossy()
                    .as_ref()
            )
        );
    }
}
