use std::path::PathBuf;

use veriskein_proto::{OwnedEvent, OwnedProcExecEvent};

pub fn enrich_event_from_procfs(event: &mut OwnedEvent) {
    if let OwnedEvent::ProcExec(exec) = event {
        if let Some(snapshot) = ProcfsExecSnapshot::read(exec.tgid) {
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
        let argv = parse_proc_cmdline(&argv_bytes);
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

fn parse_proc_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::env;

    use veriskein_proto::EventHeader;

    use super::{ProcfsExecSnapshot, apply_procfs_snapshot, parse_proc_cmdline};

    #[test]
    fn proc_cmdline_parser_splits_nul_bytes() {
        let argv = parse_proc_cmdline(b"bash\0-lc\0true\0");
        assert_eq!(argv, vec!["bash", "-lc", "true"]);
    }

    #[test]
    fn procfs_snapshot_applies_real_exec_details() {
        let mut event = veriskein_proto::OwnedProcExecEvent {
            header: EventHeader::default(),
            pid: 1,
            tgid: 1,
            ppid: 0,
            mount_ns: 0,
            comm: "bash".to_string(),
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
