use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod apply;
mod path;
mod process;

use serde::Serialize;
use veriskein_proto::EventKind;

use crate::config::{SensitiveConfig, WorkspaceRef};
use path::PathCacheKey;
use process::ProcessState;

const MAX_PATH_CACHE_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PathResolutionMode {
    LexicalOnly,
    Canonicalized,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PathVerdict {
    LexicalTrusted,
    CanonicalTrusted,
    CanonicalMismatch,
    UnresolvedSensitive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathResolution {
    pub lexical: PathBuf,
    pub canonical: Option<PathBuf>,
    pub mode: PathResolutionMode,
    pub verdict: PathVerdict,
    pub freshness_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathContext {
    pub resolution: PathResolution,
    pub workspace: Option<WorkspaceRef>,
    pub sensitive_rule: Option<String>,
    pub sensitive_severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub exe: String,
    pub comm: String,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum NormalizedData {
    ProcFork {
        child_pid: u32,
        child_tid: u32,
    },
    ProcExec {
        filename: String,
        argv: Vec<String>,
    },
    ProcExit {
        exit_code: i32,
    },
    ProcChdir {
        path: PathContext,
    },
    FdDup {
        oldfd: i32,
        newfd: i32,
        dup_ret: i32,
    },
    FileOpen {
        ret_fd: i32,
        flags: u32,
        path: PathContext,
    },
    FileUnlink {
        unlink_ret: i32,
        path: PathContext,
    },
    FileRename {
        rename_ret: i32,
        old_path: PathContext,
        new_path: PathContext,
    },
    NetConnect {
        sockfd: i32,
        dport_be: u16,
        dst_ip: Option<String>,
        dst_port: Option<u16>,
        tls_candidate: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NormalizedEvent {
    pub ingest_seq: u64,
    pub event_id: String,
    pub ts_ns: u64,
    pub kind: EventKind,
    pub process: ProcessSnapshot,
    pub data: NormalizedData,
}

pub struct Normalizer {
    sensitive: SensitiveConfig,
    workspaces: Vec<WorkspaceRef>,
    processes: BTreeMap<u32, ProcessState>,
    expiring: BTreeMap<u32, ProcessState>,
    path_cache: BTreeMap<PathCacheKey, PathResolution>,
}

impl Normalizer {
    pub fn new(sensitive: SensitiveConfig, workspaces: Vec<WorkspaceRef>) -> Self {
        let mut normalizer = Self {
            sensitive,
            workspaces,
            processes: BTreeMap::new(),
            expiring: BTreeMap::new(),
            path_cache: BTreeMap::new(),
        };
        // Bootstrapping procfs gives the daemon enough state to reason about
        // already-running agent roots before the first live event arrives.
        normalizer.bootstrap_procfs();
        normalizer
    }

    pub fn workspaces(&self) -> &[WorkspaceRef] {
        &self.workspaces
    }

    pub fn process_snapshots(&self) -> Vec<ProcessSnapshot> {
        self.processes
            .values()
            .map(ProcessState::snapshot)
            .collect()
    }

    fn bootstrap_procfs(&mut self) {
        self.bootstrap_procfs_from(Path::new("/proc"));
    }

    fn bootstrap_procfs_from(&mut self, proc_root: &Path) {
        let Ok(proc_dir) = std::fs::read_dir(proc_root) else {
            return;
        };
        // Procfs is sampled opportunistically here; failures are expected for
        // racing exits and should not block daemon startup.
        for entry in proc_dir.flatten() {
            let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
                continue;
            };
            if let Some(state) = ProcessState::from_proc_root(proc_root, pid) {
                self.processes.insert(pid, state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use veriskein_proto::{EventFixture, OwnedEvent};

    use crate::config::{SensitiveConfig, load_workspaces};

    use super::{NormalizedData, Normalizer, PathResolutionMode, PathVerdict};

    fn normalizer() -> Normalizer {
        let sensitive = SensitiveConfig::from_toml_str(
            r#"
[[rule]]
glob = "/etc/shadow"
severity = "high"
"#,
        )
        .expect("config");
        let workspaces = load_workspaces(&[PathBuf::from("/tmp/veriskein-ws")]).expect("ws");
        Normalizer::new(sensitive, workspaces)
    }

    fn parse_owned(bytes: Vec<u8>) -> OwnedEvent {
        veriskein_proto::parse(&bytes).expect("parse").to_owned()
    }

    fn fixture(seq: u64, pid: u32) -> EventFixture {
        EventFixture::for_pid(seq, pid, 1, "claude")
    }

    fn exec(seq: u64, pid: u32) -> OwnedEvent {
        parse_owned(fixture(seq, pid).exec("/usr/bin/claude", &["claude"]))
    }

    #[test]
    fn resolves_at_fdcwd_path() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 100));
        norm.apply(
            2,
            &parse_owned(fixture(2, 100).chdir("/tmp/veriskein-ws/subdir")),
        );
        let events = norm.apply(3, &parse_owned(fixture(3, 100).open(-100, 3, "file.txt")));
        match &events[0].data {
            NormalizedData::FileOpen { path, .. } => {
                assert_eq!(path.resolution.mode, PathResolutionMode::LexicalOnly);
                assert!(
                    path.resolution
                        .lexical
                        .ends_with(Path::new("/tmp/veriskein-ws/subdir/file.txt"))
                );
            }
            _ => panic!("expected file open"),
        }
    }

    #[test]
    fn sensitive_match_sets_context() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 101));
        let events = norm.apply(
            2,
            &parse_owned(fixture(2, 101).open(-100, 3, "/etc/shadow")),
        );
        match &events[0].data {
            NormalizedData::FileOpen { path, .. } => {
                assert_eq!(path.sensitive_severity.as_deref(), Some("high"));
                assert!(matches!(
                    path.resolution.verdict,
                    PathVerdict::CanonicalTrusted | PathVerdict::CanonicalMismatch
                ));
            }
            _ => panic!("expected open"),
        }
    }

    #[test]
    fn stale_dirfd_falls_back_to_unresolved_path() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 102));
        let events = norm.apply(2, &parse_owned(fixture(2, 102).open(99, 3, "file.txt")));
        match &events[0].data {
            NormalizedData::FileOpen { path, .. } => {
                assert!(path.resolution.lexical.starts_with("/stale-dirfd"));
                assert_eq!(path.resolution.mode, PathResolutionMode::Unresolved);
            }
            _ => panic!("expected open"),
        }
    }

    #[test]
    fn fchdir_uses_fd_state() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 103));
        let workspace = PathBuf::from("/tmp/veriskein-ws/dir");
        fs::create_dir_all(&workspace).expect("workspace dir");
        let open_events = norm.apply(
            2,
            &parse_owned(fixture(2, 103).open(-100, 7, workspace.to_string_lossy().as_ref())),
        );
        assert!(matches!(
            open_events[0].data,
            NormalizedData::FileOpen { .. }
        ));
        let mut chdir = parse_owned(fixture(3, 103).chdir(""));
        if let OwnedEvent::ProcChdir(ref mut evt) = chdir {
            evt.dirfd = 7;
        }
        let events = norm.apply(3, &chdir);
        match &events[0].data {
            NormalizedData::ProcChdir { path } => {
                assert!(path.resolution.lexical.ends_with("veriskein-ws/dir"));
            }
            _ => panic!("expected chdir"),
        }
    }

    #[test]
    fn close_removes_fd_state() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 104));
        norm.apply(
            2,
            &parse_owned(fixture(2, 104).open(-100, 9, "/tmp/veriskein-ws/file.txt")),
        );
        norm.apply(3, &parse_owned(fixture(3, 104).dup(-1, 9, 0)));
        let events = norm.apply(4, &parse_owned(fixture(4, 104).open(9, 10, "child.txt")));
        match &events[0].data {
            NormalizedData::FileOpen { path, .. } => {
                assert!(path.resolution.lexical.starts_with("/stale-dirfd"));
            }
            _ => panic!("expected file open"),
        }
    }

    #[test]
    fn file_open_flags_flow_into_normalized_event() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 107));
        let events = norm.apply(
            2,
            &parse_owned(fixture(2, 107).open_with_flags(
                -100,
                3,
                "/tmp/veriskein-ws/progress.txt",
                64,
            )),
        );
        match &events[0].data {
            NormalizedData::FileOpen { flags, .. } => assert_eq!(*flags, 64),
            _ => panic!("expected file open"),
        }
    }

    #[test]
    fn exit_keeps_process_snapshot_for_late_events() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 108));
        norm.apply(2, &parse_owned(fixture(2, 108).exit(0)));
        let events = norm.apply(
            3,
            &parse_owned(fixture(3, 108).open(-100, 3, "/tmp/veriskein-ws/late.txt")),
        );
        assert_eq!(events[0].process.exe, "/usr/bin/claude");
    }

    #[test]
    fn process_snapshots_expose_bootstrap_and_live_state() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 118));

        let snapshots = norm.process_snapshots();
        assert!(
            snapshots
                .iter()
                .any(|snapshot| snapshot.pid == 118 && snapshot.exe == "/usr/bin/claude")
        );
    }

    #[test]
    fn forked_fd_table_mutation_is_copy_on_write() {
        let mut norm = normalizer();
        let dir = PathBuf::from("/tmp/veriskein-ws/cow-dir");
        fs::create_dir_all(&dir).expect("cow dir");
        norm.apply(1, &exec(1, 109));
        norm.apply(
            2,
            &parse_owned(fixture(2, 109).open(-100, 9, dir.to_string_lossy().as_ref())),
        );
        norm.apply(3, &parse_owned(fixture(3, 109).fork(110, 110)));
        norm.apply(
            4,
            &parse_owned(EventFixture::for_pid(4, 110, 109, "claude").dup(-1, 9, 0)),
        );
        let events = norm.apply(5, &parse_owned(fixture(5, 109).open(9, 10, "child.txt")));
        match &events[0].data {
            NormalizedData::FileOpen { path, .. } => {
                assert!(path.resolution.lexical.ends_with("cow-dir/child.txt"));
            }
            _ => panic!("expected file open"),
        }
    }

    #[test]
    fn rename_resolves_old_and_new_paths() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 105));
        let events = norm.apply(
            2,
            &parse_owned(fixture(2, 105).rename(-100, -100, 0, "old.txt", "../new.txt")),
        );
        match &events[0].data {
            NormalizedData::FileRename {
                old_path, new_path, ..
            } => {
                assert!(old_path.resolution.lexical.ends_with("old.txt"));
                assert!(new_path.resolution.lexical.ends_with("new.txt"));
            }
            _ => panic!("expected rename"),
        }
    }

    #[test]
    fn workspace_of_distinguishes_inside_and_outside() {
        let mut norm = normalizer();
        norm.apply(1, &exec(1, 106));
        let events = norm.apply(
            2,
            &parse_owned(fixture(2, 106).unlink(-100, 0, "/tmp/outside.txt")),
        );
        match &events[0].data {
            NormalizedData::FileUnlink { path, .. } => assert!(path.workspace.is_none()),
            _ => panic!("expected unlink"),
        }
    }
}
