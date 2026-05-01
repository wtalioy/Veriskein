use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use veriskein_proto::{
    EventHeader, EventKind, OwnedEvent, OwnedFdDupEvent, OwnedFileOpenEvent, OwnedFileRenameEvent,
    OwnedFileUnlinkEvent, OwnedNetConnectEvent, OwnedProcChdirEvent, OwnedProcExecEvent,
    OwnedProcExitEvent, OwnedProcForkEvent, parse_arg_vector, parse_c_string,
};

use crate::config::{SensitiveConfig, WorkspaceRef, lexical_clean};

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

#[derive(Debug, Clone)]
enum FdEntry {
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PathCacheKey {
    mount_ns: u64,
    basis: PathBuf,
    raw: String,
}

#[derive(Debug, Clone)]
struct ProcessState {
    pid: u32,
    tid: u32,
    ppid: u32,
    mount_ns: u64,
    exe: String,
    comm: String,
    argv: Vec<String>,
    cwd: PathBuf,
    fds: BTreeMap<i32, FdEntry>,
}

impl ProcessState {
    fn from_proc_root(proc_root: &Path, pid: u32) -> Option<Self> {
        let proc_dir = proc_root.join(pid.to_string());
        let cwd = std::fs::read_link(proc_dir.join("cwd")).ok()?;
        let exe = std::fs::read_link(proc_dir.join("exe"))
            .ok()
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let comm = std::fs::read(proc_dir.join("comm"))
            .ok()
            .map(|bytes| parse_c_string(&bytes).trim_end().to_string())
            .unwrap_or_default();
        let argv = std::fs::read(proc_dir.join("cmdline"))
            .ok()
            .map(|bytes| parse_arg_vector(&bytes))
            .unwrap_or_default();
        let ppid = std::fs::read_to_string(proc_dir.join("status"))
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("PPid:")
                        .and_then(|value| value.trim().parse::<u32>().ok())
                })
            })
            .unwrap_or(0);

        Some(Self {
            pid,
            tid: pid,
            ppid,
            mount_ns: mount_ns_of_proc(&proc_dir).unwrap_or(0),
            exe,
            comm,
            argv,
            cwd,
            fds: read_fd_entries(&proc_dir),
        })
    }
}

pub struct Normalizer {
    sensitive: SensitiveConfig,
    workspaces: Vec<WorkspaceRef>,
    processes: BTreeMap<u32, ProcessState>,
    path_cache: BTreeMap<PathCacheKey, PathResolution>,
}

impl Normalizer {
    pub fn new(sensitive: SensitiveConfig, workspaces: Vec<WorkspaceRef>) -> Self {
        let mut normalizer = Self {
            sensitive,
            workspaces,
            processes: BTreeMap::new(),
            path_cache: BTreeMap::new(),
        };
        // Bootstrapping procfs gives the daemon enough state to reason about
        // already-running agent roots before the first live event arrives.
        normalizer.bootstrap_procfs();
        normalizer
    }

    pub fn apply(&mut self, ingest_seq: u64, event: &OwnedEvent) -> Vec<NormalizedEvent> {
        match event {
            OwnedEvent::ProcFork(evt) => self.on_proc_fork(ingest_seq, evt),
            OwnedEvent::ProcExec(evt) => vec![self.on_proc_exec(ingest_seq, evt)],
            OwnedEvent::ProcExit(evt) => self.on_proc_exit(ingest_seq, evt),
            OwnedEvent::ProcChdir(evt) => self.on_proc_chdir(ingest_seq, evt),
            OwnedEvent::FdDup(evt) => self.on_fd_dup(ingest_seq, evt),
            OwnedEvent::FileOpen(evt) => self.on_file_open(ingest_seq, evt),
            OwnedEvent::FileUnlink(evt) => self.on_file_unlink(ingest_seq, evt),
            OwnedEvent::FileRename(evt) => self.on_file_rename(ingest_seq, evt),
            OwnedEvent::NetConnect(evt) => vec![self.on_net_connect(ingest_seq, evt)],
            OwnedEvent::MetaDrop(_) => Vec::new(),
        }
    }

    pub fn resolve_path(&mut self, pid: u32, dirfd: i32, raw: &str, ts_ns: u64) -> PathContext {
        let process = self.processes.get(&pid);
        let mount_ns = process.map(|proc| proc.mount_ns).unwrap_or(0);
        let base = self.lookup_base_path(process, dirfd);
        let lexical = self.lexical_from_base(&base, raw);
        let cache_key = PathCacheKey {
            mount_ns,
            basis: base.clone(),
            raw: raw.to_string(),
        };
        let resolution = if let Some(cached) = self.path_cache.get(&cache_key) {
            let mut cached = cached.clone();
            cached.freshness_ns = ts_ns;
            cached
        } else {
            // Path resolution is keyed by mount namespace plus lookup basis so
            // one process cannot poison another process's view through symlinks.
            let resolved = self.compute_resolution(&base, &lexical, ts_ns);
            self.path_cache.insert(cache_key, resolved.clone());
            resolved
        };
        self.path_context_from_resolution(resolution)
    }

    pub fn workspace_of(&self, path: &Path) -> Option<&WorkspaceRef> {
        self.workspaces.iter().find(|ws| path.starts_with(&ws.root))
    }

    pub fn workspaces(&self) -> &[WorkspaceRef] {
        &self.workspaces
    }

    fn lexical_from_base(&self, base: &Path, raw: &str) -> PathBuf {
        if raw.is_empty() {
            return lexical_clean(base);
        }
        if Path::new(raw).is_absolute() {
            return lexical_clean(Path::new(raw));
        }
        lexical_clean(&base.join(raw))
    }

    fn lookup_base_path(&self, process: Option<&ProcessState>, dirfd: i32) -> PathBuf {
        if dirfd == -100 {
            // AT_FDCWD semantics follow the process cwd snapshot we currently
            // own, not whatever cwd the task may change to later in procfs.
            return process
                .map(|proc| proc.cwd.clone())
                .unwrap_or_else(|| PathBuf::from("/"));
        }

        process
            .and_then(|proc| proc.fds.get(&dirfd))
            .map(|entry| match entry {
                FdEntry::File(path) => path.clone(),
            })
            .unwrap_or_else(|| PathBuf::from("/stale-dirfd"))
    }

    fn compute_resolution(&self, base: &Path, lexical: &Path, ts_ns: u64) -> PathResolution {
        // Canonicalization is reserved for cases where lexical paths are not
        // trustworthy enough for policy: sensitive paths, paths outside a
        // workspace, or dirfds we could not reconstruct.
        let needs_canonical = self.sensitive.matching_rule(lexical).is_some()
            || self.workspace_of(lexical).is_none()
            || base == Path::new("/stale-dirfd");
        let (canonical, mode, verdict) = if needs_canonical {
            match std::fs::canonicalize(lexical) {
                Ok(path) => {
                    let verdict = if path == lexical {
                        PathVerdict::CanonicalTrusted
                    } else {
                        PathVerdict::CanonicalMismatch
                    };
                    (Some(path), PathResolutionMode::Canonicalized, verdict)
                }
                Err(_) => (
                    None,
                    PathResolutionMode::Unresolved,
                    PathVerdict::UnresolvedSensitive,
                ),
            }
        } else {
            (
                None,
                PathResolutionMode::LexicalOnly,
                PathVerdict::LexicalTrusted,
            )
        };

        PathResolution {
            lexical: lexical.to_path_buf(),
            canonical,
            mode,
            verdict,
            freshness_ns: ts_ns,
        }
    }

    fn path_context_from_resolution(&self, resolution: PathResolution) -> PathContext {
        let preferred = resolution.canonical.as_ref().unwrap_or(&resolution.lexical);
        let sensitive = self.sensitive.matching_rule(preferred);
        PathContext {
            workspace: self.workspace_of(preferred).cloned(),
            sensitive_rule: sensitive.map(|rule| rule.glob.clone()),
            sensitive_severity: sensitive.map(|rule| rule.severity.clone()),
            resolution,
        }
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

    fn snapshot_for(&self, pid: u32, fallback_header: &EventHeader) -> ProcessSnapshot {
        if let Some(proc) = self.processes.get(&pid) {
            return ProcessSnapshot {
                pid: proc.pid,
                tid: proc.tid,
                ppid: proc.ppid,
                exe: proc.exe.clone(),
                comm: proc.comm.clone(),
                argv: proc.argv.clone(),
                cwd: proc.cwd.clone(),
            };
        }

        ProcessSnapshot {
            pid: fallback_header.pid,
            tid: fallback_header.tid,
            ppid: fallback_header.ppid,
            exe: String::new(),
            comm: parse_c_string(&fallback_header.comm),
            argv: Vec::new(),
            cwd: self
                .workspaces
                .first()
                .map(|workspace| workspace.root.clone())
                .unwrap_or_else(|| PathBuf::from("/")),
        }
    }

    fn on_proc_fork(&mut self, ingest_seq: u64, evt: &OwnedProcForkEvent) -> Vec<NormalizedEvent> {
        let parent_pid = evt.header.pid;
        let child = self
            .processes
            .get(&parent_pid)
            .cloned()
            .unwrap_or(ProcessState {
                pid: evt.child_pid,
                tid: evt.child_tid,
                ppid: parent_pid,
                mount_ns: evt.header.mount_ns,
                exe: String::new(),
                comm: String::new(),
                argv: Vec::new(),
                cwd: PathBuf::from("/"),
                fds: BTreeMap::new(),
            });
        self.processes.insert(
            evt.child_pid,
            ProcessState {
                pid: evt.child_pid,
                tid: evt.child_tid,
                ppid: parent_pid,
                mount_ns: child.mount_ns,
                exe: child.exe,
                comm: child.comm,
                argv: child.argv,
                cwd: child.cwd,
                fds: child.fds,
            },
        );
        vec![self.normalized_event(
            ingest_seq,
            EventKind::ProcFork,
            self.snapshot_for(parent_pid, &evt.header),
            OwnedEvent::ProcFork(evt.clone()).event_id().hex(),
            evt.header.ts_ns,
            NormalizedData::ProcFork {
                child_pid: evt.child_pid,
                child_tid: evt.child_tid,
            },
        )]
    }

    fn on_proc_exec(&mut self, ingest_seq: u64, evt: &OwnedProcExecEvent) -> NormalizedEvent {
        let pid = evt.header.pid;
        let prior = self.processes.get(&pid).cloned();
        let cwd = prior
            .as_ref()
            .map(|proc| proc.cwd.clone())
            .or_else(|| {
                self.workspaces
                    .first()
                    .map(|workspace| workspace.root.clone())
            })
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));

        self.processes.insert(
            pid,
            ProcessState {
                pid,
                tid: evt.header.tid,
                ppid: evt.header.ppid,
                mount_ns: evt.header.mount_ns,
                exe: evt.filename.clone(),
                comm: parse_c_string(&evt.header.comm),
                argv: evt.argv.clone(),
                cwd,
                fds: prior.map(|proc| proc.fds).unwrap_or_default(),
            },
        );

        self.normalized_event(
            ingest_seq,
            EventKind::ProcExec,
            self.snapshot_for(pid, &evt.header),
            OwnedEvent::ProcExec(evt.clone()).event_id().hex(),
            evt.header.ts_ns,
            NormalizedData::ProcExec {
                filename: evt.filename.clone(),
                argv: evt.argv.clone(),
            },
        )
    }

    fn on_proc_exit(&mut self, ingest_seq: u64, evt: &OwnedProcExitEvent) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let snapshot = self.snapshot_for(pid, &evt.header);
        self.processes.remove(&pid);
        vec![self.normalized_event(
            ingest_seq,
            EventKind::ProcExit,
            snapshot,
            OwnedEvent::ProcExit(evt.clone()).event_id().hex(),
            evt.header.ts_ns,
            NormalizedData::ProcExit {
                exit_code: evt.exit_code,
            },
        )]
    }

    fn on_proc_chdir(
        &mut self,
        ingest_seq: u64,
        evt: &OwnedProcChdirEvent,
    ) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let resolved = self.resolve_path(pid, evt.dirfd, &evt.path, evt.header.ts_ns);
        if let Some(proc) = self.processes.get_mut(&pid) {
            proc.cwd = resolved
                .resolution
                .canonical
                .clone()
                .unwrap_or_else(|| resolved.resolution.lexical.clone());
        }
        vec![self.normalized_event(
            ingest_seq,
            EventKind::ProcChdir,
            self.snapshot_for(pid, &evt.header),
            OwnedEvent::ProcChdir(evt.clone()).event_id().hex(),
            evt.header.ts_ns,
            NormalizedData::ProcChdir { path: resolved },
        )]
    }

    fn on_fd_dup(&mut self, ingest_seq: u64, evt: &OwnedFdDupEvent) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        if let Some(proc) = self.processes.get_mut(&pid) {
            if evt.oldfd == -1 {
                if evt.dup_ret == 0 {
                    proc.fds.remove(&evt.newfd);
                }
            } else if evt.dup_ret >= 0 {
                if let Some(entry) = proc.fds.get(&evt.oldfd).cloned() {
                    proc.fds.insert(evt.newfd, entry);
                }
            } else if evt.newfd >= 0 {
                proc.fds.remove(&evt.newfd);
            }
        }
        vec![self.normalized_event(
            ingest_seq,
            EventKind::FdDup,
            self.snapshot_for(pid, &evt.header),
            OwnedEvent::FdDup(evt.clone()).event_id().hex(),
            evt.header.ts_ns,
            NormalizedData::FdDup {
                oldfd: evt.oldfd,
                newfd: evt.newfd,
                dup_ret: evt.dup_ret,
            },
        )]
    }

    fn on_file_open(&mut self, ingest_seq: u64, evt: &OwnedFileOpenEvent) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let resolved = self.resolve_path(pid, evt.dirfd, &evt.path, evt.header.ts_ns);
        if evt.ret_fd >= 0 {
            if let Some(proc) = self.processes.get_mut(&pid) {
                let stored = resolved
                    .resolution
                    .canonical
                    .clone()
                    .unwrap_or_else(|| resolved.resolution.lexical.clone());
                proc.fds.insert(evt.ret_fd, FdEntry::File(stored));
            }
        }
        vec![self.normalized_event(
            ingest_seq,
            EventKind::FileOpen,
            self.snapshot_for(pid, &evt.header),
            OwnedEvent::FileOpen(evt.clone()).event_id().hex(),
            evt.header.ts_ns,
            NormalizedData::FileOpen {
                ret_fd: evt.ret_fd,
                path: resolved,
            },
        )]
    }

    fn on_file_unlink(
        &mut self,
        ingest_seq: u64,
        evt: &OwnedFileUnlinkEvent,
    ) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let resolved = self.resolve_path(pid, evt.dirfd, &evt.path, evt.header.ts_ns);
        vec![self.normalized_event(
            ingest_seq,
            EventKind::FileUnlink,
            self.snapshot_for(pid, &evt.header),
            OwnedEvent::FileUnlink(evt.clone()).event_id().hex(),
            evt.header.ts_ns,
            NormalizedData::FileUnlink {
                unlink_ret: evt.unlink_ret,
                path: resolved,
            },
        )]
    }

    fn on_file_rename(
        &mut self,
        ingest_seq: u64,
        evt: &OwnedFileRenameEvent,
    ) -> Vec<NormalizedEvent> {
        let pid = evt.header.pid;
        let old_path = self.resolve_path(pid, evt.olddirfd, &evt.old_path, evt.header.ts_ns);
        let new_path = self.resolve_path(pid, evt.newdirfd, &evt.new_path, evt.header.ts_ns);
        vec![self.normalized_event(
            ingest_seq,
            EventKind::FileRename,
            self.snapshot_for(pid, &evt.header),
            OwnedEvent::FileRename(evt.clone()).event_id().hex(),
            evt.header.ts_ns,
            NormalizedData::FileRename {
                rename_ret: evt.rename_ret,
                old_path,
                new_path,
            },
        )]
    }

    fn on_net_connect(&mut self, ingest_seq: u64, evt: &OwnedNetConnectEvent) -> NormalizedEvent {
        let pid = evt.header.pid;
        self.normalized_event(
            ingest_seq,
            EventKind::NetConnect,
            self.snapshot_for(pid, &evt.header),
            OwnedEvent::NetConnect(evt.clone()).event_id().hex(),
            evt.header.ts_ns,
            NormalizedData::NetConnect {
                sockfd: evt.sockfd,
                dport_be: evt.dport_be,
                tls_candidate: evt.tls_candidate,
            },
        )
    }

    fn normalized_event(
        &self,
        ingest_seq: u64,
        kind: EventKind,
        process: ProcessSnapshot,
        event_id: String,
        ts_ns: u64,
        data: NormalizedData,
    ) -> NormalizedEvent {
        NormalizedEvent {
            ingest_seq,
            event_id,
            ts_ns,
            kind,
            process,
            data,
        }
    }
}

fn mount_ns_of_proc(proc_dir: &Path) -> Option<u64> {
    let target = std::fs::read_link(proc_dir.join("ns/mnt")).ok()?;
    let text = target.to_string_lossy();
    let start = text.find('[')? + 1;
    let end = text[start..].find(']')? + start;
    text[start..end].parse::<u64>().ok()
}

fn read_fd_entries(proc_dir: &Path) -> BTreeMap<i32, FdEntry> {
    let mut fds = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(proc_dir.join("fd")) else {
        return fds;
    };

    for entry in entries.flatten() {
        let Some(fd) = entry.file_name().to_string_lossy().parse::<i32>().ok() else {
            continue;
        };
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        fds.insert(fd, FdEntry::File(target));
    }

    fds
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use veriskein_proto::{
        OwnedEvent, build_exec_event_bytes, build_fd_dup_event_bytes, build_file_open_event_bytes,
        build_file_rename_event_bytes, build_file_unlink_event_bytes, build_proc_chdir_event_bytes,
    };

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

    #[test]
    fn resolves_at_fdcwd_path() {
        let mut norm = normalizer();
        norm.apply(
            1,
            &parse_owned(build_exec_event_bytes(
                0,
                1,
                100,
                100,
                1,
                "claude",
                "/usr/bin/claude",
                &["claude"],
            )),
        );
        norm.apply(
            2,
            &parse_owned(build_proc_chdir_event_bytes(
                0,
                2,
                100,
                100,
                1,
                "claude",
                "/tmp/veriskein-ws/subdir",
            )),
        );
        let events = norm.apply(
            3,
            &parse_owned(build_file_open_event_bytes(
                0, 3, 100, 100, 1, "claude", -100, 3, "file.txt",
            )),
        );
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
        norm.apply(
            1,
            &parse_owned(build_exec_event_bytes(
                0,
                1,
                101,
                101,
                1,
                "claude",
                "/usr/bin/claude",
                &["claude"],
            )),
        );
        let events = norm.apply(
            2,
            &parse_owned(build_file_open_event_bytes(
                0,
                2,
                101,
                101,
                1,
                "claude",
                -100,
                3,
                "/etc/shadow",
            )),
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
        norm.apply(
            1,
            &parse_owned(build_exec_event_bytes(
                0,
                1,
                102,
                102,
                1,
                "claude",
                "/usr/bin/claude",
                &["claude"],
            )),
        );
        let events = norm.apply(
            2,
            &parse_owned(build_file_open_event_bytes(
                0, 2, 102, 102, 1, "claude", 99, 3, "file.txt",
            )),
        );
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
        norm.apply(
            1,
            &parse_owned(build_exec_event_bytes(
                0,
                1,
                103,
                103,
                1,
                "claude",
                "/usr/bin/claude",
                &["claude"],
            )),
        );
        let workspace = PathBuf::from("/tmp/veriskein-ws/dir");
        fs::create_dir_all(&workspace).expect("workspace dir");
        let open_events = norm.apply(
            2,
            &parse_owned(build_file_open_event_bytes(
                0,
                2,
                103,
                103,
                1,
                "claude",
                -100,
                7,
                workspace.to_string_lossy().as_ref(),
            )),
        );
        assert!(matches!(
            open_events[0].data,
            NormalizedData::FileOpen { .. }
        ));
        let mut chdir = parse_owned(build_proc_chdir_event_bytes(
            0, 3, 103, 103, 1, "claude", "",
        ));
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
        norm.apply(
            1,
            &parse_owned(build_exec_event_bytes(
                0,
                1,
                104,
                104,
                1,
                "claude",
                "/usr/bin/claude",
                &["claude"],
            )),
        );
        norm.apply(
            2,
            &parse_owned(build_file_open_event_bytes(
                0,
                2,
                104,
                104,
                1,
                "claude",
                -100,
                9,
                "/tmp/veriskein-ws/file.txt",
            )),
        );
        norm.apply(
            3,
            &parse_owned(build_fd_dup_event_bytes(
                0, 3, 104, 104, 1, "claude", -1, 9, 0,
            )),
        );
        let events = norm.apply(
            4,
            &parse_owned(build_file_open_event_bytes(
                0,
                4,
                104,
                104,
                1,
                "claude",
                9,
                10,
                "child.txt",
            )),
        );
        match &events[0].data {
            NormalizedData::FileOpen { path, .. } => {
                assert!(path.resolution.lexical.starts_with("/stale-dirfd"));
            }
            _ => panic!("expected file open"),
        }
    }

    #[test]
    fn rename_resolves_old_and_new_paths() {
        let mut norm = normalizer();
        norm.apply(
            1,
            &parse_owned(build_exec_event_bytes(
                0,
                1,
                105,
                105,
                1,
                "claude",
                "/usr/bin/claude",
                &["claude"],
            )),
        );
        let events = norm.apply(
            2,
            &parse_owned(build_file_rename_event_bytes(
                0,
                2,
                105,
                105,
                1,
                "claude",
                -100,
                -100,
                0,
                "old.txt",
                "../new.txt",
            )),
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
        norm.apply(
            1,
            &parse_owned(build_exec_event_bytes(
                0,
                1,
                106,
                106,
                1,
                "claude",
                "/usr/bin/claude",
                &["claude"],
            )),
        );
        let events = norm.apply(
            2,
            &parse_owned(build_file_unlink_event_bytes(
                0,
                2,
                106,
                106,
                1,
                "claude",
                -100,
                0,
                "/tmp/outside.txt",
            )),
        );
        match &events[0].data {
            NormalizedData::FileUnlink { path, .. } => assert!(path.workspace.is_none()),
            _ => panic!("expected unlink"),
        }
    }
}
