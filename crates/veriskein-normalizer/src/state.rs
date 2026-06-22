use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

mod apply;
mod path;
mod process;

use serde::Serialize;
use veriskein_proto::EventKind;
use veriskein_retention::BoundedMap;

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

impl PathContext {
    pub fn preferred_path(&self) -> &Path {
        self.resolution
            .canonical
            .as_deref()
            .unwrap_or(self.resolution.lexical.as_path())
    }

    pub fn preferred_path_string(&self) -> String {
        self.preferred_path().display().to_string()
    }
}

pub fn path_basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
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
    TlsAssoc {
        ssl_ctx: u64,
        fd: i32,
        assoc_ret: i32,
        direction: veriskein_proto::ContentDirection,
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
    process_order: VecDeque<u32>,
    expiring: BTreeMap<u32, ProcessState>,
    expiring_order: VecDeque<u32>,
    path_cache: BoundedMap<PathCacheKey, PathResolution>,
    evicted_process_detail_total: u64,
}

impl Normalizer {
    pub fn new(sensitive: SensitiveConfig, workspaces: Vec<WorkspaceRef>) -> Self {
        let mut normalizer = Self {
            sensitive,
            workspaces,
            processes: BTreeMap::new(),
            process_order: VecDeque::new(),
            expiring: BTreeMap::new(),
            expiring_order: VecDeque::new(),
            path_cache: BoundedMap::new(MAX_PATH_CACHE_ENTRIES),
            evicted_process_detail_total: 0,
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

    pub fn evicted_process_detail_total(&self) -> u64 {
        self.evicted_process_detail_total
    }

    pub(crate) fn enforce_process_bounds(&mut self) {
        self.enforce_process_bounds_to(veriskein_proto::defaults::MAX_PROCESS_STATES);
    }

    pub(crate) fn enforce_process_bounds_to(&mut self, max_entries: usize) {
        while self.processes.len() + self.expiring.len() > max_entries {
            if self.evict_oldest_expiring_process() {
                continue;
            }
            let Some(pid) = self.process_order.pop_front() else {
                break;
            };
            if self.processes.remove(&pid).is_some() {
                self.evicted_process_detail_total =
                    self.evicted_process_detail_total.saturating_add(1);
            }
        }
    }

    pub(crate) fn note_expiring_process(&mut self, pid: u32) {
        self.expiring_order.retain(|existing| *existing != pid);
        self.expiring_order.push_back(pid);
    }

    fn evict_oldest_expiring_process(&mut self) -> bool {
        while let Some(pid) = self.expiring_order.pop_front() {
            if self.expiring.remove(&pid).is_some() {
                self.evicted_process_detail_total =
                    self.evicted_process_detail_total.saturating_add(1);
                return true;
            }
        }
        false
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
                self.note_process(pid);
            }
        }
    }

    pub(crate) fn note_process(&mut self, pid: u32) {
        self.process_order.retain(|existing| *existing != pid);
        self.process_order.push_back(pid);
    }
}
