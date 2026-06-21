use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use veriskein_proto::{parse_arg_vector, parse_c_string};

use super::ProcessSnapshot;

#[derive(Debug, Clone)]
pub(super) enum FdEntry {
    File(PathBuf),
}

#[derive(Debug, Clone)]
pub(super) struct ProcessState {
    pub(super) pid: u32,
    pub(super) tid: u32,
    pub(super) ppid: u32,
    pub(super) mount_ns: u64,
    pub(super) exe: String,
    pub(super) comm: String,
    pub(super) argv: Vec<String>,
    pub(super) cwd: PathBuf,
    pub(super) fds: Arc<BTreeMap<i32, FdEntry>>,
    pub(super) expired_at_ns: Option<u64>,
}

impl ProcessState {
    pub(super) fn from_proc_root(proc_root: &Path, pid: u32) -> Option<Self> {
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
            fds: Arc::new(read_fd_entries(&proc_dir)),
            expired_at_ns: None,
        })
    }

    pub(super) fn snapshot(&self) -> ProcessSnapshot {
        ProcessSnapshot {
            pid: self.pid,
            tid: self.tid,
            ppid: self.ppid,
            exe: self.exe.clone(),
            comm: self.comm.clone(),
            argv: self.argv.clone(),
            cwd: self.cwd.clone(),
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
