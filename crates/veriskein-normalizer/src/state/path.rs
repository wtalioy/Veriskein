use std::path::{Path, PathBuf};

use crate::config::{WorkspaceRef, lexical_clean};

use super::process::{FdEntry, ProcessState};
use super::{Normalizer, PathContext, PathResolution, PathResolutionMode, PathVerdict};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PathCacheKey {
    pub mount_ns: u64,
    pub basis: PathBuf,
    pub raw: String,
}

impl Normalizer {
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
            let resolved = self.compute_resolution(&base, &lexical, ts_ns);
            self.path_cache.insert(cache_key, resolved.clone());
            self.prune_path_cache();
            resolved
        };
        self.path_context_from_resolution(resolution)
    }

    pub fn workspace_of(&self, path: &Path) -> Option<&WorkspaceRef> {
        self.workspaces.iter().find(|ws| path.starts_with(&ws.root))
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

    fn prune_path_cache(&mut self) {
        while self.path_cache.len() > super::MAX_PATH_CACHE_ENTRIES {
            let Some(key) = self.path_cache.keys().next().cloned() else {
                break;
            };
            self.path_cache.remove(&key);
        }
    }
}
