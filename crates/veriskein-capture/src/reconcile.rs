use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Result;
use serde::Serialize;
use veriskein_graph::CaptureCandidate;
use veriskein_proto::{Role, VisibilityState, defaults};

use crate::maps::{LibraryMapping, MapsProvider, is_known_unsupported_tls, is_supported_openssl};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CaptureStatusKind {
    IntentSeen,
    Attached,
    Unsupported,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureStatus {
    pub pid: u32,
    pub kind: CaptureStatusKind,
    pub visibility_state: VisibilityState,
    pub attached_libraries: usize,
    pub capture_lag_ms: u64,
}

impl CaptureStatus {
    fn new(
        pid: u32,
        kind: CaptureStatusKind,
        visibility_state: VisibilityState,
        attached_libraries: usize,
        capture_lag_ms: u64,
    ) -> Self {
        Self {
            pid,
            kind,
            visibility_state,
            attached_libraries,
            capture_lag_ms,
        }
    }
}

pub trait AttachSink {
    fn attach_openssl_library(&mut self, library_path: &Path) -> Result<usize>;
}

impl<T> AttachSink for Box<T>
where
    T: AttachSink + ?Sized,
{
    fn attach_openssl_library(&mut self, library_path: &Path) -> Result<usize> {
        (**self).attach_openssl_library(library_path)
    }
}

#[derive(Clone)]
pub struct RuntimeAttachSink {
    control: veriskein_bpf::CaptureControl,
}

impl RuntimeAttachSink {
    pub fn new(control: veriskein_bpf::CaptureControl) -> Self {
        Self { control }
    }
}

impl AttachSink for RuntimeAttachSink {
    fn attach_openssl_library(&mut self, library_path: &Path) -> Result<usize> {
        self.control.attach_openssl_library(library_path)
    }
}

#[derive(Debug, Clone)]
struct CaptureIntent {
    first_seen_ns: u64,
    next_retry_ns: u64,
    attempts: u32,
    status: CaptureStatus,
}

impl CaptureIntent {
    fn new(
        pid: u32,
        now_ns: u64,
        kind: CaptureStatusKind,
        visibility_state: VisibilityState,
    ) -> Self {
        Self {
            first_seen_ns: now_ns,
            next_retry_ns: now_ns,
            attempts: 0,
            status: CaptureStatus::new(pid, kind, visibility_state, 0, 0),
        }
    }
}

pub struct CaptureReconciler<S, M> {
    sink: S,
    maps: M,
    attached: BTreeSet<(u64, u64)>,
    intents: BTreeMap<u32, CaptureIntent>,
}

impl<S, M> CaptureReconciler<S, M>
where
    S: AttachSink,
    M: MapsProvider,
{
    pub fn new(sink: S, maps: M) -> Self {
        Self {
            sink,
            maps,
            attached: BTreeSet::new(),
            intents: BTreeMap::new(),
        }
    }

    pub fn apply_candidate(
        &mut self,
        candidate: &CaptureCandidate,
        now_ns: u64,
    ) -> Result<CaptureStatus> {
        self.intents.entry(candidate.pid).or_insert_with(|| {
            CaptureIntent::new(
                candidate.pid,
                now_ns,
                CaptureStatusKind::IntentSeen,
                VisibilityState::Partial,
            )
        });
        self.try_attach(candidate.pid, now_ns)
    }

    pub fn reconcile_role(&mut self, pid: u32, role: Role, now_ns: u64) -> Result<CaptureStatus> {
        if !role_allows_capture(role) {
            return Ok(CaptureStatus::new(
                pid,
                CaptureStatusKind::IntentSeen,
                VisibilityState::Partial,
                0,
                0,
            ));
        }
        self.intents.entry(pid).or_insert_with(|| {
            CaptureIntent::new(
                pid,
                now_ns,
                CaptureStatusKind::IntentSeen,
                VisibilityState::Partial,
            )
        });
        self.try_attach(pid, now_ns)
    }

    fn try_attach(&mut self, pid: u32, now_ns: u64) -> Result<CaptureStatus> {
        let Some(intent_view) = self.intents.get(&pid) else {
            return Ok(CaptureStatus::new(
                pid,
                CaptureStatusKind::IntentSeen,
                VisibilityState::Partial,
                0,
                0,
            ));
        };
        if intent_view.next_retry_ns > now_ns {
            return Ok(intent_view.status.clone());
        }
        let first_seen_ns = intent_view.first_seen_ns;

        let mappings = match self.maps.library_mappings(pid) {
            Ok(mappings) => mappings,
            Err(_) => {
                let intent = self.intents.get_mut(&pid).expect("intent exists");
                intent.attempts += 1;
                intent.next_retry_ns = next_retry(now_ns, intent.attempts);
                intent.status.kind = CaptureStatusKind::Unavailable;
                intent.status.visibility_state = VisibilityState::Unavailable;
                return Ok(intent.status.clone());
            }
        };

        let supported = mappings
            .iter()
            .filter(|mapping| is_supported_openssl(mapping))
            .cloned()
            .collect::<Vec<_>>();
        if supported.is_empty() {
            let unsupported = mappings.iter().any(is_known_unsupported_tls);
            let intent = self.intents.get_mut(&pid).expect("intent exists");
            intent.status.kind = if unsupported {
                CaptureStatusKind::Unsupported
            } else {
                CaptureStatusKind::Unavailable
            };
            intent.status.visibility_state = if unsupported {
                VisibilityState::Unsupported
            } else {
                VisibilityState::Unavailable
            };
            intent.attempts += 1;
            intent.next_retry_ns = next_retry(now_ns, intent.attempts);
            return Ok(intent.status.clone());
        }

        let mut attached_now = 0;
        for mapping in supported {
            if self.attach_mapping(&mapping)? {
                attached_now += 1;
            }
        }
        let lag_ms = now_ns.saturating_sub(first_seen_ns) / 1_000_000;
        let intent = self.intents.get_mut(&pid).expect("intent exists");
        intent.status = CaptureStatus::new(
            pid,
            CaptureStatusKind::Attached,
            if lag_ms > defaults::CAPTURE_LAG_WARN_MS {
                VisibilityState::Partial
            } else {
                VisibilityState::Full
            },
            intent.status.attached_libraries + attached_now,
            lag_ms,
        );
        Ok(intent.status.clone())
    }

    fn attach_mapping(&mut self, mapping: &LibraryMapping) -> Result<bool> {
        let key = (mapping.dev, mapping.inode);
        if self.attached.contains(&key) {
            return Ok(false);
        }
        self.sink.attach_openssl_library(&mapping.path)?;
        self.attached.insert(key);
        Ok(true)
    }
}

pub fn role_allows_capture(role: Role) -> bool {
    matches!(role, Role::RootAgent | Role::SubAgent)
}

fn next_retry(now_ns: u64, attempts: u32) -> u64 {
    let backoff_ms = 50_u64.saturating_mul(1_u64 << attempts.min(5));
    now_ns + backoff_ms * 1_000_000
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use anyhow::Result;
    use veriskein_graph::CaptureCandidate;
    use veriskein_proto::{AttributionStrength, Role, VisibilityState};

    use super::*;

    #[derive(Default)]
    struct FakeMaps {
        rows: RefCell<BTreeMap<u32, Vec<LibraryMapping>>>,
        fail: RefCell<BTreeSet<u32>>,
    }

    impl FakeMaps {
        fn insert(&self, pid: u32, path: &str, dev: u64, inode: u64) {
            self.rows
                .borrow_mut()
                .entry(pid)
                .or_default()
                .push(LibraryMapping {
                    path: PathBuf::from(path),
                    dev,
                    inode,
                });
        }
    }

    impl MapsProvider for FakeMaps {
        fn library_mappings(&self, pid: u32) -> Result<Vec<LibraryMapping>> {
            if self.fail.borrow().contains(&pid) {
                anyhow::bail!("maps unavailable");
            }
            Ok(self.rows.borrow().get(&pid).cloned().unwrap_or_default())
        }
    }

    #[derive(Default)]
    struct FakeAttach {
        paths: Vec<PathBuf>,
    }

    impl AttachSink for FakeAttach {
        fn attach_openssl_library(&mut self, library_path: &Path) -> Result<usize> {
            self.paths.push(library_path.to_path_buf());
            Ok(6)
        }
    }

    fn candidate(pid: u32) -> CaptureCandidate {
        CaptureCandidate {
            pid,
            lineage_id: "lineage".to_string(),
            ttl_s: 15,
            evidence_strength: AttributionStrength::Strong,
        }
    }

    #[test]
    fn attaches_supported_openssl_once_per_inode() {
        let maps = FakeMaps::default();
        maps.insert(10, "/usr/lib/libssl.so.3", 1, 99);
        maps.insert(10, "/other/libssl.so.3", 1, 99);
        let mut reconciler = CaptureReconciler::new(FakeAttach::default(), maps);

        let status = reconciler
            .apply_candidate(&candidate(10), 1_000_000)
            .expect("attach");

        assert_eq!(status.kind, CaptureStatusKind::Attached);
        assert_eq!(status.attached_libraries, 1);
        assert_eq!(status.visibility_state, VisibilityState::Full);
    }

    #[test]
    fn unsupported_stack_is_honest() {
        let maps = FakeMaps::default();
        maps.insert(10, "/opt/boringssl/libcrypto.so", 1, 10);
        let mut reconciler = CaptureReconciler::new(FakeAttach::default(), maps);

        let status = reconciler
            .apply_candidate(&candidate(10), 1)
            .expect("status");

        assert_eq!(status.kind, CaptureStatusKind::Unsupported);
        assert_eq!(status.visibility_state, VisibilityState::Unsupported);
    }

    #[test]
    fn role_filter_skips_non_agent_roles() {
        assert!(role_allows_capture(Role::RootAgent));
        assert!(role_allows_capture(Role::SubAgent));
        assert!(!role_allows_capture(Role::ShellTool));
        assert!(!role_allows_capture(Role::ToolWorker));
    }

    #[test]
    fn maps_failure_surfaces_unavailable_with_retry() {
        let maps = FakeMaps::default();
        maps.fail.borrow_mut().insert(10);
        let mut reconciler = CaptureReconciler::new(FakeAttach::default(), maps);

        let status = reconciler
            .apply_candidate(&candidate(10), 1_000_000)
            .expect("status");

        assert_eq!(status.kind, CaptureStatusKind::Unavailable);
        assert_eq!(status.visibility_state, VisibilityState::Unavailable);
    }

    #[test]
    fn capture_lag_marks_partial() {
        let maps = FakeMaps::default();
        maps.insert(10, "/usr/lib/libssl.so.3", 1, 99);
        let mut reconciler = CaptureReconciler::new(FakeAttach::default(), maps);
        reconciler
            .apply_candidate(&candidate(10), 0)
            .expect("first");

        let status = reconciler
            .apply_candidate(&candidate(10), 600_000_000)
            .expect("late");

        assert_eq!(status.visibility_state, VisibilityState::Partial);
        assert_eq!(status.capture_lag_ms, 600);
    }
}
