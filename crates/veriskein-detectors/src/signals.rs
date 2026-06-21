use veriskein_graph::Attribution;
use veriskein_normalizer::{NormalizedData, NormalizedEvent, PathContext, PathResolutionMode};

const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u32 = 64;
const O_TRUNC: u32 = 512;
const O_APPEND: u32 = 1024;

#[derive(Debug, Clone)]
pub(crate) enum DetectorSignal {
    SensitivePathHit(SensitivePathHit),
    OutOfWorkspaceMutation(OutOfWorkspaceMutation),
    SessionActivity(SessionActivity),
    SessionProgressSignal(SessionProgressSignal),
}

#[derive(Debug, Clone)]
pub(crate) struct SensitivePathHit {
    pub path: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct OutOfWorkspaceMutation {
    pub path: String,
    pub reason_code: &'static str,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionActivity {
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub evidence_kind: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionProgressSignal {
    pub path: String,
}

pub(crate) fn materialize_signals(
    event: &NormalizedEvent,
    binding: &Attribution,
) -> Vec<DetectorSignal> {
    match &event.data {
        NormalizedData::FileOpen {
            path,
            ret_fd,
            flags,
        } => file_open_signals(binding, path, *ret_fd, *flags),
        NormalizedData::FileUnlink { unlink_ret, path }
            if *unlink_ret == 0 && path.workspace.is_none() =>
        {
            vec![DetectorSignal::OutOfWorkspaceMutation(
                OutOfWorkspaceMutation {
                    path: path.preferred_path_string(),
                    reason_code: "unlink_outside_workspace",
                    note: note_for_path(path),
                },
            )]
        }
        NormalizedData::FileRename {
            rename_ret,
            new_path,
            ..
        } if *rename_ret == 0 && new_path.workspace.is_none() => {
            vec![DetectorSignal::OutOfWorkspaceMutation(
                OutOfWorkspaceMutation {
                    path: new_path.preferred_path_string(),
                    reason_code: "rename_outside_workspace",
                    note: note_for_path(new_path),
                },
            )]
        }
        NormalizedData::NetConnect {
            dst_ip, dst_port, ..
        } => vec![DetectorSignal::SessionActivity(SessionActivity {
            ip: dst_ip.clone(),
            port: *dst_port,
            path: None,
            evidence_kind: "net_connect",
        })],
        _ => Vec::new(),
    }
}

fn file_open_signals(
    binding: &Attribution,
    path: &PathContext,
    ret_fd: i32,
    flags: u32,
) -> Vec<DetectorSignal> {
    let mut out = Vec::new();
    let chosen_path = path.preferred_path_string();
    if path.sensitive_rule.is_some() {
        out.push(DetectorSignal::SensitivePathHit(SensitivePathHit {
            path: chosen_path.clone(),
            note: note_for_path(path),
        }));
    }
    if ret_fd >= 0 {
        out.push(DetectorSignal::SessionActivity(SessionActivity {
            ip: None,
            port: None,
            path: Some(chosen_path.clone()),
            evidence_kind: "file_access",
        }));
        if is_progress_file_open(binding, path, flags) {
            out.push(DetectorSignal::SessionProgressSignal(
                SessionProgressSignal { path: chosen_path },
            ));
        }
    }
    out
}

fn is_progress_file_open(binding: &Attribution, path: &PathContext, flags: u32) -> bool {
    path.workspace
        .as_ref()
        .is_some_and(|workspace| workspace.id == binding.workspace.id)
        && flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND) != 0
}

fn note_for_path(path: &PathContext) -> Option<String> {
    if path.resolution.mode == PathResolutionMode::LexicalOnly {
        Some("lexical_only".to_string())
    } else {
        None
    }
}
