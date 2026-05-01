use thiserror::Error;

use crate::{
    EventHeader, EventKind, EventRef, FdDupEvent, FileOpenEvent, FileRenameEvent, FileUnlinkEvent,
    MetaDropEvent, NetConnectEvent, ProcChdirEvent, ProcExecEvent, ProcExitEvent, ProcForkEvent,
    defaults,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("buffer shorter than event header")]
    BufferTooShort,
    #[error("unsupported abi version {0}")]
    AbiMismatch(u32),
    #[error("unknown event kind {0}")]
    UnknownEventKind(u16),
    #[error("buffer shorter than expected payload")]
    TruncatedPayload,
}

pub fn parse(buf: &[u8]) -> Result<EventRef<'_>, ParseError> {
    if buf.len() < core::mem::size_of::<EventHeader>() {
        return Err(ParseError::BufferTooShort);
    }

    let header = plain::from_bytes::<EventHeader>(buf).map_err(|_| ParseError::BufferTooShort)?;
    if header.abi_version != defaults::EVT_ABI_VERSION {
        return Err(ParseError::AbiMismatch(header.abi_version));
    }

    let total_len = usize::from(header.total_len);
    if buf.len() < total_len {
        return Err(ParseError::TruncatedPayload);
    }

    match EventKind::from_raw(header.kind).ok_or(ParseError::UnknownEventKind(header.kind))? {
        EventKind::ProcFork => parse_as::<ProcForkEvent>(&buf[..total_len]).map(EventRef::ProcFork),
        EventKind::ProcExec => parse_as::<ProcExecEvent>(&buf[..total_len]).map(EventRef::ProcExec),
        EventKind::ProcExit => parse_as::<ProcExitEvent>(&buf[..total_len]).map(EventRef::ProcExit),
        EventKind::ProcChdir => {
            parse_as::<ProcChdirEvent>(&buf[..total_len]).map(EventRef::ProcChdir)
        }
        EventKind::FdDup => parse_as::<FdDupEvent>(&buf[..total_len]).map(EventRef::FdDup),
        EventKind::FileOpen => parse_as::<FileOpenEvent>(&buf[..total_len]).map(EventRef::FileOpen),
        EventKind::FileUnlink => {
            parse_as::<FileUnlinkEvent>(&buf[..total_len]).map(EventRef::FileUnlink)
        }
        EventKind::FileRename => {
            parse_as::<FileRenameEvent>(&buf[..total_len]).map(EventRef::FileRename)
        }
        EventKind::NetConnect => {
            parse_as::<NetConnectEvent>(&buf[..total_len]).map(EventRef::NetConnect)
        }
        EventKind::MetaDrop => parse_as::<MetaDropEvent>(&buf[..total_len]).map(EventRef::MetaDrop),
    }
}

fn parse_as<T: plain::Plain>(buf: &[u8]) -> Result<&T, ParseError> {
    plain::from_bytes::<T>(buf).map_err(|_| ParseError::TruncatedPayload)
}

pub fn parse_c_string(bytes: &[u8]) -> String {
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

pub fn parse_arg_vector(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

pub fn parse_path_pair(bytes: &[u8]) -> (String, String) {
    let mut iter = bytes.splitn(3, |byte| *byte == 0);
    let left = iter.next().unwrap_or_default();
    let right = iter.next().unwrap_or_default();
    (
        String::from_utf8_lossy(left).into_owned(),
        String::from_utf8_lossy(right).into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        DropReason, EventKind, EventRef, OwnedEvent, build_exec_event_bytes,
        build_fd_dup_event_bytes, build_file_open_event_bytes, build_file_rename_event_bytes,
        build_file_unlink_event_bytes, build_meta_drop_event_bytes, build_net_connect_event_bytes,
        build_proc_chdir_event_bytes, build_proc_exit_event_bytes, build_proc_fork_event_bytes,
    };

    use super::{ParseError, parse, parse_c_string};

    #[test]
    fn parse_exec_roundtrip() {
        let raw = build_exec_event_bytes(
            3,
            7,
            4242,
            4242,
            1,
            "bash",
            "/bin/bash",
            &["bash", "-lc", "true"],
        );
        let parsed = parse(&raw).expect("exec event should parse");
        match parsed {
            EventRef::ProcExec(evt) => {
                let kind = evt.header.kind;
                let pid = evt.header.pid;
                assert_eq!(kind, EventKind::ProcExec as u16);
                assert_eq!(pid, 4242);
                assert_eq!(parse_c_string(&evt.header.comm), "bash");
                assert_eq!(parse_c_string(&evt.filename), "/bin/bash");
            }
            _ => panic!("expected proc exec"),
        }

        match parsed.to_owned() {
            OwnedEvent::ProcExec(evt) => assert_eq!(evt.argv, vec!["bash", "-lc", "true"]),
            _ => panic!("expected owned proc exec"),
        }
    }

    #[test]
    fn parse_proc_fork_roundtrip() {
        let raw = build_proc_fork_event_bytes(0, 1, 100, 100, 1, "claude", 101, 101);
        let parsed = parse(&raw).expect("fork event should parse");
        match parsed.to_owned() {
            OwnedEvent::ProcFork(evt) => assert_eq!(evt.child_pid, 101),
            _ => panic!("expected proc fork"),
        }
    }

    #[test]
    fn parse_file_open_roundtrip() {
        let raw =
            build_file_open_event_bytes(0, 2, 200, 200, 1, "python3", -100, 3, "/tmp/demo.txt");
        match parse(&raw).expect("open should parse").to_owned() {
            OwnedEvent::FileOpen(evt) => {
                assert_eq!(evt.ret_fd, 3);
                assert_eq!(evt.path, "/tmp/demo.txt");
            }
            _ => panic!("expected file open"),
        }
    }

    #[test]
    fn parse_net_connect_roundtrip() {
        let raw = build_net_connect_event_bytes(0, 3, 300, 300, 1, "curl", 7, 443, true);
        match parse(&raw).expect("connect should parse").to_owned() {
            OwnedEvent::NetConnect(evt) => {
                assert_eq!(evt.sockfd, 7);
                assert!(evt.tls_candidate);
            }
            _ => panic!("expected connect"),
        }
    }

    #[test]
    fn parse_proc_exit_roundtrip() {
        let raw = build_proc_exit_event_bytes(0, 4, 400, 400, 1, "bash", 17);
        match parse(&raw).expect("exit should parse").to_owned() {
            OwnedEvent::ProcExit(evt) => assert_eq!(evt.exit_code, 17),
            _ => panic!("expected exit"),
        }
    }

    #[test]
    fn parse_proc_chdir_roundtrip() {
        let raw = build_proc_chdir_event_bytes(0, 5, 500, 500, 1, "bash", "/tmp/ws");
        match parse(&raw).expect("chdir should parse").to_owned() {
            OwnedEvent::ProcChdir(evt) => assert_eq!(evt.path, "/tmp/ws"),
            _ => panic!("expected chdir"),
        }
    }

    #[test]
    fn parse_fd_dup_roundtrip() {
        let raw = build_fd_dup_event_bytes(0, 6, 600, 600, 1, "bash", 3, 9, 9);
        match parse(&raw).expect("dup should parse").to_owned() {
            OwnedEvent::FdDup(evt) => {
                assert_eq!(evt.oldfd, 3);
                assert_eq!(evt.newfd, 9);
            }
            _ => panic!("expected fd dup"),
        }
    }

    #[test]
    fn parse_file_unlink_roundtrip() {
        let raw = build_file_unlink_event_bytes(0, 7, 700, 700, 1, "bash", -100, 0, "/tmp/x");
        match parse(&raw).expect("unlink should parse").to_owned() {
            OwnedEvent::FileUnlink(evt) => assert_eq!(evt.path, "/tmp/x"),
            _ => panic!("expected unlink"),
        }
    }

    #[test]
    fn parse_file_rename_roundtrip() {
        let raw = build_file_rename_event_bytes(
            0, 8, 800, 800, 1, "bash", -100, -100, 0, "/tmp/old", "/tmp/new",
        );
        match parse(&raw).expect("rename should parse").to_owned() {
            OwnedEvent::FileRename(evt) => {
                assert_eq!(evt.old_path, "/tmp/old");
                assert_eq!(evt.new_path, "/tmp/new");
            }
            _ => panic!("expected rename"),
        }
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let err = parse(&[0_u8; 8]).expect_err("short buffer must fail");
        assert_eq!(err, ParseError::BufferTooShort);
    }

    #[test]
    fn parse_rejects_abi_mismatch() {
        let mut raw = build_exec_event_bytes(0, 1, 12, 12, 1, "sh", "/bin/sh", &["sh"]);
        raw[8..12].copy_from_slice(&99_u32.to_ne_bytes());
        let err = parse(&raw).expect_err("abi mismatch must fail");
        assert_eq!(err, ParseError::AbiMismatch(99));
    }

    #[test]
    fn parse_drop_roundtrip() {
        let raw = build_meta_drop_event_bytes(1, 9, 4, 9, 5, DropReason::SeqGap);
        match parse(&raw).expect("drop should parse").to_owned() {
            OwnedEvent::MetaDrop(evt) => {
                assert_eq!(evt.expected_seq, 4);
                assert_eq!(evt.observed_seq, 9);
                assert_eq!(evt.reason, DropReason::SeqGap);
            }
            _ => panic!("expected drop"),
        }
    }
}
