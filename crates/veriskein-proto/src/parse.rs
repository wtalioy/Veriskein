use thiserror::Error;

use crate::{
    ContentFragEvent, EventHeader, EventKind, EventRef, FdDupEvent, FileOpenEvent, FileRenameEvent,
    FileUnlinkEvent, MetaDropEvent, NetConnectEvent, ProcChdirEvent, ProcExecEvent, ProcExitEvent,
    ProcForkEvent, TlsAssocEvent, defaults,
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
    // The kernel may reuse a larger scratch buffer around the event payload, so
    // parsing clamps to the declared event length after header validation.
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
        EventKind::ContentFrag => {
            parse_as::<ContentFragEvent>(&buf[..total_len]).map(EventRef::ContentFrag)
        }
        EventKind::TlsAssoc => parse_as::<TlsAssocEvent>(&buf[..total_len]).map(EventRef::TlsAssoc),
        EventKind::MetaDrop => parse_as::<MetaDropEvent>(&buf[..total_len]).map(EventRef::MetaDrop),
    }
}

fn parse_as<T: plain::Plain>(buf: &[u8]) -> Result<&T, ParseError> {
    plain::from_bytes::<T>(buf).map_err(|_| ParseError::TruncatedPayload)
}

pub fn parse_c_string(bytes: &[u8]) -> String {
    // Kernel payloads use fixed-width inline buffers, so everything after the
    // first NUL is capacity noise rather than data.
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
    // Rename events pack both paths into one fixed buffer with an expected NUL
    // separator, so split once and treat any tail garbage as irrelevant.
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
        ContentChannel, ContentDirection, DropReason, EventFixture, EventKind, EventRef, OwnedEvent,
    };

    use super::{ParseError, parse, parse_c_string};

    fn parse_owned(raw: Vec<u8>, label: &str) -> OwnedEvent {
        parse(&raw)
            .unwrap_or_else(|_| panic!("{label} should parse"))
            .to_owned()
    }

    #[test]
    fn parse_exec_roundtrip() {
        let raw = EventFixture::new(3, 7, 4242, 4242, 1, "bash")
            .exec("/bin/bash", &["bash", "-lc", "true"]);
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
        let raw = EventFixture::for_pid(1, 100, 1, "claude").fork(101, 101);
        match parse_owned(raw, "fork event") {
            OwnedEvent::ProcFork(evt) => assert_eq!(evt.child_pid, 101),
            _ => panic!("expected proc fork"),
        }
    }

    #[test]
    fn parse_file_open_roundtrip() {
        let raw = EventFixture::for_pid(2, 200, 1, "python3").open(-100, 3, "/tmp/demo.txt");
        match parse_owned(raw, "open") {
            OwnedEvent::FileOpen(evt) => {
                assert_eq!(evt.ret_fd, 3);
                assert_eq!(evt.path, "/tmp/demo.txt");
            }
            _ => panic!("expected file open"),
        }
    }

    #[test]
    fn parse_net_connect_roundtrip() {
        let raw = EventFixture::for_pid(3, 300, 1, "curl").connect(7, 443, true);
        match parse_owned(raw, "connect") {
            OwnedEvent::NetConnect(evt) => {
                assert_eq!(evt.sockfd, 7);
                assert!(evt.tls_candidate);
            }
            _ => panic!("expected connect"),
        }
    }

    #[test]
    fn parse_proc_exit_roundtrip() {
        let raw = EventFixture::for_pid(4, 400, 1, "bash").exit(17);
        match parse_owned(raw, "exit") {
            OwnedEvent::ProcExit(evt) => assert_eq!(evt.exit_code, 17),
            _ => panic!("expected exit"),
        }
    }

    #[test]
    fn parse_proc_chdir_roundtrip() {
        let raw = EventFixture::for_pid(5, 500, 1, "bash").chdir("/tmp/ws");
        match parse_owned(raw, "chdir") {
            OwnedEvent::ProcChdir(evt) => assert_eq!(evt.path, "/tmp/ws"),
            _ => panic!("expected chdir"),
        }
    }

    #[test]
    fn parse_fd_dup_roundtrip() {
        let raw = EventFixture::for_pid(6, 600, 1, "bash").dup(3, 9, 9);
        match parse_owned(raw, "dup") {
            OwnedEvent::FdDup(evt) => {
                assert_eq!(evt.oldfd, 3);
                assert_eq!(evt.newfd, 9);
            }
            _ => panic!("expected fd dup"),
        }
    }

    #[test]
    fn parse_file_unlink_roundtrip() {
        let raw = EventFixture::for_pid(7, 700, 1, "bash").unlink(-100, 0, "/tmp/x");
        match parse_owned(raw, "unlink") {
            OwnedEvent::FileUnlink(evt) => assert_eq!(evt.path, "/tmp/x"),
            _ => panic!("expected unlink"),
        }
    }

    #[test]
    fn parse_file_rename_roundtrip() {
        let raw =
            EventFixture::for_pid(8, 800, 1, "bash").rename(-100, -100, 0, "/tmp/old", "/tmp/new");
        match parse_owned(raw, "rename") {
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
        let mut raw = EventFixture::for_pid(1, 12, 1, "sh").exec("/bin/sh", &["sh"]);
        raw[8..12].copy_from_slice(&99_u32.to_ne_bytes());
        let err = parse(&raw).expect_err("abi mismatch must fail");
        assert_eq!(err, ParseError::AbiMismatch(99));
    }

    #[test]
    fn parse_drop_roundtrip() {
        let raw = EventFixture::new(1, 9, 0, 0, 0, "meta").meta_drop(4, 9, 5, DropReason::SeqGap);
        match parse_owned(raw, "drop") {
            OwnedEvent::MetaDrop(evt) => {
                assert_eq!(evt.expected_seq, 4);
                assert_eq!(evt.observed_seq, 9);
                assert_eq!(evt.reason, DropReason::SeqGap);
            }
            _ => panic!("expected drop"),
        }
    }

    #[test]
    fn parse_content_frag_roundtrip() {
        let raw = EventFixture::for_pid(10, 1000, 1, "curl").content_frag(
            0xabc,
            5,
            ContentChannel::Tls,
            ContentDirection::Write,
            b"POST /v1/chat\r\n\r\n{}",
            false,
        );
        match parse_owned(raw, "content frag") {
            OwnedEvent::ContentFrag(evt) => {
                assert_eq!(evt.ssl_ctx, 0xabc);
                assert_eq!(evt.stream_offset, 5);
                assert_eq!(evt.channel, ContentChannel::Tls);
                assert_eq!(evt.direction, ContentDirection::Write);
                assert_eq!(evt.data, b"POST /v1/chat\r\n\r\n{}");
            }
            _ => panic!("expected content frag"),
        }
    }

    #[test]
    fn parse_tls_assoc_roundtrip() {
        let raw = EventFixture::for_pid(11, 1100, 1, "curl").tls_assoc(
            0xabc,
            4,
            ContentDirection::Write,
            1,
        );
        match parse_owned(raw, "tls assoc") {
            OwnedEvent::TlsAssoc(evt) => {
                assert_eq!(evt.ssl_ctx, 0xabc);
                assert_eq!(evt.fd, 4);
                assert_eq!(evt.direction, ContentDirection::Write);
                assert_eq!(evt.assoc_ret, 1);
            }
            _ => panic!("expected tls assoc"),
        }
    }
}
