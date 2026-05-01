use thiserror::Error;

use crate::{EventHeader, EventKind, EventRef, MetaDropEvent, ProcExecEvent, defaults};

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

    // Phase 0 keeps parsing zero-copy: validate the common header first, then
    // reinterpret the payload as the concrete packed event type.
    let header = plain::from_bytes::<EventHeader>(buf).map_err(|_| ParseError::BufferTooShort)?;
    if header.abi_version != defaults::EVT_ABI_VERSION {
        return Err(ParseError::AbiMismatch(header.abi_version));
    }

    let total_len = header.total_len as usize;
    if buf.len() < total_len {
        return Err(ParseError::TruncatedPayload);
    }

    match EventKind::from_raw(header.kind).ok_or(ParseError::UnknownEventKind(header.kind))? {
        EventKind::ProcExec => plain::from_bytes::<ProcExecEvent>(&buf[..total_len])
            .map(EventRef::ProcExec)
            .map_err(|_| ParseError::TruncatedPayload),
        EventKind::MetaDrop => plain::from_bytes::<MetaDropEvent>(&buf[..total_len])
            .map(EventRef::MetaDrop)
            .map_err(|_| ParseError::TruncatedPayload),
    }
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

#[cfg(test)]
mod tests {
    use crate::{
        DropReason, EventKind, EventRef, OwnedEvent, build_exec_event_bytes,
        build_meta_drop_event_bytes,
    };

    use super::{ParseError, parse, parse_c_string};

    #[test]
    fn parse_exec_roundtrip() {
        let raw = build_exec_event_bytes(3, 7, 4242, "bash", "/bin/bash", &["bash", "-lc", "true"]);
        let parsed = parse(&raw).expect("exec event should parse");
        match parsed {
            EventRef::ProcExec(evt) => {
                let kind = evt.header.kind;
                let pid = evt.pid;
                assert_eq!(kind, EventKind::ProcExec as u16);
                assert_eq!(pid, 4242);
                assert_eq!(parse_c_string(&evt.comm), "bash");
                assert_eq!(parse_c_string(&evt.filename), "/bin/bash");
            }
            _ => panic!("expected proc exec"),
        }

        let owned = parsed.to_owned();
        match owned {
            OwnedEvent::ProcExec(evt) => {
                assert_eq!(evt.argv, vec!["bash", "-lc", "true"]);
            }
            _ => panic!("expected owned proc exec"),
        }
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let err = parse(&[0_u8; 8]).expect_err("short buffer must fail");
        assert_eq!(err, ParseError::BufferTooShort);
    }

    #[test]
    fn parse_rejects_abi_mismatch() {
        let mut raw = build_exec_event_bytes(0, 1, 12, "sh", "/bin/sh", &["sh"]);
        raw[..4].copy_from_slice(&99_u32.to_ne_bytes());
        let err = parse(&raw).expect_err("abi mismatch must fail");
        assert_eq!(err, ParseError::AbiMismatch(99));
    }

    #[test]
    fn parse_drop_roundtrip() {
        let raw = build_meta_drop_event_bytes(1, 9, 4, 9, 5, DropReason::SeqGap);
        let parsed = parse(&raw).expect("drop event should parse");
        match parsed.to_owned() {
            OwnedEvent::MetaDrop(evt) => {
                assert_eq!(evt.expected_seq, 4);
                assert_eq!(evt.observed_seq, 9);
                assert_eq!(evt.reason, DropReason::SeqGap);
            }
            _ => panic!("expected meta drop"),
        }
    }
}
