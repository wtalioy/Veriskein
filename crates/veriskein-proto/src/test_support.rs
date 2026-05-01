use crate::{DropReason, EventHeader, EventKind, MetaDropEvent, ProcExecEvent, defaults};

pub fn build_exec_event_bytes(
    cpu: u32,
    seq: u64,
    pid: u32,
    comm: &str,
    filename: &str,
    argv: &[&str],
) -> Vec<u8> {
    // These fixture builders intentionally construct the packed wire layout, not
    // the owned event shape, so tests exercise the real parser boundary.
    let mut event = ProcExecEvent {
        header: EventHeader {
            abi_version: defaults::EVT_ABI_VERSION,
            kind: EventKind::ProcExec as u16,
            header_len: core::mem::size_of::<EventHeader>() as u16,
            total_len: core::mem::size_of::<ProcExecEvent>() as u32,
            cpu,
            seq,
            ts_ns: 1_700_000_000_000_000_000 + seq,
        },
        pid,
        tgid: pid,
        ppid: 1,
        mount_ns: 42,
        ..Default::default()
    };

    write_c_bytes(&mut event.comm, comm.as_bytes());
    write_c_bytes(&mut event.filename, filename.as_bytes());
    write_arg_bytes(&mut event.argv, argv);

    unsafe { plain::as_bytes(&event) }.to_vec()
}

pub fn build_meta_drop_event_bytes(
    cpu: u32,
    seq: u64,
    expected_seq: u64,
    observed_seq: u64,
    missing: u64,
    reason: DropReason,
) -> Vec<u8> {
    let event = MetaDropEvent {
        header: EventHeader {
            abi_version: defaults::EVT_ABI_VERSION,
            kind: EventKind::MetaDrop as u16,
            header_len: core::mem::size_of::<EventHeader>() as u16,
            total_len: core::mem::size_of::<MetaDropEvent>() as u32,
            cpu,
            seq,
            ts_ns: 1_700_000_000_000_000_000 + seq,
        },
        expected_seq,
        observed_seq,
        missing,
        reason: reason as u8,
        _reserved: [0; 7],
    };

    unsafe { plain::as_bytes(&event) }.to_vec()
}

fn write_c_bytes(target: &mut [u8], source: &[u8]) {
    let max = target.len().saturating_sub(1);
    let len = source.len().min(max);
    target[..len].copy_from_slice(&source[..len]);
    if !target.is_empty() {
        target[len] = 0;
    }
}

fn write_arg_bytes(target: &mut [u8], args: &[&str]) {
    // Match the kernel-side convention for inline argv storage: NUL-separated
    // strings packed into a fixed-size byte region.
    let mut offset = 0;
    for arg in args {
        let bytes = arg.as_bytes();
        let needed = bytes.len() + 1;
        if offset + needed > target.len() {
            break;
        }
        target[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
        target[offset] = 0;
        offset += 1;
    }
}
