use std::fs::File;
use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};

use veriskein_proto::{EventRef, parse};

use crate::RuntimeEventSource;

fn requires_root() -> bool {
    if unsafe { libc::geteuid() } != 0 {
        return false;
    }
    true
}

fn observe_event(
    trigger: impl FnOnce(),
    matches_event: impl Fn(&EventRef<'_>) -> bool,
    description: &str,
) {
    if !requires_root() {
        return;
    }

    let mut source = RuntimeEventSource::start().expect("source should start");
    trigger();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_event = false;
    while Instant::now() < deadline {
        if let Some(bytes) = source
            .recv_timeout(Duration::from_millis(250))
            .expect("recv")
        {
            let parsed = parse(&bytes).expect("parse");
            if matches_event(&parsed) {
                saw_event = true;
                break;
            }
        }
    }

    source.shutdown().expect("source should shut down");
    assert!(saw_event, "{description}");
}

#[test]
fn smoke_test_observes_evt_proc_exec() {
    observe_event(
        || {
            let status = Command::new("/bin/sh")
                .arg("-lc")
                .arg("true")
                .status()
                .expect("shell should run");
            assert!(status.success());
        },
        |event| matches!(event, EventRef::ProcExec(_)),
        "collector::smoke_test should observe EVT_PROC_EXEC",
    );
}

#[test]
fn smoke_test_observes_evt_file_open() {
    observe_event(
        || {
            let path = std::env::temp_dir().join("veriskein-bpf-open-smoke.txt");
            let _file = File::create(&path).expect("create temp file");
        },
        |event| matches!(event, EventRef::FileOpen(_)),
        "smoke test should observe EVT_FILE_OPEN",
    );
}

#[test]
fn smoke_test_observes_evt_net_connect() {
    observe_event(
        || {
            let _ = TcpStream::connect("127.0.0.1:9");
        },
        |event| matches!(event, EventRef::NetConnect(_)),
        "smoke test should observe EVT_NET_CONNECT",
    );
}
