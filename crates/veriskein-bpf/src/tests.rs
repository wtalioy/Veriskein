use std::fs::File;
use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};

use veriskein_proto::{EventRef, parse};

use crate::RuntimeEventSource;

#[test]
fn smoke_test_observes_evt_proc_exec() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let mut source = RuntimeEventSource::start().expect("source should start");
    let status = Command::new("/bin/sh")
        .arg("-lc")
        .arg("true")
        .status()
        .expect("shell should run");
    assert!(status.success());

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_exec = false;
    while Instant::now() < deadline {
        if let Some(bytes) = source
            .recv_timeout(Duration::from_millis(250))
            .expect("recv")
        {
            if matches!(parse(&bytes).expect("parse"), EventRef::ProcExec(_)) {
                saw_exec = true;
                break;
            }
        }
    }

    source.shutdown().expect("source should shut down");
    assert!(
        saw_exec,
        "collector::smoke_test should observe EVT_PROC_EXEC"
    );
}

#[test]
fn smoke_test_observes_evt_file_open() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let mut source = RuntimeEventSource::start().expect("source should start");
    let path = std::env::temp_dir().join("veriskein-bpf-open-smoke.txt");
    let _file = File::create(&path).expect("create temp file");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_open = false;
    while Instant::now() < deadline {
        if let Some(bytes) = source
            .recv_timeout(Duration::from_millis(250))
            .expect("recv")
        {
            if matches!(parse(&bytes).expect("parse"), EventRef::FileOpen(_)) {
                saw_open = true;
                break;
            }
        }
    }

    source.shutdown().expect("source should shut down");
    assert!(saw_open, "smoke test should observe EVT_FILE_OPEN");
}

#[test]
fn smoke_test_observes_evt_net_connect() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let mut source = RuntimeEventSource::start().expect("source should start");
    let _ = TcpStream::connect("127.0.0.1:9");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_connect = false;
    while Instant::now() < deadline {
        if let Some(bytes) = source
            .recv_timeout(Duration::from_millis(250))
            .expect("recv")
        {
            if matches!(parse(&bytes).expect("parse"), EventRef::NetConnect(_)) {
                saw_connect = true;
                break;
            }
        }
    }

    source.shutdown().expect("source should shut down");
    assert!(saw_connect, "smoke test should observe EVT_NET_CONNECT");
}
