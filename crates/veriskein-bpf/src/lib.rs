//! BPF loading, attachment, and raw event delivery.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use libbpf_rs::{Link, MapCore, Object, ObjectBuilder, RingBufferBuilder};

const PROC_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/proc.bpf.o"));
const FS_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fs.bpf.o"));
const NET_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/net.bpf.o"));

pub struct RuntimeEventSource {
    rx: Receiver<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl RuntimeEventSource {
    pub fn start() -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);

        let worker = thread::Builder::new()
            .name("veriskein-bpf".to_string())
            .spawn(move || {
                let mut objects = load_objects()?;
                let mut links = Vec::<Link>::new();

                for object in &mut objects {
                    for program in object.progs_mut() {
                        links.push(program.attach().context("attach BPF program")?);
                    }
                }

                let event_maps: Vec<_> = objects
                    .iter()
                    .map(|object| {
                        object
                            .maps()
                            .find(|map| map.name().to_string_lossy() == "events")
                            .context("find ringbuf map `events`")
                    })
                    .collect::<Result<_>>()?;

                let mut builder = RingBufferBuilder::new();
                for events_map in &event_maps {
                    let sender = tx.clone();
                    builder
                        .add(&*events_map, move |data| match sender.send(data.to_vec()) {
                            Ok(()) => 0,
                            Err(_) => -libc::ECANCELED,
                        })
                        .context("add ringbuf callback")?;
                }
                let ringbuf = builder.build().context("build ringbuf")?;

                while !worker_shutdown.load(Ordering::Relaxed) {
                    ringbuf
                        .poll(Duration::from_millis(200))
                        .context("poll ringbuf")?;
                }

                drop(objects);
                drop(links);
                Ok(())
            })
            .context("spawn BPF worker thread")?;

        Ok(Self {
            rx,
            shutdown,
            worker: Some(worker),
        })
    }

    pub fn try_recv(&self) -> Result<Option<Vec<u8>>> {
        match self.rx.try_recv() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(anyhow!("BPF worker disconnected")),
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        match self.rx.recv_timeout(timeout) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(anyhow!("BPF worker disconnected")),
        }
    }

    pub fn shutdown(&mut self) -> Result<()> {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow!("BPF worker panicked"))??;
        }
        Ok(())
    }
}

impl Drop for RuntimeEventSource {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn load_objects() -> Result<Vec<Object>> {
    [("proc", PROC_BPF_OBJECT), ("fs", FS_BPF_OBJECT), ("net", NET_BPF_OBJECT)]
        .into_iter()
        .map(|(name, bytes)| {
            ObjectBuilder::default()
                .open_memory(bytes)
                .with_context(|| format!("open {name} BPF object"))?
                .load()
                .with_context(|| format!("load {name} BPF object"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::process::Command;
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    use super::*;
    use veriskein_proto::{EventRef, parse};

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
            if let Some(bytes) = source.recv_timeout(Duration::from_millis(250)).expect("recv") {
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
            if let Some(bytes) = source.recv_timeout(Duration::from_millis(250)).expect("recv") {
                if matches!(parse(&bytes).expect("parse"), EventRef::NetConnect(_)) {
                    saw_connect = true;
                    break;
                }
            }
        }

        source.shutdown().expect("source should shut down");
        assert!(saw_connect, "smoke test should observe EVT_NET_CONNECT");
    }
}
