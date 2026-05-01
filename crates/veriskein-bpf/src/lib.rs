//! Phase 0 BPF loading and attachment helpers.
//! This crate owns BPF object compilation, attachment, and raw event delivery.

use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use libbpf_rs::{Link, MapCore, ObjectBuilder, RingBufferBuilder};

const PROC_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/proc.bpf.o"));
#[allow(dead_code, unused_imports, clippy::unwrap_used)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/proc.skel.rs"));
}

pub struct ProcExecSource {
    rx: Receiver<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl ProcExecSource {
    pub fn start() -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);

        let worker = thread::Builder::new()
            .name("veriskein-bpf".to_string())
            .spawn(move || {
                // Phase 0 keeps libbpf interaction isolated in a worker thread and
                // forwards opaque event bytes over an mpsc channel. That gives the
                // rest of the daemon a plain Rust interface with no libbpf types
                // leaking into higher layers.
                let object = ObjectBuilder::default()
                    .open_memory(PROC_BPF_OBJECT)
                    .context("open proc BPF object")?
                    .load()
                    .context("load proc BPF object")?;

                let mut links = Vec::<Link>::new();
                for program in object.progs_mut() {
                    links.push(program.attach().context("attach proc BPF program")?);
                }

                let events_map = object
                    .maps()
                    .find(|map| map.name() == OsStr::new("events"))
                    .context("find ringbuf map `events`")?;

                let mut builder = RingBufferBuilder::new();
                let sender = tx;
                builder
                    .add(&events_map, move |data| match sender.send(data.to_vec()) {
                        Ok(()) => 0,
                        Err(_) => -libc::ECANCELED,
                    })
                    .context("add ringbuf callback")?;
                let ringbuf = builder.build().context("build ringbuf")?;

                // Poll in bounded intervals so shutdown can observe the flag
                // promptly without needing more complex cross-thread wakeups.
                while !worker_shutdown.load(Ordering::Relaxed) {
                    ringbuf
                        .poll(Duration::from_millis(200))
                        .context("poll ringbuf")?;
                }

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

impl Drop for ProcExecSource {
    fn drop(&mut self) {
        // Best-effort cleanup: the explicit shutdown path reports errors, while
        // drop just ensures we do not leave the worker thread running.
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::*;
    use veriskein_proto::{EventRef, parse};

    #[test]
    fn smoke_test_observes_evt_proc_exec() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        let mut source = ProcExecSource::start().expect("source should start");
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
}
