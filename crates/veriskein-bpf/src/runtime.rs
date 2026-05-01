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

                // Attach every program before building the ring buffer so probe
                // activation is all-or-nothing from the daemon's perspective.
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
                        // Copy into owned bytes immediately because libbpf only
                        // lends ring buffer memory for the callback duration.
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
    // Runtime loading order matches the logical ownership split in `bpf/` and
    // keeps object-specific errors easy to attribute.
    [
        ("proc", PROC_BPF_OBJECT),
        ("fs", FS_BPF_OBJECT),
        ("net", NET_BPF_OBJECT),
    ]
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
