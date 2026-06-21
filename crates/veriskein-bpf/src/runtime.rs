use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use libbpf_rs::{Link, MapCore, Object, ObjectBuilder, RingBufferBuilder, UprobeOpts};

const PROC_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/proc.bpf.o"));
const FS_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fs.bpf.o"));
const NET_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/net.bpf.o"));
const TLS_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tls_uprobe.bpf.o"));

pub struct RuntimeEventSource {
    rx: Receiver<Vec<u8>>,
    control_tx: Sender<ControlCommand>,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}

#[derive(Clone)]
pub struct CaptureControl {
    tx: Sender<ControlCommand>,
}

enum ControlCommand {
    AttachOpenSsl {
        library_path: PathBuf,
        reply: Sender<Result<usize, String>>,
    },
}

impl RuntimeEventSource {
    pub fn start() -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let (control_tx, control_rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);

        let worker = thread::Builder::new()
            .name("veriskein-bpf".to_string())
            .spawn(move || {
                let mut objects = load_objects()?;
                let mut links = Vec::<Link>::new();
                let tls_index = objects
                    .iter()
                    .position(|object| {
                        object
                            .name()
                            .is_some_and(|name| name.to_string_lossy() == "tls_uprobe")
                    })
                    .context("find tls_uprobe BPF object")?;

                // Attach every program before building the ring buffer so probe
                // activation is all-or-nothing from the daemon's perspective.
                for (index, object) in objects.iter_mut().enumerate() {
                    if index == tls_index {
                        continue;
                    }
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
                        .add(events_map, move |data| match sender.send(data.to_vec()) {
                            Ok(()) => 0,
                            Err(_) => -libc::ECANCELED,
                        })
                        .context("add ringbuf callback")?;
                }
                let ringbuf = builder.build().context("build ringbuf")?;

                while !worker_shutdown.load(Ordering::Relaxed) {
                    while let Ok(command) = control_rx.try_recv() {
                        handle_control_command(command, &mut objects[tls_index], &mut links);
                    }
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
            control_tx,
            shutdown,
            worker: Some(worker),
        })
    }

    pub fn capture_control(&self) -> CaptureControl {
        CaptureControl {
            tx: self.control_tx.clone(),
        }
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

impl CaptureControl {
    pub fn attach_openssl_library(&self, library_path: impl AsRef<Path>) -> Result<usize> {
        let (reply, rx) = mpsc::channel();
        self.tx
            .send(ControlCommand::AttachOpenSsl {
                library_path: library_path.as_ref().to_path_buf(),
                reply,
            })
            .context("send OpenSSL attach request")?;
        rx.recv()
            .context("receive OpenSSL attach result")?
            .map_err(anyhow::Error::msg)
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
        ("tls_uprobe", TLS_BPF_OBJECT),
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

fn handle_control_command(command: ControlCommand, tls_object: &mut Object, links: &mut Vec<Link>) {
    match command {
        ControlCommand::AttachOpenSsl {
            library_path,
            reply,
        } => {
            let result = attach_openssl_programs(tls_object, &library_path, links)
                .map_err(|err| format!("{err:#}"));
            let _ = reply.send(result);
        }
    }
}

fn attach_openssl_programs(
    tls_object: &mut Object,
    library_path: &Path,
    links: &mut Vec<Link>,
) -> Result<usize> {
    let specs = [
        ("handle_ssl_read_enter", "SSL_read", false),
        ("handle_ssl_read_exit", "SSL_read", true),
        ("handle_ssl_read_ex_enter", "SSL_read_ex", false),
        ("handle_ssl_read_ex_exit", "SSL_read_ex", true),
        ("handle_ssl_write_enter", "SSL_write", false),
        ("handle_ssl_write_exit", "SSL_write", true),
        ("handle_ssl_write_ex_enter", "SSL_write_ex", false),
        ("handle_ssl_write_ex_exit", "SSL_write_ex", true),
    ];
    let start_len = links.len();
    for (program_name, symbol, retprobe) in specs {
        let program = tls_object
            .progs_mut()
            .find(|program| program.name().to_string_lossy() == program_name)
            .with_context(|| format!("find TLS BPF program {program_name}"))?;
        let opts = UprobeOpts {
            retprobe,
            func_name: Some(symbol.to_string()),
            ..Default::default()
        };
        links.push(
            program
                .attach_uprobe_with_opts(-1, library_path, 0, opts)
                .with_context(|| format!("attach {symbol} in {}", library_path.display()))?,
        );
    }
    Ok(links.len() - start_len)
}
