use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use libbpf_rs::{
    ErrorKind as BpfErrorKind, Link, MapCore, Object, ObjectBuilder, RingBufferBuilder, UprobeOpts,
};

const PROC_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/proc.bpf.o"));
const FS_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fs.bpf.o"));
const NET_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/net.bpf.o"));
const TLS_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tls_uprobe.bpf.o"));

#[derive(Debug, Clone)]
pub struct BpfRuntimeConfig {
    pub openssl_library_paths: Vec<PathBuf>,
    pub openssl_soname_allowlist: Vec<String>,
}

impl Default for BpfRuntimeConfig {
    fn default() -> Self {
        Self {
            openssl_library_paths: Vec::new(),
            openssl_soname_allowlist: vec!["libssl.so.3".to_string(), "libssl.so.1.1".to_string()],
        }
    }
}

struct LoadedObject {
    name: &'static str,
    object: Object,
}

pub struct RuntimeEventSource {
    rx: Receiver<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl RuntimeEventSource {
    pub fn start() -> Result<Self> {
        Self::start_with_config(BpfRuntimeConfig::default())
    }

    pub fn start_with_config(config: BpfRuntimeConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let openssl_libraries = discover_openssl_libraries(&config)?;

        let worker = thread::Builder::new()
            .name("veriskein-bpf".to_string())
            .spawn(move || {
                let mut objects = load_objects()?;
                let mut links = Vec::<Link>::new();
                let tls_index = objects
                    .iter()
                    .position(|loaded| loaded.name == "tls_uprobe")
                    .context("find tls_uprobe BPF object")?;

                // Attach every program before building the ring buffer so probe
                // activation is all-or-nothing from the daemon's perspective.
                for (index, loaded) in objects.iter_mut().enumerate() {
                    if index == tls_index {
                        continue;
                    }
                    for program in loaded.object.progs_mut() {
                        links.push(program.attach().context("attach BPF program")?);
                    }
                }
                for library_path in &openssl_libraries {
                    attach_openssl_programs(
                        &mut objects[tls_index].object,
                        library_path,
                        &mut links,
                    )
                    .with_context(|| {
                        format!("attach OpenSSL TLS probes in {}", library_path.display())
                    })?;
                }

                let event_maps: Vec<_> = objects
                    .iter()
                    .map(|loaded| {
                        loaded
                            .object
                            .maps()
                            .find(|map| map.name().to_string_lossy() == "events")
                            .with_context(|| {
                                format!("find ringbuf map `events` in {}", loaded.name)
                            })
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
                    match ringbuf.poll(Duration::from_millis(200)) {
                        Ok(()) => {}
                        Err(err) if err.kind() == BpfErrorKind::Interrupted => continue,
                        Err(err) => return Err(err).context("poll ringbuf"),
                    }
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

    pub fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
        match self.rx.try_recv() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => self.worker_exit_error(),
        }
    }

    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        match self.rx.recv_timeout(timeout) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => self.worker_exit_error(),
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

    fn worker_exit_error<T>(&mut self) -> Result<T> {
        let Some(worker) = self.worker.take() else {
            return Err(anyhow!("BPF worker disconnected"));
        };
        match worker.join() {
            Ok(Ok(())) => Err(anyhow!("BPF worker exited unexpectedly")),
            Ok(Err(err)) => Err(err.context("BPF worker exited")),
            Err(_) => Err(anyhow!("BPF worker panicked")),
        }
    }
}

impl Drop for RuntimeEventSource {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn load_objects() -> Result<Vec<LoadedObject>> {
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
        let object = ObjectBuilder::default()
            .open_memory(bytes)
            .with_context(|| format!("open {name} BPF object"))?
            .load()
            .with_context(|| format!("load {name} BPF object"))?;
        Ok(LoadedObject { name, object })
    })
    .collect()
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
        ("handle_ssl_set_fd_enter", "SSL_set_fd", false),
        ("handle_ssl_set_fd_exit", "SSL_set_fd", true),
        ("handle_ssl_set_rfd_enter", "SSL_set_rfd", false),
        ("handle_ssl_set_rfd_exit", "SSL_set_rfd", true),
        ("handle_ssl_set_wfd_enter", "SSL_set_wfd", false),
        ("handle_ssl_set_wfd_exit", "SSL_set_wfd", true),
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

fn discover_openssl_libraries(config: &BpfRuntimeConfig) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    for configured in &config.openssl_library_paths {
        if !configured.is_file() {
            return Err(anyhow!(
                "configured OpenSSL library path is not a file: {}",
                configured.display()
            ));
        }
        if !is_supported_openssl_path(config, configured) {
            return Err(anyhow!(
                "configured OpenSSL library path is not allowed by soname policy: {}",
                configured.display()
            ));
        }
        paths.insert(
            configured
                .canonicalize()
                .unwrap_or_else(|_| configured.clone()),
        );
    }
    for path in ldconfig_openssl_paths(config) {
        paths.insert(path);
    }
    for candidate in [
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.3",
        "/usr/lib/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/lib64/libssl.so.1.1",
        "/usr/lib64/libssl.so.1.1",
        "/usr/lib/libssl.so.1.1",
    ] {
        paths.insert(PathBuf::from(candidate));
    }
    Ok(paths
        .into_iter()
        .filter(|path| path.is_file() && is_supported_openssl_path(config, path))
        .map(|path| path.canonicalize().unwrap_or(path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn ldconfig_openssl_paths(config: &BpfRuntimeConfig) -> Vec<PathBuf> {
    let Ok(output) = Command::new("ldconfig").arg("-p").output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            line.split_once("=>")
                .map(|(_, path)| PathBuf::from(path.trim()))
        })
        .filter(|path| is_supported_openssl_path(config, path))
        .collect()
}

fn is_supported_openssl_path(config: &BpfRuntimeConfig, path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            config
                .openssl_soname_allowlist
                .iter()
                .any(|allowed| name.starts_with(allowed))
        })
}
