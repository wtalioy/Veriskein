//! Daemon entrypoint and runtime orchestration.

mod driver;
mod enrich;
mod entry;
mod ipc;
pub mod pipeline;
mod preflight;

pub use driver::run;
pub use entry::{Cli, install_tracing, main_entry};
pub use preflight::{PreflightError, check_btf_path, check_kernel_release, preflight};
