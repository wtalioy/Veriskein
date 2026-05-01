use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use caps::{CapSet, Capability};
use veriskein_graph::AgentConfig;

use crate::Cli;
use crate::driver::resolve_config_root;

#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    #[error("kernel {0} is below the supported minimum of 5.15")]
    KernelTooOld(String),
    #[error("missing readable BTF file at {0}")]
    MissingBtf(String),
    #[error("tracefs is not readable at {0}; run as root or grant a DAC-bypass capability")]
    TracefsUnreadable(String),
    #[error("failed to raise RLIMIT_MEMLOCK")]
    Memlock,
    #[error("missing required capability {0}")]
    MissingCapability(&'static str),
    #[error("at least one workspace is required")]
    MissingWorkspace,
}

impl PreflightError {
    pub fn exit_code(&self) -> i32 {
        2
    }
}

pub fn preflight(cli: &Cli) -> Result<(), PreflightError> {
    check_kernel_release(&read_kernel_release()?)?;
    check_btf_path(Path::new("/sys/kernel/btf/vmlinux"))?;
    check_tracefs_path(Path::new(
        "/sys/kernel/tracing/events/sched/sched_process_exec/id",
    ))?;
    ensure_memlock_limit().map_err(|_| PreflightError::Memlock)?;
    ensure_capabilities()?;
    let config_root = resolve_config_root().map_err(|_| PreflightError::MissingWorkspace)?;
    let default_workspace = AgentConfig::load(&config_root.join("config/agents.toml"))
        .ok()
        .map(|config| config.default_workspace)
        .filter(|path| !path.is_empty());
    ensure_workspace_configured(&cli.workspaces, default_workspace.as_deref())?;
    Ok(())
}

pub fn check_kernel_release(release: &str) -> Result<(), PreflightError> {
    let mut parts = release.split(['.', '-']);
    let major = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    if (major, minor) < (5, 15) {
        return Err(PreflightError::KernelTooOld(release.to_string()));
    }
    Ok(())
}

pub fn check_btf_path(path: &Path) -> Result<(), PreflightError> {
    if !path.is_file() {
        return Err(PreflightError::MissingBtf(path.display().to_string()));
    }
    Ok(())
}

pub fn check_tracefs_path(path: &Path) -> Result<(), PreflightError> {
    std::fs::File::open(path)
        .map(|_| ())
        .map_err(|_| PreflightError::TracefsUnreadable(path.display().to_string()))
}

pub fn ensure_workspace_configured(
    workspaces: &[PathBuf],
    default_workspace: Option<&str>,
) -> Result<(), PreflightError> {
    if workspaces.is_empty() && default_workspace.is_none() {
        return Err(PreflightError::MissingWorkspace);
    }
    Ok(())
}

fn read_kernel_release() -> Result<String, PreflightError> {
    let output = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .map_err(|_| PreflightError::KernelTooOld("unknown".to_string()))?;
    let release = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if release.is_empty() {
        return Err(PreflightError::KernelTooOld("unknown".to_string()));
    }
    Ok(release)
}

fn ensure_memlock_limit() -> Result<()> {
    let target = 64_u64 * 1024 * 1024;
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut current) };
    if rc != 0 {
        bail!("getrlimit failed");
    }

    if current.rlim_cur >= target {
        return Ok(());
    }

    let desired = libc::rlimit {
        rlim_cur: target,
        rlim_max: current.rlim_max.max(target),
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &desired) };
    if rc != 0 {
        bail!("setrlimit failed");
    }
    Ok(())
}

fn ensure_capabilities() -> Result<(), PreflightError> {
    let required = [
        (Capability::CAP_BPF, "CAP_BPF"),
        (Capability::CAP_PERFMON, "CAP_PERFMON"),
        (Capability::CAP_SYS_PTRACE, "CAP_SYS_PTRACE"),
    ];

    for (capability, name) in required {
        let has_cap = caps::has_cap(None, CapSet::Effective, capability)
            .map_err(|_| PreflightError::MissingCapability(name))?;
        if !has_cap {
            return Err(PreflightError::MissingCapability(name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        PreflightError, check_btf_path, check_kernel_release, check_tracefs_path,
        ensure_workspace_configured,
    };

    #[test]
    fn preflight_detects_old_kernel() {
        let err = check_kernel_release("5.14.0").expect_err("old kernel must fail");
        assert!(matches!(err, PreflightError::KernelTooOld(_)));
    }

    #[test]
    fn preflight_detects_missing_btf() {
        let path = PathBuf::from("/tmp/definitely-missing-veriskein-btf");
        let err = check_btf_path(&path).expect_err("missing btf must fail");
        assert!(matches!(err, PreflightError::MissingBtf(_)));
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn preflight_detects_unreadable_tracefs_target() {
        let path = PathBuf::from("/tmp/definitely-missing-veriskein-tracefs-id");
        let err = check_tracefs_path(&path).expect_err("missing tracefs target must fail");
        assert!(matches!(err, PreflightError::TracefsUnreadable(_)));
    }

    #[test]
    fn preflight_requires_workspace() {
        let err = ensure_workspace_configured(&[], None).expect_err("workspace is required");
        assert!(matches!(err, PreflightError::MissingWorkspace));
    }

    #[test]
    fn preflight_accepts_default_workspace() {
        ensure_workspace_configured(&[], Some("/tmp/ws")).expect("default workspace accepted");
    }
}
