use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use veriskein_alert::{AlertRecord, emit_ndjson_line, validate};
use veriskein_detectors::DetectorEngine;
use veriskein_graph::{AgentConfig, EnvEvidence, GraphState, LlmEndpointResolver};
use veriskein_normalizer::{
    Normalizer, ProcessSnapshot, SensitiveConfig, load_workspaces, path_basename,
};
use veriskein_proto::{EventFixture, OwnedEvent, parse};
use veriskein_state_net::StateNet;

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReplayEvent {
    Exec {
        pid: u32,
        #[serde(default)]
        ppid: u32,
        filename: String,
        #[serde(default)]
        comm: String,
        #[serde(default)]
        argv: Vec<String>,
        #[serde(default)]
        env_hints: Vec<String>,
    },
    Startup {
        pid: u32,
        #[serde(default)]
        ppid: u32,
        filename: String,
        #[serde(default)]
        comm: String,
        #[serde(default)]
        argv: Vec<String>,
        #[serde(default)]
        env_hints: Vec<String>,
        #[serde(default)]
        cwd: Option<PathBuf>,
    },
    Fork {
        pid: u32,
        child_pid: u32,
        #[serde(default)]
        comm: String,
    },
    Open {
        pid: u32,
        path: String,
        #[serde(default = "default_ret_fd")]
        ret_fd: i32,
        #[serde(default)]
        comm: String,
    },
    Unlink {
        pid: u32,
        path: String,
        #[serde(default)]
        ret: i32,
        #[serde(default)]
        comm: String,
    },
    Connect {
        pid: u32,
        #[serde(default = "default_ip")]
        ip: String,
        #[serde(default = "default_port")]
        port: u16,
        #[serde(default)]
        comm: String,
    },
}

pub(crate) fn replay_fixture(
    fixture: &Path,
    output: &Path,
    config_root: &Path,
    workspace_inputs: &[PathBuf],
) -> Result<()> {
    let sensitive = SensitiveConfig::load(&config_root.join("config/sensitive.toml"))?;
    let agent_config = AgentConfig::load(&config_root.join("config/agents.toml"))?;
    let workspace_inputs = agent_config.workspace_inputs_with_default(workspace_inputs);
    if workspace_inputs.is_empty() {
        bail!("replay requires at least one --workspace or config/agents.toml default_workspace");
    }
    let workspaces = load_workspaces(&workspace_inputs)?;
    let mut normalizer = Normalizer::new(sensitive, workspaces);
    let mut state_net = StateNet::new();
    let mut graph = GraphState::new(agent_config.clone(), normalizer.workspaces().to_vec())?;
    graph.refresh_endpoint_ips(LlmEndpointResolver::resolve(&agent_config.llm_endpoints));
    let mut detectors = DetectorEngine::new();
    let mut writer = BufWriter::new(
        std::fs::File::create(output)
            .with_context(|| format!("create replay output {}", output.display()))?,
    );

    let text = std::fs::read_to_string(fixture)
        .with_context(|| format!("read replay fixture {}", fixture.display()))?;
    for (idx, line) in text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let seq = (idx + 1) as u64;
        let replay: ReplayEvent = serde_json::from_str(line)
            .with_context(|| format!("parse replay fixture line {}", idx + 1))?;
        if let Some((snapshot, env_evidence)) = replay.to_startup_seed(&workspace_inputs) {
            graph.seed_from_snapshot(&snapshot, env_evidence);
            continue;
        }
        let event = replay
            .to_owned_event(seq)
            .with_context(|| format!("build replay fixture line {}", idx + 1))?;
        if let Some((pid, env_evidence)) = replay.env_evidence_for_exec() {
            graph.apply_env_evidence(pid, env_evidence, seq);
        }
        for normalized in normalizer.apply(seq, &event) {
            state_net.apply(&normalized);
            graph.apply(&normalized);
            for finding in detectors.detect(&normalized, &graph, false) {
                let alert = AlertRecord::from_finding(&finding);
                let value = alert.as_value()?;
                validate(&value).context("validate replay alert")?;
                emit_ndjson_line(&mut writer, &value)?;
            }
        }
    }
    writer.flush().context("flush replay output")?;
    Ok(())
}

impl ReplayEvent {
    fn to_owned_event(&self, seq: u64) -> Result<OwnedEvent> {
        let bytes = match self {
            Self::Startup { .. } => bail!("startup replay events do not build raw events"),
            Self::Exec {
                pid,
                ppid,
                filename,
                comm,
                argv,
                ..
            } => {
                let comm = default_comm(comm, filename);
                let argv_refs: Vec<&str> = if argv.is_empty() {
                    vec![comm.as_str()]
                } else {
                    argv.iter().map(String::as_str).collect()
                };
                EventFixture::for_pid(seq, *pid, *ppid, comm.as_str()).exec(filename, &argv_refs)
            }
            Self::Fork {
                pid,
                child_pid,
                comm,
            } => EventFixture::for_pid(seq, *pid, 1, default_comm(comm, "proc"))
                .fork(*child_pid, *child_pid),
            Self::Open {
                pid,
                path,
                ret_fd,
                comm,
            } => EventFixture::for_pid(seq, *pid, 1, default_comm(comm, "proc"))
                .open(-100, *ret_fd, path),
            Self::Unlink {
                pid,
                path,
                ret,
                comm,
            } => EventFixture::for_pid(seq, *pid, 1, default_comm(comm, "proc"))
                .unlink(-100, *ret, path),
            Self::Connect {
                pid, port, comm, ..
            } => EventFixture::for_pid(seq, *pid, 1, default_comm(comm, "proc")).connect(
                3,
                *port,
                *port == 443,
            ),
        };
        let mut event = parse(&bytes)?.to_owned();
        if let Self::Connect { ip, .. } = self {
            apply_connect_ip(&mut event, ip)?;
        }
        Ok(event)
    }

    fn to_startup_seed(&self, workspaces: &[PathBuf]) -> Option<(ProcessSnapshot, EnvEvidence)> {
        let Self::Startup {
            pid,
            ppid,
            filename,
            comm,
            argv,
            env_hints,
            cwd,
        } = self
        else {
            return None;
        };
        let comm = default_comm(comm, filename);
        let argv = if argv.is_empty() {
            vec![comm.clone()]
        } else {
            argv.clone()
        };
        Some((
            ProcessSnapshot {
                pid: *pid,
                tid: *pid,
                ppid: *ppid,
                exe: filename.clone(),
                comm,
                argv,
                cwd: cwd
                    .clone()
                    .or_else(|| workspaces.first().cloned())
                    .unwrap_or_else(|| PathBuf::from("/")),
            },
            EnvEvidence::new(env_hints.clone()),
        ))
    }

    fn env_evidence_for_exec(&self) -> Option<(u32, EnvEvidence)> {
        let Self::Exec { pid, env_hints, .. } = self else {
            return None;
        };
        if env_hints.is_empty() {
            return None;
        }
        Some((*pid, EnvEvidence::new(env_hints.clone())))
    }
}

fn apply_connect_ip(event: &mut OwnedEvent, ip: &str) -> Result<()> {
    let OwnedEvent::NetConnect(connect) = event else {
        bail!("connect replay event did not build a net_connect event");
    };
    match ip
        .parse::<IpAddr>()
        .with_context(|| format!("parse connect ip {ip:?}"))?
    {
        IpAddr::V4(ip) => {
            connect.family = 2;
            connect.addr_dst = [0; 16];
            connect.addr_dst[12..16].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            connect.family = 10;
            connect.addr_dst = ip.octets();
        }
    }
    Ok(())
}

fn default_comm(comm: &str, fallback: &str) -> String {
    if !comm.is_empty() {
        return comm.to_string();
    }
    path_basename(fallback).to_string()
}

fn default_ret_fd() -> i32 {
    3
}

fn default_port() -> u16 {
    443
}

fn default_ip() -> String {
    "127.0.0.1".to_string()
}
