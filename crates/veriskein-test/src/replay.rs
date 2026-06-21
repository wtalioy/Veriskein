use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use veriskein_alert::{AlertThrottler, emit_ndjson_line, validate};
use veriskein_content::{
    ContentFragment, ContentRuntime, StreamOwner, StreamProvenance, TlsStreamKey,
};
use veriskein_correlator::{
    CapiState, ChainRiskKind, FileEventInput, InjectionKeywordConfig, PromptInput, PromptStore,
};
use veriskein_detectors::DetectorEngine;
use veriskein_detectors::detect_cross_agent_prompt_injection;
use veriskein_graph::{AgentConfig, EnvEvidence, GraphState, LlmEndpointResolver};
use veriskein_normalizer::{
    NormalizedData, NormalizedEvent, Normalizer, ProcessSnapshot, SensitiveConfig, load_workspaces,
    path_basename,
};
use veriskein_proto::{
    ContentChannel, ContentDirection, EventFixture, OwnedContentFragEvent, OwnedEvent, parse,
};
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
        flags: u32,
        #[serde(default)]
        content: Option<String>,
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
    ContentFrag {
        pid: u32,
        #[serde(default = "default_ssl_ctx")]
        ssl_ctx: u64,
        #[serde(default)]
        offset: u64,
        #[serde(default = "default_direction")]
        direction: String,
        bytes: String,
        #[serde(default)]
        truncated: bool,
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
    let mut content = ContentRuntime::new();
    let mut prompts = PromptStore::default();
    let mut capi = CapiState::new(InjectionKeywordConfig::load(
        &config_root.join("config/injection_keywords.toml"),
    )?);
    let mut throttler = AlertThrottler::default();
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
        replay.materialize_open_content(&workspace_inputs)?;
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
        if let OwnedEvent::ContentFrag(evt) = &event {
            process_content_fragment(
                evt,
                &graph,
                &mut state_net,
                &mut content,
                &mut prompts,
                &mut capi,
            );
            continue;
        }
        for normalized in normalizer.apply(seq, &event) {
            state_net.apply(&normalized);
            graph.apply(&normalized);
            observe_capi_file_event(&normalized, &graph, &mut capi);
            let mut findings = detectors.detect(&normalized, &graph, false);
            findings.extend(capi_findings_for_event(
                &normalized,
                &graph,
                &mut capi,
                &prompts,
                &findings,
            ));
            for finding in findings {
                let Some(alert) = throttler.project(&finding) else {
                    continue;
                };
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
                flags,
                comm,
                ..
            } => EventFixture::for_pid(seq, *pid, 1, default_comm(comm, "proc"))
                .open_with_flags(-100, *ret_fd, path, *flags),
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
            Self::ContentFrag {
                pid,
                ssl_ctx,
                offset,
                direction,
                bytes,
                truncated,
                comm,
            } => EventFixture::for_pid(seq, *pid, 1, default_comm(comm, "proc")).content_frag(
                *ssl_ctx,
                *offset,
                ContentChannel::Tls,
                parse_direction(direction)?,
                bytes.as_bytes(),
                *truncated,
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

    fn materialize_open_content(&self, workspaces: &[PathBuf]) -> Result<()> {
        let Self::Open {
            path,
            content: Some(content),
            ..
        } = self
        else {
            return Ok(());
        };
        let path = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            workspaces
                .first()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(path)
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create replay file parent {}", parent.display()))?;
        }
        std::fs::write(&path, content)
            .with_context(|| format!("write replay file content {}", path.display()))?;
        Ok(())
    }
}

fn process_content_fragment(
    evt: &OwnedContentFragEvent,
    graph: &GraphState,
    state_net: &mut StateNet,
    content: &mut ContentRuntime,
    prompts: &mut PromptStore,
    capi: &mut CapiState,
) {
    let binding = graph.resolve(evt.header.pid);
    let owner = StreamOwner::new(
        binding.map(|binding| binding.session_id),
        binding.map(|binding| binding.agent_id),
    );
    state_net.record_tls_fragment(evt.header.pid, evt.ssl_ctx, evt.header.ts_ns);
    let fragment = ContentFragment::with_degradation(
        TlsStreamKey::new(evt.header.pid, evt.ssl_ctx, evt.direction).stream_id(),
        evt.stream_offset,
        evt.data.clone(),
        owner,
        StreamProvenance {
            channel: evt.channel,
            direction: evt.direction,
            source: Some(format!("ssl_ctx={:x}", evt.ssl_ctx)),
        },
        Vec::new(),
    );
    for prompt in content.append(fragment) {
        let Some(session_id) = prompt.owner.session_id else {
            continue;
        };
        let prompt_id = prompts.insert(PromptInput {
            session_id,
            agent_id: prompt.owner.agent_id,
            stream_id: prompt.stream_id,
            capture_mode: prompt.provenance.channel,
            ts_start: evt.header.ts_ns,
            ts_end: evt.header.ts_ns,
            excerpt: prompt.text.into_bytes(),
            visibility_state: prompt.visibility,
            degraded: !prompt.degradation_reasons.is_empty(),
        });
        if let Some(snapshot) = prompts.snapshot(prompt_id) {
            capi.observe_prompt(snapshot);
        }
    }
}

fn observe_capi_file_event(normalized: &NormalizedEvent, graph: &GraphState, capi: &mut CapiState) {
    let Some(binding) = graph.resolve(normalized.process.pid) else {
        return;
    };
    let NormalizedData::FileOpen {
        path,
        ret_fd,
        flags,
    } = &normalized.data
    else {
        return;
    };
    if *ret_fd < 0 {
        return;
    }
    let (is_read, is_write) = file_access_modes(*flags);
    capi.observe_file_event(
        FileEventInput {
            session_id: binding.session_id,
            agent_id: Some(binding.agent_id),
            pid: normalized.process.pid,
            path: path.preferred_path_string(),
            ts_ns: normalized.ts_ns,
            is_workspace: path
                .workspace
                .as_ref()
                .is_some_and(|workspace| workspace.id == binding.workspace.id),
            is_write,
            is_read,
            inline_excerpt: None,
        },
        |path| std::fs::read(path).ok(),
    );
}

fn capi_findings_for_event(
    normalized: &NormalizedEvent,
    graph: &GraphState,
    capi: &mut CapiState,
    prompts: &PromptStore,
    base_findings: &[veriskein_detectors::Finding],
) -> Vec<veriskein_detectors::Finding> {
    let Some(binding) = graph.resolve(normalized.process.pid) else {
        return Vec::new();
    };
    base_findings
        .iter()
        .filter_map(|finding| ChainRiskKind::from_alert_type(finding.finding_type.as_str()))
        .flat_map(|risk_kind| {
            capi.chains_for_risky_event(
                binding.session_id,
                normalized.event_id.clone(),
                normalized.ts_ns,
                risk_kind,
                |prompt_id| prompts.snapshot(prompt_id),
            )
        })
        .filter_map(|chain| {
            detect_cross_agent_prompt_injection(
                &chain,
                normalized.process.pid,
                normalized.process.tid,
            )
        })
        .collect()
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

fn default_ssl_ctx() -> u64 {
    0xabc
}

fn default_direction() -> String {
    "write".to_string()
}

fn parse_direction(direction: &str) -> Result<ContentDirection> {
    match direction {
        "read" | "in" => Ok(ContentDirection::Read),
        "write" | "out" => Ok(ContentDirection::Write),
        other => bail!("unsupported content direction {other:?}"),
    }
}

const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_ACCMODE: u32 = 3;
const O_CREAT: u32 = 64;
const O_TRUNC: u32 = 512;
const O_APPEND: u32 = 1024;

fn file_access_modes(flags: u32) -> (bool, bool) {
    let access_mode = flags & O_ACCMODE;
    let is_read = access_mode == 0 || access_mode == O_RDWR;
    let is_write = access_mode == O_WRONLY
        || access_mode == O_RDWR
        || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0;
    (is_read, is_write)
}
