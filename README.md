# Veriskein

Veriskein is a local runtime monitor for AI-agent workspaces. It combines kernel events, normalized process/file/network state, prompt provenance, detector findings, alert projection, IPC streaming, replay fixtures, and scenario tests.

## Build

```bash
cargo build --workspace
```

The live daemon uses BPF components and may need Linux capabilities or sudo depending on the host. Replay tests do not attach BPF programs.

## Unit Tests

```bash
cargo test --workspace
```

For the end-to-end scenario suite:

```bash
tests/run_all.sh
tests/run_all.sh --only cross_agent_prompt_injection_tls
```

Scenario artifacts are written under `artifacts/` unless that directory is not writable, in which case the runner falls back to `target/veriskein-artifacts/`.

## Replay Fixtures

Replay fixtures are deterministic NDJSON event streams. They exercise normalization, attribution, prompt provenance, detectors, alert projection, and schema validation without live BPF.

```bash
cargo run -p veriskein-test -- replay \
  --fixture tests/replay/cross_agent_prompt_injection.jsonl \
  --output /tmp/veriskein-replay-alerts.jsonl \
  --workspace "$PWD"

cargo run -p veriskein-test -- assert \
  --expect tests/replay/cross_agent_prompt_injection.expect.jsonl \
  --actual /tmp/veriskein-replay-alerts.jsonl
```

Useful fixtures include:

- `tests/replay/attribution_shell.jsonl`
- `tests/replay/sensitive_file_access_shadow.jsonl`
- `tests/replay/out_of_workspace_deletion.jsonl`
- `tests/replay/tls_prompt_same_session.jsonl`
- `tests/replay/cross_agent_prompt_injection.jsonl`
- `tests/replay/cross_agent_prompt_injection_parallel_streams.jsonl`
- `tests/replay/deadloop_waste.jsonl`

## Live Scenarios

Each directory under `tests/scenarios/` owns its setup, workload, and expected alerts. Common smoke paths:

```bash
tests/run_all.sh --only unexpected_shell_basic
tests/run_all.sh --only sensitive_file_access_shadow
tests/run_all.sh --only out_of_workspace_deletion
tests/run_all.sh --only tls_openssl_prompt_capture
tests/run_all.sh --only cross_agent_prompt_injection_tls
tests/run_all.sh --only cross_agent_prompt_injection_parallel_streams_tls
tests/run_all.sh --only deadloop_waste
tests/run_all.sh --only degradation_honesty
```

## Daemon And IPC

Run the daemon against a workspace and write alerts to NDJSON:

```bash
cargo run -p veriskein-daemon -- \
  --workspace "$PWD" \
  --alert-output artifacts/alerts.jsonl
```

Tail alert IPC from another shell:

```bash
cargo run -p veriskein-cli -- tail --ipc
```

The IPC wire format is newline-delimited JSON with a flat `kind` discriminator. For example, clients send `{"kind":"hello",...,"subscribe":["alerts","metrics"]}` and receive `{"kind":"welcome",...,"schema":{"alert":1,"metrics":1}}`.

## Performance Reports

Render a sample performance artifact:

```bash
cargo run -p veriskein-perf -- report \
  --sample \
  --output-dir artifacts/perf-smoke \
  --max-duration-overhead-percent 40 \
  --max-rss-overhead-percent 40 \
  --max-drops-total 0
```

Render real measurements from JSON:

```bash
cargo run -p veriskein-perf -- report \
  --input measurements.json \
  --output-dir artifacts/perf-run
```

Run one workload command per mode and render the measured durations:

```bash
cargo run -p veriskein-perf -- measure \
  --baseline-cmd 'tests/run_all.sh --only benign_shell' \
  --kernel-only-cmd 'tests/run_all.sh --only unexpected_shell_basic' \
  --kernel-tls-cmd 'tests/run_all.sh --only tls_openssl_prompt_capture' \
  --full-cmd 'tests/run_all.sh --only cross_agent_prompt_injection_tls' \
  --output-dir artifacts/perf-run \
  --max-duration-overhead-percent 60
```

The report input can be either a full `PerfReport` JSON object or a map from mode names (`baseline`, `kernel-only`, `kernel+tls`, `full`) to measurements. Report and measure commands write `report.json` and `report.md`, and exit non-zero when configured budgets fail.

`measure` records wall-clock duration by default and uses `/usr/bin/time -v` for RSS/CPU when available. Workloads only need to print a `PerfMeasurement` JSON object on the last non-empty stdout line when drop or alert budgets are configured.

## Design Docs

The detailed implementation plan lives in `impl_docs/`, especially:

- `impl_docs/04_prompt_and_provenance.md`
- `impl_docs/05_detectors.md`
- `impl_docs/06_alerts.md`
- `impl_docs/07_tests_and_perf.md`
- `impl_docs/10_phase_issue_breakdown.md`
