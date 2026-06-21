# Replay Fixtures

Replay fixtures are NDJSON files: one event object per line, in the order the
userspace pipeline should process them. `veriskein-test replay` feeds these
events through normalization, graph attribution, detectors, alert projection,
and schema validation without attaching live BPF programs.

Run the checked-in attribution fixture:

```bash
cargo run -p veriskein-test -- replay \
  --fixture tests/replay/attribution_shell.jsonl \
  --output /tmp/veriskein-replay-alerts.jsonl \
  --workspace "$PWD"

cargo run -p veriskein-test -- assert \
  --expect tests/replay/attribution_shell.expect.jsonl \
  --actual /tmp/veriskein-replay-alerts.jsonl
```

`--workspace` is required unless `config/agents.toml` sets
`default_workspace`; replay uses it as the synthetic process cwd for fixture
PIDs that do not exist on the host.

Supported event shapes:

```json
{"kind":"exec","pid":700100,"ppid":1,"filename":"/usr/bin/claude","comm":"claude","argv":["claude"]}
{"kind":"startup","pid":700200,"ppid":1,"filename":"/usr/bin/claude","comm":"claude","argv":["claude"]}
{"kind":"fork","pid":700100,"child_pid":700101,"comm":"claude"}
{"kind":"open","pid":700101,"path":"/tmp/demo.txt","ret_fd":3,"comm":"python3"}
{"kind":"unlink","pid":700101,"path":"/tmp/demo.txt","ret":0,"comm":"python3"}
{"kind":"connect","pid":700101,"ip":"127.0.0.1","port":443,"comm":"python3"}
```

Defaults keep compact fixtures readable:

- `exec.ppid`: `0`
- `exec.comm`: basename of `filename`
- `exec.argv`: `[comm]`
- `startup`: seeds graph attribution without emitting a raw event
- `open.ret_fd`: `3`
- `unlink.ret`: `0`
- `connect.ip`: `127.0.0.1`
- `connect.port`: `443`
- all `comm` fields: a stable fallback derived from the event
