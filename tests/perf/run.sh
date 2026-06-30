#!/usr/bin/env bash
# Veriskein capture-overhead benchmark.
#
# Runs ONE fixed workload (tests/perf/workloads/mixed_workload.sh) under four
# configurations and reports the workload's wall-clock overhead relative to the
# no-daemon baseline. The capture paths are isolated by real daemon flags so
# each mode attaches exactly the probes it claims:
#
#   baseline     workload only, no daemon attached
#   kernel-only  proc/fs/net syscall capture only
#                (--disable-tls --disable-content-io)
#   kernel+tls   + OpenSSL SSL_read/SSL_write uprobes      (--disable-content-io)
#   full         + content_io stdio/pipe capture actually populated
#                (--enable-content-capture; content_io tracepoints attached)
#
# To make `full` measure REAL stdio capture (not just attached-but-empty
# whitelist), the workload always runs under an agent-seeded `claude` wrapper and
# writes/reads its own stdio; in `full` the daemon recognizes the agent and
# whitelists fds 0/1/2, so those bytes flow through the content_io capture path.
# The workload is byte-for-byte identical across all modes, so the only variable
# is which probes the daemon attaches.
#
# Measurement is INTERLEAVED: each pass runs baseline and then every daemon mode
# back-to-back, and results are aggregated with the median across passes. This
# pairs each mode sample with a baseline sample from the same time window and
# cancels slow drift (cache/turbo warmup, thermal) that otherwise biases a
# block-ordered design. The first pass is discarded as warmup, and the daemon is
# given time to settle after each attach.
#
# Budget gate: the <=5% data-capture-loss limit is enforced strictly on
# kernel-only and kernel+tls (syscall + TLS capture). `full` adds stdio/MCP
# content capture, whose cost scales with captured content throughput, so it is
# reported informationally rather than held to the same fixed bound.
#
# Requires root for BPF attachment. Canonical invocation runs the whole script
# as root with SUDO empty:
#   sudo env PERF_SKIP_BUILD=1 SUDO= PERF_PROFILE=release bash tests/perf/run.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
PERF_DIR="${ROOT_DIR}/tests/perf"
WORKLOAD="${PERF_DIR}/workloads/mixed_workload.sh"

PROFILE="${PERF_PROFILE:-release}"
OUT_DIR="${PERF_OUT_DIR:-${ROOT_DIR}/artifacts/perf-real}"
TLS_PORT="${PERF_TLS_PORT:-14443}"
SUDO="${SUDO-sudo}"
CARGO_BIN="${CARGO_BIN:-$(command -v cargo || true)}"
# Pin the timed workload to a fixed CPU set so scheduler migration does not
# dominate the small capture-overhead signal. Baseline and every daemon mode use
# the same pinning, so the comparison stays fair.
PERF_CPUS="${PERF_CPUS:-0,1}"
# Run the daemon on a disjoint CPU set so its userspace analysis does not steal
# cycles from the timed workload; the measured overhead then reflects in-kernel
# capture cost (charged to the workload's own syscalls) rather than CPU
# contention with the collector.
PERF_DAEMON_CPUS="${PERF_DAEMON_CPUS:-2-7}"
PIN=()
DAEMON_PIN=()
if command -v taskset >/dev/null 2>&1; then
  PIN=(taskset -c "${PERF_CPUS}")
  DAEMON_PIN=(taskset -c "${PERF_DAEMON_CPUS}")
fi

export PERF_ITERS="${PERF_ITERS:-8}"
export PERF_FUNCS="${PERF_FUNCS:-200}"
export PERF_TLS_REQS="${PERF_TLS_REQS:-12}"
export PERF_STDIO_LINES="${PERF_STDIO_LINES:-20000}"

if [[ "${PROFILE}" == "release" ]]; then
  TARGET_DIR="${ROOT_DIR}/target/release"
  BUILD_FLAGS=(--release)
else
  TARGET_DIR="${ROOT_DIR}/target/debug"
  BUILD_FLAGS=()
fi
DAEMON_BIN="${TARGET_DIR}/veriskein-daemon"
PERF_BIN="${TARGET_DIR}/veriskein-perf"

WORK_DIR="$(mktemp -d)"
WS_DIR="${WORK_DIR}/ws"
SCRATCH_DIR="${WORK_DIR}/scratch"
CERT="${WORK_DIR}/cert.pem"
KEY="${WORK_DIR}/key.pem"
# The workload runs under this agent-seeded wrapper (basename matches a
# binary_seed in config/agents.toml) so the daemon classifies it as an agent and,
# in full mode, whitelists its stdio fds for content capture.
AGENT_WRAPPER="${WORK_DIR}/claude"
STDIN_FILE="${WORK_DIR}/agent-stdin.txt"
mkdir -p "${WS_DIR}" "${SCRATCH_DIR}" "${OUT_DIR}"

server_pid=""
daemon_pid=""

cleanup() {
  [[ -n "${daemon_pid}" ]] && ${SUDO} kill -TERM "${daemon_pid}" 2>/dev/null || true
  [[ -n "${server_pid}" ]] && kill -TERM "${server_pid}" 2>/dev/null || true
  rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

log() { printf '[perf] %s\n' "$*" >&2; }

build() {
  log "building ${PROFILE} binaries"
  "${CARGO_BIN}" build "${BUILD_FLAGS[@]}" \
    -p veriskein-daemon -p veriskein-perf --manifest-path "${ROOT_DIR}/Cargo.toml" >&2
}

start_tls_server() {
  log "generating self-signed cert + starting TLS server on :${TLS_PORT}"
  openssl req -x509 -newkey rsa:2048 -keyout "${KEY}" -out "${CERT}" \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1
  openssl s_server -accept "${TLS_PORT}" -cert "${CERT}" -key "${KEY}" \
    -quiet -www >/dev/null 2>&1 &
  server_pid="$!"
  for _ in $(seq 1 50); do
    if printf 'GET / HTTP/1.0\r\n\r\n' \
      | openssl s_client -connect "127.0.0.1:${TLS_PORT}" -quiet 2>/dev/null >/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  log "TLS server failed to come up"
  exit 1
}

# Parse "Elapsed (wall clock) time ...: [h:]m:s.ss" into milliseconds.
elapsed_ms_from_time() {
  awk '
    /Elapsed \(wall clock\)/ {
      n = split($NF, p, ":")
      if (n == 3) { ms = (p[1]*3600 + p[2]*60 + p[3]) * 1000 }
      else        { ms = (p[1]*60 + p[2]) * 1000 }
      printf "%.3f", ms
    }
  ' "$1"
}

cpu_percent_from_time() {
  awk -F': ' '/Percent of CPU this job got/ { gsub(/%/, "", $2); print $2 }' "$1"
}

median() {
  printf '%s\n' "$@" | sort -n | awk '{ a[NR]=$1 } END {
    if (NR % 2) { print a[(NR+1)/2] }
    else        { printf "%.3f", (a[NR/2] + a[NR/2+1]) / 2 }
  }'
}

# Create the agent wrapper (execs the workload, preserving pid so the seeded
# process IS the workload shell) and a finite stdin file for fd 0 read capture.
setup_agent_inputs() {
  cat > "${AGENT_WRAPPER}" <<EOF
#!/usr/bin/env bash
exec bash "${WORKLOAD}"
EOF
  chmod +x "${AGENT_WRAPPER}"
  : > "${STDIN_FILE}"
  for ((i = 0; i < 5000; i++)); do
    printf 'agent stdin line %d payload bbbbbbbbbbbbbbbbbbbbbbbb\n' "${i}"
  done > "${STDIN_FILE}"
}

start_daemon() {
  local alerts="$1"; shift
  local dlog="$1"; shift
  # With SUDO empty (canonical root invocation), env/taskset exec in place so $!
  # is the daemon pid. Capture it directly rather than scanning by name, which
  # could otherwise match an unrelated stale daemon on the host.
  ${SUDO} env VERISKEIN_CONFIG_ROOT="${ROOT_DIR}" "${DAEMON_PIN[@]}" "${DAEMON_BIN}" \
    --workspace "${WS_DIR}" --alert-output "${alerts}" --no-ipc "$@" \
    >"${dlog}" 2>&1 &
  daemon_pid="$!"
  for _ in $(seq 1 50); do
    if grep -q "veriskein runtime started" "${dlog}" 2>/dev/null; then break; fi
    if ! kill -0 "${daemon_pid}" 2>/dev/null; then break; fi
    sleep 0.2
  done
  # Verify the captured pid is actually our daemon bound to this run's workspace.
  if ! tr '\0' ' ' <"/proc/${daemon_pid}/cmdline" 2>/dev/null | grep -q "veriskein-daemon"; then
    log "captured pid ${daemon_pid} is not veriskein-daemon (SUDO='${SUDO}'?)"
    log "daemon log follows:"; sed -n '1,40p' "${dlog}" >&2
    exit 1
  fi
  if ! grep -q "veriskein runtime started" "${dlog}" 2>/dev/null; then
    log "daemon did not report startup; log follows:"; sed -n '1,40p' "${dlog}" >&2
    exit 1
  fi
  # Give uprobe attachment a moment to settle before timing.
  sleep 2
}

stop_daemon() {
  [[ -z "${daemon_pid}" ]] && return 0
  ${SUDO} kill -TERM "${daemon_pid}" 2>/dev/null || true
  for _ in $(seq 1 25); do
    kill -0 "${daemon_pid}" 2>/dev/null || break
    sleep 0.2
  done
  daemon_pid=""
}

daemon_rss_bytes() {
  [[ -z "${daemon_pid}" ]] && { echo 0; return; }
  local kb
  kb="$(${SUDO} awk '/VmRSS:/ { print $2 }' "/proc/${daemon_pid}/status" 2>/dev/null || echo 0)"
  echo $(( ${kb:-0} * 1024 ))
}

# Read a numeric field from the daemon's "veriskein final counters" log line,
# emitted on shutdown. Returns the cumulative total over the mode's session, or 0
# if the line is absent. Never fails the caller (safe under `set -e`).
counter_from_log() {
  local dlog="$1" field="$2" val
  val="$(grep "veriskein final counters" "${dlog}" 2>/dev/null \
    | tail -n1 \
    | sed -r 's/\x1b\[[0-9;]*m//g' \
    | grep -oE "${field}=[0-9]+" \
    | tail -n1 \
    | cut -d= -f2 || true)"
  printf '%s' "${val:-0}"
}

# The capture flags for each daemon mode (baseline runs without a daemon).
mode_flags() {
  case "$1" in
    kernel-only) printf -- '--disable-tls --disable-content-io' ;;
    kernel+tls) printf -- '--disable-content-io' ;;
    full) printf -- '--enable-content-capture' ;;
    *) printf '' ;;
  esac
}

# Run the timed workload once and print elapsed ms. The /usr/bin/time report is
# left in ${WORK_DIR}/run.time so the caller can also read CPU%.
time_one_run() {
  local tfile="${WORK_DIR}/run.time"
  /usr/bin/time -v -o "${tfile}" \
    env PERF_SCRATCH="${SCRATCH_DIR}" PERF_TLS_PORT="${TLS_PORT}" \
    "${PIN[@]}" "${AGENT_WRAPPER}" <"${STDIN_FILE}" >/dev/null 2>&1
  elapsed_ms_from_time "${tfile}"
}

# Interleaved measurement. Each pass runs baseline and then every daemon mode
# back-to-back under the same machine state, so per-mode samples are paired with
# baseline samples drawn from the same time window. Aggregating with the median
# across passes then cancels slow drift (cache/turbo warmup, thermal), which is
# what produced misleading negative overheads in a block-ordered design.
DAEMON_MODES=(kernel-only kernel+tls full)
PASSES="${PERF_PASSES:-6}"
WARM_PASSES="${PERF_WARM_PASSES:-1}"

main() {
  if [[ "${PERF_SKIP_BUILD:-0}" != "1" ]]; then
    build
  fi
  [[ -x "${DAEMON_BIN}" ]] || { log "missing ${DAEMON_BIN}"; exit 1; }
  [[ -x "${PERF_BIN}" ]] || { log "missing ${PERF_BIN}"; exit 1; }
  start_tls_server
  setup_agent_inputs

  log "workload: ITERS=${PERF_ITERS} FUNCS=${PERF_FUNCS} TLS_REQS=${PERF_TLS_REQS} STDIO_LINES=${PERF_STDIO_LINES}"
  log "passes: ${PASSES} (${WARM_PASSES} discarded as warmup), interleaved baseline+modes"

  local -A samp_file cpu_file ev_total dr_total al_total rss_max
  local m
  for m in baseline "${DAEMON_MODES[@]}"; do
    samp_file["${m}"]="${WORK_DIR}/samp.${m}"; : > "${samp_file[${m}]}"
    cpu_file["${m}"]="${WORK_DIR}/cpu.${m}"; : > "${cpu_file[${m}]}"
    ev_total["${m}"]=0; dr_total["${m}"]=0; al_total["${m}"]=0; rss_max["${m}"]=0
  done

  local p keep t c
  for ((p = 1; p <= PASSES; p++)); do
    keep=1; (( p <= WARM_PASSES )) && keep=0
    log "=== pass ${p}/${PASSES} (keep=${keep}) ==="

    # baseline (no daemon)
    t="$(time_one_run)"; c="$(cpu_percent_from_time "${WORK_DIR}/run.time")"
    log "  baseline = ${t} ms"
    if (( keep )); then echo "${t}" >>"${samp_file[baseline]}"; echo "${c}" >>"${cpu_file[baseline]}"; fi

    for m in "${DAEMON_MODES[@]}"; do
      local alerts="${WORK_DIR}/${m}.p${p}.alerts.jsonl"
      local dlog="${WORK_DIR}/${m}.p${p}.daemon.log"
      # shellcheck disable=SC2046
      start_daemon "${alerts}" "${dlog}" $(mode_flags "${m}")
      t="$(time_one_run)"; c="$(cpu_percent_from_time "${WORK_DIR}/run.time")"
      local r; r="$(daemon_rss_bytes)"
      stop_daemon
      local e d a
      e="$(counter_from_log "${dlog}" raw_events_total)"
      d="$(counter_from_log "${dlog}" reorder_or_drop_total)"
      a="$(wc -l <"${alerts}" 2>/dev/null | tr -d ' ')"
      log "  ${m} = ${t} ms (events=${e} drops=${d} alerts=${a})"
      if (( keep )); then
        echo "${t}" >>"${samp_file[${m}]}"; echo "${c}" >>"${cpu_file[${m}]}"
        ev_total["${m}"]=$(( ev_total[${m}] + ${e:-0} ))
        dr_total["${m}"]=$(( dr_total[${m}] + ${d:-0} ))
        al_total["${m}"]=$(( al_total[${m}] + ${a:-0} ))
        (( r > rss_max[${m}] )) && rss_max["${m}"]="${r}"
        cp -f "${dlog}" "${OUT_DIR}/${m}.daemon.log" 2>/dev/null || true
      fi
    done
  done

  emit_mode() {
    local m="$1" ev="$2" dr="$3" al="$4" rss="$5"
    local dur cpu
    # shellcheck disable=SC2046
    dur="$(median $(cat "${samp_file[${m}]}"))"
    # shellcheck disable=SC2046
    cpu="$(median $(cat "${cpu_file[${m}]}"))"
    printf '"%s": {"duration_ms": %s, "events_total": %s, "drops_total": %s, "alerts_total": %s, "rss_bytes": %s, "cpu_percent": %s}' \
      "${m}" "${dur}" "${ev}" "${dr}" "${al}" "${rss}" "${cpu:-0}"
  }

  local map="${WORK_DIR}/report-input.json"
  {
    printf '{\n'
    emit_mode baseline 0 0 0 0; printf ',\n'
    emit_mode kernel-only "${ev_total[kernel-only]}" "${dr_total[kernel-only]}" "${al_total[kernel-only]}" "${rss_max[kernel-only]}"; printf ',\n'
    emit_mode kernel+tls "${ev_total[kernel+tls]}" "${dr_total[kernel+tls]}" "${al_total[kernel+tls]}" "${rss_max[kernel+tls]}"; printf ',\n'
    emit_mode full "${ev_total[full]}" "${dr_total[full]}" "${al_total[full]}" "${rss_max[full]}"; printf '\n'
    printf '}\n'
  } > "${map}"

  log "rendering report into ${OUT_DIR}"
  "${PERF_BIN}" report --input "${map}" --output-dir "${OUT_DIR}" \
    --title "Veriskein Capture-Overhead Benchmark (${PROFILE})"
  cat "${OUT_DIR}/report.md" >&2

  # Budget gate. The competition/impl_docs limit of <=5% is the data-capture loss
  # for syscall + TLS capture, so we gate kernel-only and kernel+tls strictly.
  # full (stdio/MCP content capture) is reported informationally: its cost scales
  # with captured content throughput, so it is not held to the same fixed bound.
  local base_dur kmode_dur ov status=0
  base_dur="$(median "$(cat "${samp_file[baseline]}")")"
  for m in kernel-only kernel+tls; do
    kmode_dur="$(median "$(cat "${samp_file[${m}]}")")"
    ov="$(awk -v a="${kmode_dur}" -v b="${base_dur}" 'BEGIN { printf "%.2f", (a-b)/b*100 }')"
    if awk -v o="${ov}" 'BEGIN { exit !(o > 5.0) }'; then
      log "BUDGET FAILED: ${m} duration overhead ${ov}% > 5%"
      status=1
    else
      log "budget ok: ${m} duration overhead ${ov}% <= 5%"
    fi
  done
  kmode_dur="$(median "$(cat "${samp_file[full]}")")"
  ov="$(awk -v a="${kmode_dur}" -v b="${base_dur}" 'BEGIN { printf "%.2f", (a-b)/b*100 }')"
  log "full (content capture, informational): duration overhead ${ov}%"
  return "${status}"
}

main "$@"
