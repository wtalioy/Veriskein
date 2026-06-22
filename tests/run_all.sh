#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${ROOT_DIR}/artifacts"
SCENARIO_ROOT="${ROOT_DIR}/tests/scenarios"
ONLY=""
RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
CARGO_BIN="${CARGO_BIN:-$(command -v cargo || true)}"
DAEMON_BIN="${ROOT_DIR}/target/debug/veriskein-daemon"
TEST_BIN="${ROOT_DIR}/target/debug/veriskein-test"
SCENARIO_TIMEOUT_SECS="${SCENARIO_TIMEOUT_SECS:-20}"

if [[ -z "${CARGO_BIN}" ]]; then
  if [[ -n "${SUDO_USER:-}" ]] && [[ -x "/home/${SUDO_USER}/.cargo/bin/cargo" ]]; then
    CARGO_BIN="/home/${SUDO_USER}/.cargo/bin/cargo"
  elif [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    CARGO_BIN="${HOME}/.cargo/bin/cargo"
  else
    echo "cargo not found; set CARGO_BIN explicitly" >&2
    exit 1
  fi
fi

configure_rust_toolchain() {
  local cargo_dir
  cargo_dir="$(cd "$(dirname "${CARGO_BIN}")" && pwd)"
  export PATH="${cargo_dir}:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"

  if [[ -z "${RUSTC:-}" && -x "${cargo_dir}/rustc" ]]; then
    export RUSTC="${cargo_dir}/rustc"
  fi

  if [[ -n "${SUDO_USER:-}" && "${CARGO_BIN}" == "/home/${SUDO_USER}/.cargo/bin/cargo" ]]; then
    export CARGO_HOME="${CARGO_HOME:-/home/${SUDO_USER}/.cargo}"
    export RUSTUP_HOME="${RUSTUP_HOME:-/home/${SUDO_USER}/.rustup}"
  fi
}

configure_rust_toolchain

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)
      ONLY="$2"
      shift 2
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -e "${ARTIFACT_DIR}" && ! -w "${ARTIFACT_DIR}" ]]; then
  # Sudo-driven test runs often leave repo-local artifacts unwritable for the
  # current user, so fall back to a target-owned location instead of failing.
  ARTIFACT_DIR="${ROOT_DIR}/target/veriskein-artifacts"
fi
mkdir -p "${ARTIFACT_DIR}"

ensure_binaries() {
  # Rebuilding `veriskein-daemon` can strip file capabilities needed for live
  # BPF preflight, so preserve existing runnable binaries unless a rebuild is
  # explicitly requested or an artifact is missing.
  if [[ "${VERISKEIN_FORCE_BUILD:-0}" = "1" || ! -x "${DAEMON_BIN}" || ! -x "${TEST_BIN}" ]]; then
    "${CARGO_BIN}" build -p veriskein-daemon -p veriskein-test --manifest-path "${ROOT_DIR}/Cargo.toml" >/dev/null
  fi
  if [[ ! -x "${DAEMON_BIN}" || ! -x "${TEST_BIN}" ]]; then
    echo "required binaries were not produced under ${ROOT_DIR}/target/debug" >&2
    exit 1
  fi
}

run_scenario() {
  local slug="$1"
  local scenario_dir="${SCENARIO_ROOT}/${slug}"
  local run_dir="${ARTIFACT_DIR}/${slug}-${RUN_ID}"
  local workspace="${run_dir}/ws"
  local scratch="${run_dir}/scratch"
  local config_root="${run_dir}"
  local alerts="${run_dir}/alerts.jsonl"
  local daemon_log="${run_dir}/daemon.log"
  local daemon_pid=""
  local daemon_args=()

  echo "RUN ${slug}"

  mkdir -p "${workspace}" "${scratch}" "${config_root}/config"
  # Each scenario runs against an isolated config copy so setup scripts can
  # patch rules without leaking state into later scenarios.
  cp "${ROOT_DIR}/config/"*.toml "${config_root}/config/"

  export VERISKEIN_ROOT="${ROOT_DIR}"
  export VERISKEIN_SCENARIO_DIR="${scenario_dir}"
  export VERISKEIN_RUN_DIR="${run_dir}"
  export VERISKEIN_WORKSPACE="${workspace}"
  export VERISKEIN_SCRATCH="${scratch}"
  export VERISKEIN_CONFIG_ROOT="${config_root}"

  if [[ -x "${scenario_dir}/setup.sh" ]]; then
    "${scenario_dir}/setup.sh"
  fi

  if [[ -f "${scenario_dir}/daemon_args" ]]; then
    mapfile -t daemon_args < <(sed '/^[[:space:]]*$/d' "${scenario_dir}/daemon_args")
  fi

  cleanup_daemon() {
    if [[ -n "${daemon_pid}" ]] && kill -0 "${daemon_pid}" 2>/dev/null; then
      kill -TERM "${daemon_pid}" 2>/dev/null || true
      wait "${daemon_pid}" 2>/dev/null || true
    fi
    daemon_pid=""
  }
  trap cleanup_daemon RETURN

  VERISKEIN_CONFIG_ROOT="${config_root}" "${DAEMON_BIN}" \
    --workspace "${workspace}" \
    --alert-output "${alerts}" \
    "${daemon_args[@]}" \
    >"${daemon_log}" 2>&1 </dev/null &
  daemon_pid="$!"

  sleep 2
  if ! kill -0 "${daemon_pid}" 2>/dev/null; then
    echo "daemon exited before scenario ${slug}" >&2
    sed -n '1,120p' "${daemon_log}" >&2 || true
    wait "${daemon_pid}" || true
    daemon_pid=""
    return 1
  fi

  timeout "${SCENARIO_TIMEOUT_SECS}s" "${scenario_dir}/run.sh" </dev/null
  sleep 1

  # Ask the daemon to flush and stop cleanly so alert assertions see the final
  # NDJSON output instead of racing a forced exit.
  kill -TERM "${daemon_pid}"
  if ! wait "${daemon_pid}"; then
    echo "daemon exited non-zero after scenario ${slug}" >&2
    sed -n '1,120p' "${daemon_log}" >&2 || true
    daemon_pid=""
    return 1
  fi
  daemon_pid=""

  "${TEST_BIN}" assert \
    --expect "${scenario_dir}/expect.jsonl" \
    --actual "${alerts}"

  trap - RETURN
  echo "PASS ${slug} (${run_dir})"
}

ensure_binaries

mapfile -t scenarios < <(find "${SCENARIO_ROOT}" -mindepth 1 -maxdepth 1 -type d | sort)
for scenario_dir in "${scenarios[@]}"; do
  slug="$(basename "${scenario_dir}")"
  if [[ -n "${ONLY}" && "${slug}" != "${ONLY}" ]]; then
    continue
  fi
  run_scenario "${slug}"
done
