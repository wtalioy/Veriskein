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
  if [[ "${VERISKEIN_FORCE_BUILD:-0}" = "1" || ! -x "${DAEMON_BIN}" || ! -x "${TEST_BIN}" ]]; then
    "${CARGO_BIN}" build -p veriskein-daemon -p veriskein-test --manifest-path "${ROOT_DIR}/Cargo.toml" >/dev/null
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

  ensure_binaries

  VERISKEIN_CONFIG_ROOT="${config_root}" "${DAEMON_BIN}" \
    --workspace "${workspace}" \
    --alert-output "${alerts}" \
    >"${daemon_log}" 2>&1 </dev/null &
  daemon_pid="$!"

  sleep 2
  if ! kill -0 "${daemon_pid}" 2>/dev/null; then
    echo "daemon exited before scenario ${slug}" >&2
    sed -n '1,120p' "${daemon_log}" >&2 || true
    wait "${daemon_pid}" || true
    return 1
  fi

  timeout "${SCENARIO_TIMEOUT_SECS}s" "${scenario_dir}/run.sh" </dev/null
  sleep 1

  # Ask the daemon to flush and stop cleanly so alert assertions see the final
  # NDJSON output instead of racing a forced exit.
  kill -TERM "${daemon_pid}"
  wait "${daemon_pid}"

  "${TEST_BIN}" assert \
    --expect "${scenario_dir}/expect.jsonl" \
    --actual "${alerts}"

  echo "PASS ${slug} (${run_dir})"
}

mapfile -t scenarios < <(find "${SCENARIO_ROOT}" -mindepth 1 -maxdepth 1 -type d | sort)
for scenario_dir in "${scenarios[@]}"; do
  slug="$(basename "${scenario_dir}")"
  if [[ -n "${ONLY}" && "${slug}" != "${ONLY}" ]]; then
    continue
  fi
  run_scenario "${slug}"
done
