#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/phase0"
OUT_FILE="${OUT_DIR}/alerts.jsonl"
WORKSPACE_PATH="${1:-/tmp/veriskein-phase0-ws}"

mkdir -p "${OUT_DIR}" "${WORKSPACE_PATH}"

echo "Starting veriskein-daemon dry-run..."
sudo --preserve-env=VERISKEIN_LOG \
  cargo run -p veriskein-daemon --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
  --workspace "${WORKSPACE_PATH}" \
  --dry-run \
  --alert-output "${OUT_FILE}" &
DAEMON_PID=$!

cleanup() {
  if kill -0 "${DAEMON_PID}" 2>/dev/null; then
    sudo kill -TERM "${DAEMON_PID}" 2>/dev/null || true
    wait "${DAEMON_PID}" || true
  fi
}
trap cleanup EXIT

sleep 2
/bin/sh -lc "true"
sleep 2

sudo kill -TERM "${DAEMON_PID}"
wait "${DAEMON_PID}" || true
trap - EXIT

echo "Alerts written to ${OUT_FILE}"
if [[ -f "${OUT_FILE}" ]]; then
  tail -n 5 "${OUT_FILE}"
fi
