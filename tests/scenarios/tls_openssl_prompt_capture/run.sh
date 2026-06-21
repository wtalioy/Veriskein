#!/usr/bin/env bash
set -euo pipefail

port="${VERISKEIN_TLS_PORT:-443}"
server_log="${VERISKEIN_RUN_DIR}/openssl-server.log"

openssl s_server \
  -accept "${port}" \
  -cert "${VERISKEIN_SCRATCH}/cert.pem" \
  -key "${VERISKEIN_SCRATCH}/key.pem" \
  -quiet >"${server_log}" 2>&1 &
server_pid="$!"

cleanup() {
  kill "${server_pid}" 2>/dev/null || true
  wait "${server_pid}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 0.5
cd "${VERISKEIN_WORKSPACE}"
"${VERISKEIN_SCRATCH}/claude"
