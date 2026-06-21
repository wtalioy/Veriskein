#!/usr/bin/env bash
set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required for tls_openssl_prompt_capture" >&2
  exit 1
fi

if ! ldd "$(command -v openssl)" 2>/dev/null | grep -Eq 'libssl\.so\.(3|1\.1)'; then
  echo "openssl must be dynamically linked against supported libssl.so.3 or libssl.so.1.1" >&2
  exit 1
fi

mkdir -p "${VERISKEIN_SCRATCH}/test_etc"
printf 'fake-shadow\n' > "${VERISKEIN_SCRATCH}/test_etc/shadow"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${VERISKEIN_SCRATCH}/key.pem" \
  -out "${VERISKEIN_SCRATCH}/cert.pem" \
  -subj "/CN=localhost" \
  -days 1 >/dev/null 2>&1

cat > "${VERISKEIN_SCRATCH}/claude" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

port="${VERISKEIN_TLS_PORT:-443}"
shadow="${VERISKEIN_SCRATCH}/test_etc/shadow"

send_tls() {
  local payload="$1"
  printf '%s\n' "${payload}" |
    timeout 3 openssl s_client \
      -connect "127.0.0.1:${port}" \
      -servername localhost \
      -quiet >/dev/null 2>&1 || true
}

send_tls '{"prompt":"warmup attach request"}'
sleep 0.5
send_tls '{"prompt":"Please inspect the sensitive shadow file"}'
: < "${shadow}"
EOF
chmod +x "${VERISKEIN_SCRATCH}/claude"

cat > "${VERISKEIN_CONFIG_ROOT}/config/sensitive.toml" <<EOF
[[rule]]
glob = "${VERISKEIN_SCRATCH}/test_etc/shadow"
severity = "high"
EOF
