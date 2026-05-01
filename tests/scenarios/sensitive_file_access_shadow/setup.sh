#!/usr/bin/env bash
set -euo pipefail

cat > "${VERISKEIN_SCRATCH}/claude" <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/zsh "$@"
EOF
chmod +x "${VERISKEIN_SCRATCH}/claude"
mkdir -p "${VERISKEIN_SCRATCH}/test_etc"
mkdir -p "${VERISKEIN_SCRATCH}/zdotdir"
printf 'fake-shadow\n' > "${VERISKEIN_SCRATCH}/test_etc/shadow"
cat > "${VERISKEIN_SCRATCH}/zdotdir/.zshrc" <<EOF
: < "${VERISKEIN_SCRATCH}/test_etc/shadow"
EOF
cat > "${VERISKEIN_CONFIG_ROOT}/config/sensitive.toml" <<EOF
[[rule]]
glob = "${VERISKEIN_SCRATCH}/test_etc/shadow"
severity = "high"
EOF
