#!/usr/bin/env bash
set -euo pipefail

ln -sf /usr/bin/zsh "${VERISKEIN_SCRATCH}/claude"
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
