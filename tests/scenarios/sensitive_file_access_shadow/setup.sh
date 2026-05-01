#!/usr/bin/env bash
set -euo pipefail

# The fake "claude" wrapper preserves the process name the agent config expects
# while still delegating to zsh so the scenario can source a custom .zshrc.
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
# Override the copied scenario config so this run marks only the synthetic
# shadow path as sensitive, keeping the assertion deterministic across hosts.
cat > "${VERISKEIN_CONFIG_ROOT}/config/sensitive.toml" <<EOF
[[rule]]
glob = "${VERISKEIN_SCRATCH}/test_etc/shadow"
severity = "high"
EOF
