#!/usr/bin/env bash
set -euo pipefail

# Use the same agent-root wrapper pattern as the shell scenario so file actions
# stay attributable to a confirmed session.
cat > "${VERISKEIN_SCRATCH}/claude" <<'EOF'
#!/usr/bin/env bash
exec /bin/sh "$@"
EOF
chmod +x "${VERISKEIN_SCRATCH}/claude"
# Create one path inside the workspace and one outside so the detector has a
# clean contrast case in a single run.
mkdir -p "${VERISKEIN_SCRATCH}/outside"
printf 'delete-me\n' > "${VERISKEIN_SCRATCH}/outside/file.txt"
printf 'keep-me\n' > "${VERISKEIN_WORKSPACE}/inside.txt"
