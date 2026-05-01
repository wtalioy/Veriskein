#!/usr/bin/env bash
set -euo pipefail

# Match the configured seed binary name while delegating to `/bin/sh` so the
# graph attributes the session before the child shell is spawned.
cat > "${VERISKEIN_SCRATCH}/claude" <<'EOF'
#!/usr/bin/env bash
exec /bin/sh "$@"
EOF
chmod +x "${VERISKEIN_SCRATCH}/claude"
