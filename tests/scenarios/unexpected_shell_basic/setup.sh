#!/usr/bin/env bash
set -euo pipefail

cat > "${VERISKEIN_SCRATCH}/claude" <<'EOF'
#!/usr/bin/env bash
exec /bin/sh "$@"
EOF
chmod +x "${VERISKEIN_SCRATCH}/claude"
