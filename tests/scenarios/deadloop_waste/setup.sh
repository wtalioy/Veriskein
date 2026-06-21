#!/usr/bin/env bash
set -euo pipefail

cat > "${VERISKEIN_SCRATCH}/claude" <<'EOF'
#!/usr/bin/env python3
import socket
import sys

loop_file = sys.argv[1]
for _ in range(60):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.02)
    try:
        s.connect(("127.0.0.1", 9))
    except OSError:
        pass
    finally:
        s.close()

for _ in range(20):
    with open(loop_file, "rb") as handle:
        handle.read(1)
EOF
chmod +x "${VERISKEIN_SCRATCH}/claude"
printf 'loop\n' > "${VERISKEIN_SCRATCH}/loopfile"
