#!/usr/bin/env bash
set -euo pipefail

# Delete both files; only the path outside the configured workspace should
# produce an alert.
"${VERISKEIN_SCRATCH}/claude" -lc "rm -f '${VERISKEIN_SCRATCH}/outside/file.txt' '${VERISKEIN_WORKSPACE}/inside.txt'"
