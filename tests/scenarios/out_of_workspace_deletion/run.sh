#!/usr/bin/env bash
set -euo pipefail

"${VERISKEIN_SCRATCH}/claude" -lc "rm -f '${VERISKEIN_SCRATCH}/outside/file.txt' '${VERISKEIN_WORKSPACE}/inside.txt'"
