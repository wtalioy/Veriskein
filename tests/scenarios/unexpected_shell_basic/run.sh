#!/usr/bin/env bash
set -euo pipefail

"${VERISKEIN_SCRATCH}/claude" -lc 'sh -lc "echo unexpected-shell >/dev/null"'
