#!/usr/bin/env bash
set -euo pipefail

# The wrapper becomes the root session, and the nested `sh -lc` is what should
# trip the detector.
"${VERISKEIN_SCRATCH}/claude" -lc 'sh -lc "echo unexpected-shell >/dev/null"'
