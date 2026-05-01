#!/usr/bin/env bash
set -euo pipefail

ZDOTDIR="${VERISKEIN_SCRATCH}/zdotdir" "${VERISKEIN_SCRATCH}/claude" -ic 'exit 0'
