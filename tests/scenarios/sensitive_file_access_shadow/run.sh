#!/usr/bin/env bash
set -euo pipefail

# zsh reads `.zshrc` on interactive startup, which lets the scenario trigger a
# sensitive open before the shell exits immediately.
ZDOTDIR="${VERISKEIN_SCRATCH}/zdotdir" "${VERISKEIN_SCRATCH}/claude" -ic 'exit 0'
