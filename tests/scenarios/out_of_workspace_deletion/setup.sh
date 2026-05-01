#!/usr/bin/env bash
set -euo pipefail

ln -sf /bin/sh "${VERISKEIN_SCRATCH}/claude"
mkdir -p "${VERISKEIN_SCRATCH}/outside"
printf 'delete-me\n' > "${VERISKEIN_SCRATCH}/outside/file.txt"
printf 'keep-me\n' > "${VERISKEIN_WORKSPACE}/inside.txt"
