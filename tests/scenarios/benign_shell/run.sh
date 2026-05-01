#!/usr/bin/env bash
set -euo pipefail

# Drive a plain interactive shell path without impersonating an agent root.
/bin/sh -lc 'echo benign-shell >/dev/null'
