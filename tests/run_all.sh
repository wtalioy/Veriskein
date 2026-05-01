#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Running Veriskein Phase 1 scenario-backed tests..."

cargo test -p veriskein-daemon \
  driver::tests::driver_emits_unexpected_shell_alert \
  --manifest-path "${ROOT_DIR}/Cargo.toml"

cargo test -p veriskein-daemon \
  driver::tests::driver_emits_sensitive_and_outside_workspace_alerts \
  --manifest-path "${ROOT_DIR}/Cargo.toml"

cargo test -p veriskein-detectors --manifest-path "${ROOT_DIR}/Cargo.toml"

echo
echo "Scenario mapping:"
echo "  A unexpected_shell_basic          -> driver_emits_unexpected_shell_alert"
echo "  B sensitive_file_access_shadow    -> driver_emits_sensitive_and_outside_workspace_alerts"
echo "  C out_of_workspace_deletion       -> driver_emits_sensitive_and_outside_workspace_alerts"
echo "  H benign_shell                    -> veriskein_detectors::tests::benign_shell_negative_when_not_in_session"
