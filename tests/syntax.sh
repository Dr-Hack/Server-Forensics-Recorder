#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

SHELL_FILES=(
    "$ROOT_DIR/install.sh"
    "$ROOT_DIR/uninstall.sh"
    "$ROOT_DIR/bin/server-forensics"
    "$ROOT_DIR/scripts/collector.sh"
    "$ROOT_DIR/scripts/watcher.sh"
    "$ROOT_DIR/scripts/panic.sh"
    "$ROOT_DIR/scripts/rotate.sh"
    "$ROOT_DIR/lib/analysis.sh"
    "$ROOT_DIR/lib/incident.sh"
    "$ROOT_DIR/lib/logging.sh"
    "$ROOT_DIR/lib/metrics.sh"
    "$ROOT_DIR/lib/plugins.sh"
    "$ROOT_DIR/lib/utils.sh"
    "$ROOT_DIR/tests/analysis.sh"
    "$ROOT_DIR/tests/format.sh"
    "$ROOT_DIR/tests/lint.sh"
    "$ROOT_DIR/tests/syntax.sh"
    "$ROOT_DIR/tests/systemd.sh"
)

bash -n \
    "${SHELL_FILES[@]}"

printf 'syntax checks passed.\n'
