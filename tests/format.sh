#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

if ! command -v shfmt >/dev/null 2>&1; then
    printf 'shfmt is required for format checks.\n' >&2
    exit 127
fi

shfmt -d -i 4 -ci -bn \
    "$ROOT_DIR/install.sh" \
    "$ROOT_DIR/uninstall.sh" \
    "$ROOT_DIR/scripts/collector.sh" \
    "$ROOT_DIR/scripts/watcher.sh" \
    "$ROOT_DIR/scripts/panic.sh" \
    "$ROOT_DIR/scripts/rotate.sh" \
    "$ROOT_DIR/lib/incident.sh" \
    "$ROOT_DIR/lib/logging.sh" \
    "$ROOT_DIR/lib/metrics.sh" \
    "$ROOT_DIR/lib/utils.sh" \
    "$ROOT_DIR/tests/format.sh" \
    "$ROOT_DIR/tests/lint.sh" \
    "$ROOT_DIR/tests/syntax.sh" \
    "$ROOT_DIR/tests/systemd.sh"

printf 'shfmt formatting check passed.\n'
