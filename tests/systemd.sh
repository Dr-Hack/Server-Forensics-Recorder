#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

if ! command -v systemd-analyze >/dev/null 2>&1; then
    printf 'systemd-analyze is required for systemd unit validation.\n' >&2
    exit 127
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT

cp "$ROOT_DIR/scripts/watcher.sh" "$TMP_DIR/watcher.sh"
chmod 0755 "$TMP_DIR/watcher.sh"

sed "s|/opt/server-forensics/scripts/watcher.sh|${TMP_DIR}/watcher.sh|g" \
    "$ROOT_DIR/systemd/service" >"$TMP_DIR/server-forensics.service"
cp "$ROOT_DIR/systemd/timer" "$TMP_DIR/server-forensics.timer"

systemd-analyze verify "$TMP_DIR/server-forensics.service" "$TMP_DIR/server-forensics.timer"

printf 'systemd unit validation passed.\n'
