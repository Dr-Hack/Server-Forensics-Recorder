#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=../lib/utils.sh
source "${ROOT_DIR}/lib/utils.sh"
load_config
# shellcheck source=../lib/logging.sh
source "${ROOT_DIR}/lib/logging.sh"

main() {
    log_init

    ensure_dir "$INCIDENT_DIR"
    ensure_dir "$ARCHIVE_DIR"

    local keep="${KEEP_INCIDENTS:-100}"
    local old_dir base archive

    while IFS= read -r old_dir; do
        [[ -n "$old_dir" ]] || continue
        base="$(basename "$old_dir")"
        archive="${ARCHIVE_DIR}/${base}.tar.gz"

        if command_exists tar; then
            tar -C "$INCIDENT_DIR" -czf "$archive" "$base"
            log_info "archived old incident: ${archive}"
        else
            log_warn "tar not found; deleting old incident without archive: ${base}"
        fi

        rm -rf -- "$old_dir"
    done < <(find "$INCIDENT_DIR" -mindepth 1 -maxdepth 1 -type d -name 'incident-*' | sort -r | awk -v keep="$keep" 'NR > keep')
}

main "$@"
