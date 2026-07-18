#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=../lib/utils.sh
source "${ROOT_DIR}/lib/utils.sh"
load_config
# shellcheck source=../lib/logging.sh
source "${ROOT_DIR}/lib/logging.sh"
# shellcheck source=../lib/metrics.sh
source "${ROOT_DIR}/lib/metrics.sh"
# shellcheck source=../lib/incident.sh
source "${ROOT_DIR}/lib/incident.sh"

main() {
    log_init

    local line reason panic_script
    line="$(collect_metrics_line)"
    printf '%s\n' "$line" >>"$CURRENT_LOG"

    if ! reason="$(metrics_unhealthy_reason "$line")"; then
        log_debug "server healthy"
        "${SCRIPT_DIR}/rotate.sh" >/dev/null 2>&1 || log_warn "rotation failed"
        return 0
    fi

    if incident_active_dir >/dev/null; then
        log_warn "server unhealthy; continuing active incident: ${reason}"
    elif incident_in_cooldown; then
        log_warn "server unhealthy but panic cooldown is active: ${reason}"
        return 0
    else
        log_warn "server unhealthy; entering panic mode: ${reason}"
    fi

    panic_script="${SCRIPT_DIR}/panic.sh"
    "$panic_script" "$reason" "$line"
}

main "$@"
