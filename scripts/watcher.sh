#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=../lib/utils.sh
source "${ROOT_DIR}/lib/utils.sh"
load_config
# shellcheck source=../lib/logging.sh
source "${ROOT_DIR}/lib/logging.sh"
# shellcheck source=../lib/plugins.sh
source "${ROOT_DIR}/lib/plugins.sh"
# shellcheck source=../lib/metrics.sh
source "${ROOT_DIR}/lib/metrics.sh"
# shellcheck source=../lib/incident.sh
source "${ROOT_DIR}/lib/incident.sh"
# shellcheck source=../lib/procring.sh
source "${ROOT_DIR}/lib/procring.sh"

main() {
    log_init

    local line reason panic_script
    line="$(collect_metrics_line)"
    printf '%s\n' "$line" >>"$CURRENT_LOG"

    # Record the pre-incident process picture on every cycle. This is what the
    # analysis reads backwards into when a spike is over before panic mode can
    # sample it. It never evaluates thresholds, so it cannot change when an
    # incident is declared.
    ring_tick || log_debug "ring sample skipped"

    if ! reason="$(metrics_unhealthy_reason "$line")"; then
        log_debug "server healthy"
        "${SCRIPT_DIR}/rotate.sh" >/dev/null 2>&1 || log_warn "rotation failed"
        # Spend the rest of the interval polling /proc/loadavg cheaply, taking a
        # full sample only while load is elevated, so a burst that starts and
        # finishes between timer ticks still leaves a trace.
        ring_poll_window || log_debug "ring poll window ended early"
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
