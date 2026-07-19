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

append_header() {
    local file="$1"
    local title="$2"
    {
        printf '\n\n===== %s =====\n' "$title"
        printf 'captured_at=%s\n' "$(now_iso)"
    } >>"$file"
}

run_diag() {
    local file="$1"
    local title="$2"
    shift 2
    local command_name="$1"
    local rc=0

    append_header "$file" "$title"

    if ! command_exists "$command_name"; then
        printf 'SKIPPED: command not found: %s\n' "$command_name" >>"$file"
        return 0
    fi

    set +e
    if command_exists timeout; then
        timeout "$PANIC_COMMAND_TIMEOUT" "$@" 2>&1 | head -n "$PANIC_OUTPUT_LINES" >>"$file"
        rc=${PIPESTATUS[0]}
    else
        "$@" 2>&1 | head -n "$PANIC_OUTPUT_LINES" >>"$file"
        rc=${PIPESTATUS[0]}
    fi
    set -e

    if [[ "$rc" -eq 141 ]]; then
        printf '\n[output capped at %s lines]\n' "$PANIC_OUTPUT_LINES" >>"$file"
    elif [[ "$rc" -ne 0 ]]; then
        printf '\n[command exited with status %s]\n' "$rc" >>"$file"
    fi
}

run_diag_shell() {
    local file="$1"
    local title="$2"
    local shell_command="$3"
    local rc=0

    append_header "$file" "$title"

    if ! command_exists bash; then
        printf 'SKIPPED: bash not found\n' >>"$file"
        return 0
    fi

    set +e
    if command_exists timeout; then
        timeout "$PANIC_COMMAND_TIMEOUT" bash -o pipefail -c "$shell_command" 2>&1 | head -n "$PANIC_OUTPUT_LINES" >>"$file"
        rc=${PIPESTATUS[0]}
    else
        bash -o pipefail -c "$shell_command" 2>&1 | head -n "$PANIC_OUTPUT_LINES" >>"$file"
        rc=${PIPESTATUS[0]}
    fi
    set -e

    if [[ "$rc" -eq 141 ]]; then
        printf '\n[output capped at %s lines]\n' "$PANIC_OUTPUT_LINES" >>"$file"
    elif [[ "$rc" -ne 0 ]]; then
        printf '\n[command exited with status %s]\n' "$rc" >>"$file"
    fi
}

capture_snapshot() {
    local dir="$1"
    local index="$2"
    local metric_line="$3"
    local file="${dir}/snapshot-${index}.log"

    {
        printf 'Server Forensics Panic Snapshot\n'
        printf 'snapshot=%s\n' "$index"
        printf 'created_at=%s\n' "$(now_iso)"
        printf '\nLightweight metrics:\n%s\n' "$metric_line"
    } >"$file"

    run_diag "$file" "date" date
    run_diag "$file" "uptime" uptime
    run_diag "$file" "free -m" free -m
    run_diag "$file" "vmstat 1 5" vmstat 1 5
    run_diag "$file" "iostat -xz 1 3" iostat -xz 1 3
    run_diag "$file" "top -b -n1" top -b -n1
    run_diag "$file" "ps auxfww" ps auxfww
    run_diag "$file" "ss -antp" ss -antp
    run_diag "$file" "lsof" lsof
    run_diag "$file" "df -h" df -h
    run_diag_shell "$file" "dmesg | tail -100" "dmesg | tail -100"
    run_diag "$file" "journalctl --since -5 min" journalctl --since "-5 min" --no-pager
    run_diag "$file" "mysqladmin processlist" mysqladmin --connect-timeout=2 processlist
    run_diag "$file" "mysqladmin status" mysqladmin --connect-timeout=2 status
    run_diag "$file" "apachectl status" apachectl status

    incident_increment_snapshots "$dir" >/dev/null
    log_warn "captured panic snapshot ${index}: ${file}"
}

main() {
    log_init

    local reason="${1:-manual}"
    local metric_line="${2:-}"
    local dir index

    if [[ -z "$metric_line" ]]; then
        metric_line="$(collect_metrics_line)"
        printf '%s\n' "$metric_line" >>"$CURRENT_LOG"
    fi

    dir="$(incident_start "$reason" "$metric_line")"
    log_warn "panic mode active: ${dir}"

    index="$(incident_meta_get "$dir" snapshots 0)"
    index=$((index + 1))

    while true; do
        incident_update_peaks "$dir" "$metric_line"
        capture_snapshot "$dir" "$index" "$metric_line"

        sleep "$PANIC_SNAPSHOT_INTERVAL"

        metric_line="$(collect_metrics_line)"
        printf '%s\n' "$metric_line" >>"$CURRENT_LOG"
        incident_update_peaks "$dir" "$metric_line"

        if metrics_are_healthy "$metric_line"; then
            incident_close "$dir" "$metric_line"
            log_warn "panic mode recovered and incident closed: ${dir}"
            "${SCRIPT_DIR}/rotate.sh" >/dev/null 2>&1 || log_warn "rotation failed"
            return 0
        fi

        index=$((index + 1))
    done
}

main "$@"
