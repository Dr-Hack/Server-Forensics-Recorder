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
# shellcheck source=../lib/analysis.sh
source "${ROOT_DIR}/lib/analysis.sh"
# shellcheck source=../lib/ioforensics.sh
source "${ROOT_DIR}/lib/ioforensics.sh"

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

# Reads kernel stacks and wchan for the D-state processes that are the whole
# point of this investigation. Runs entirely from /proc — no disk I/O to the
# (possibly stalled) filesystem — and is bounded by PANIC_DSTATE_MAX_PIDS so a
# storm of blocked tasks can never make the recorder fan out. Skips gracefully
# when the kernel or permissions withhold the stack (needs root; some hardened
# kernels restrict /proc/<pid>/stack entirely).
capture_dstate_kernel_stacks() {
    local file="$1"
    local max="${PANIC_DSTATE_MAX_PIDS:-25}"
    local -a pids=()
    local pid comm

    append_header "$file" "kernel stacks (D-state, capped ${max})"

    mapfile -t pids < <(ps -eo pid=,stat= 2>/dev/null | awk '$2 ~ /^D/ { print $1 }' | head -n "$max")

    if [[ "${#pids[@]}" -eq 0 ]]; then
        printf 'no D-state processes present at capture time\n' >>"$file"
        return 0
    fi

    for pid in "${pids[@]}"; do
        comm="$(cat "/proc/${pid}/comm" 2>/dev/null || printf '?')"
        {
            printf '\n--- pid %s (%s) ---\n' "$pid" "$comm"
            printf 'wchan: '
            cat "/proc/${pid}/wchan" 2>/dev/null || printf '[unavailable]'
            printf '\nstack:\n'
            if [[ -r "/proc/${pid}/stack" ]]; then
                cat "/proc/${pid}/stack" 2>/dev/null || printf '[stack unreadable]\n'
            else
                printf '[stack unavailable — needs root / permitted kernel]\n'
            fi
        } >>"$file"
    done
}

# Captures PSI (Pressure Stall Information) from /proc/pressure and raises the
# incident's PSI peaks. PSI is the single best signal for telling a storage stall
# apart from a CPU or memory stall when utilisation looks low: it reports the
# fraction of the last 10s that tasks were stalled waiting on each resource. All
# three are tiny /proc reads. Skips gracefully on kernels without CONFIG_PSI.
capture_psi() {
    local dir="$1"
    local file="$2"
    local -a psi=()

    append_header "$file" "PSI (pressure stall information)"

    if [[ ! -d /proc/pressure ]]; then
        printf 'SKIPPED: /proc/pressure not present (kernel lacks CONFIG_PSI)\n' >>"$file"
        return 0
    fi

    local res
    for res in io cpu memory; do
        printf '\n--- /proc/pressure/%s ---\n' "$res" >>"$file"
        if [[ -r "/proc/pressure/${res}" ]]; then
            cat "/proc/pressure/${res}" 2>/dev/null >>"$file" || printf '[unreadable]\n' >>"$file"
        else
            printf '[unavailable]\n' >>"$file"
        fi
    done

    mapfile -t psi < <(read_psi_avg10 | tr ' ' '\n')
    # read_psi_avg10 emits: io_some io_full cpu_some mem_some mem_full
    incident_update_psi_peaks "$dir" \
        "${psi[0]:-NA}" "${psi[1]:-NA}" "${psi[2]:-NA}" "${psi[3]:-NA}" "${psi[4]:-NA}"
}

# Captures the D-state / blocking picture into its own file so the analysis
# engine (and a human) can parse it without wading through the general snapshot.
# Everything here is a cheap /proc or metadata read; package managers are
# DETECTED from the process table, never invoked — running dnf/yum/rpm during a
# panic can block on locks or the network and make the recorder part of the
# outage.
capture_forensics() {
    local dir="$1"
    local index="$2"
    local file="${dir}/dstate-${index}.log"

    {
        printf 'Server Forensics D-state / Blocking Snapshot\n'
        printf 'snapshot=%s\n' "$index"
        printf 'created_at=%s\n' "$(now_iso)"
    } >"$file"

    # Full process table with wait channels, then the D-state processes alone —
    # the single most valuable signal for "high load, low CPU".
    run_diag "$file" "ps wchan (all)" ps -eo pid,user,state,wchan:40,comm,args
    run_diag_shell "$file" "ps wchan (D-state only)" \
        "ps -eo pid,user,state,wchan:40,comm,args | awk 'NR==1 || \$3 ~ /^D/'"

    if sf_bool "${PANIC_CAPTURE_KERNEL_STACK:-1}"; then
        capture_dstate_kernel_stacks "$file"
    fi

    # PSI: how long tasks were actually stalled on I/O, CPU, and memory — the
    # measurement that distinguishes a storage stall from CPU or memory pressure.
    if sf_bool "${PANIC_CAPTURE_PSI:-1}"; then
        capture_psi "$dir" "$file"
    fi

    # Which service spawned the blocked processes.
    run_diag "$file" "pstree -ap" pstree -ap

    # Scheduled jobs running during the incident.
    run_diag "$file" "systemctl list-timers" systemctl list-timers --all --no-pager
    run_diag_shell "$file" "crontab -l (root)" "crontab -l"
    run_diag_shell "$file" "/etc/crontab and /etc/cron.*" \
        "cat /etc/crontab 2>/dev/null; for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do printf '\n== %s ==\n' \"\$d\"; ls -la \"\$d\" 2>/dev/null; done"

    # Maintenance / package / backup activity, detected from the process table.
    # The exclusion list covers the recorder's own helpers: without it the tool
    # detects its own `timeout`, `pidstat` and `iostat` invocations and then
    # scores them as maintenance activity, which is how a previous build reported
    # "Maintenance" as a cause partly on the strength of its own processes.
    run_diag_shell "$file" "maintenance/package processes (detected)" \
        "ps -eo pid,ppid,user,stat,etimes,comm,args | awk 'NR==1 || (tolower(\$0) ~ /dnf|yum| rpm|packagekit|imunify|cagefs|clamscan|freshclam|updatedb|mlocate|pkgacct|cpbackup|jetbackup|backup|rsync| tar |mysqldump|xtrabackup|mariabackup|upcp|leapp|ea-nginx|quota/ && \$6 !~ /^(awk|ps|sh|bash|timeout|pidstat|iostat|vmstat|lsof|find|sed|grep|head|sort|server-forensics)\$/ && \$0 !~ /server-forensics/)'"

    incident_meta_set "$dir" last_dstate_log "$file"
    log_warn "captured d-state forensics ${index}: ${file}"
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
    run_diag "$file" "lsof -nP" lsof -nP
    run_diag "$file" "df -h" df -h
    run_diag_shell "$file" "dmesg | tail -100" "dmesg | tail -100"
    run_diag "$file" "journalctl --since -5 min" journalctl --since "-5 min" --no-pager

    local -a mysqladmin_base
    mapfile -t mysqladmin_base < <(mysqladmin_base_args)
    run_diag "$file" "mysqladmin processlist" "${mysqladmin_base[@]}" --connect-timeout=2 processlist
    run_diag "$file" "mysqladmin status" "${mysqladmin_base[@]}" --connect-timeout=2 status
    run_diag "$file" "apachectl status" apachectl status

    if sf_bool "${ENABLE_DSTATE_FORENSICS:-1}"; then
        capture_forensics "$dir" "$index"
    fi

    # Per-process I/O attribution. This is what names the process actually moving
    # bytes, as opposed to naming services that merely exist. Runs last in the
    # snapshot because it is the only step with a sampling window; the three
    # samplers inside it run concurrently so it costs one window, not three.
    if sf_bool "${ENABLE_IO_FORENSICS:-1}"; then
        capture_io_forensics "$dir" "$index"
    fi

    incident_increment_snapshots "$dir" >/dev/null
    log_warn "captured panic snapshot ${index}: ${file}"
}

capture_test_snapshot() {
    local dir="$1"
    local metric_line="$2"
    local file="${dir}/snapshot-1.log"

    {
        printf 'Server Forensics Test Panic Snapshot\n'
        printf 'created_at=%s\n' "$(now_iso)"
        printf 'mode=test-panic\n'
        printf '\nLightweight metrics:\n%s\n' "$metric_line"
        printf '\nNo expensive diagnostics were executed in test-panic mode.\n'
    } >"$file"

    incident_increment_snapshots "$dir" >/dev/null
}

main() {
    log_init

    local reason="${1:-manual}"
    local metric_line="${2:-}"
    local dir index
    local test_panic=0

    if [[ "$reason" == "--test-panic" ]]; then
        test_panic=1
        reason="test-panic"
        metric_line=""
    fi

    if [[ "$test_panic" -eq 1 ]] && incident_active_dir >/dev/null; then
        log_error "refusing test panic while a real incident is active"
        return 1
    fi

    if [[ -z "$metric_line" ]]; then
        metric_line="$(collect_metrics_line)"
        printf '%s\n' "$metric_line" >>"$CURRENT_LOG"
    fi

    dir="$(incident_start "$reason" "$metric_line")"
    log_warn "panic mode active: ${dir}"

    if [[ "$test_panic" -eq 1 ]]; then
        capture_test_snapshot "$dir" "$metric_line"
        incident_close "$dir" "$metric_line"
        log_warn "test panic incident created and closed: ${dir}"
        printf '%s\n' "$dir"
        return 0
    fi

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
            analysis_generate "$dir" || log_warn "analysis generation failed"
            log_warn "panic mode recovered and incident closed: ${dir}"
            "${SCRIPT_DIR}/rotate.sh" >/dev/null 2>&1 || log_warn "rotation failed"
            return 0
        fi

        index=$((index + 1))
    done
}

main "$@"
