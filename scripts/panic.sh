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
# shellcheck source=../lib/aggregate.sh
source "${ROOT_DIR}/lib/aggregate.sh"
# shellcheck source=../lib/ioforensics.sh
source "${ROOT_DIR}/lib/ioforensics.sh"
# shellcheck source=../lib/procring.sh
source "${ROOT_DIR}/lib/procring.sh"
# shellcheck source=../lib/webforensics.sh
source "${ROOT_DIR}/lib/webforensics.sh"

# `set -E` above propagates this trap into functions and subshells. Without a
# trap the only trace of a mid-capture death is systemd's "status=1/FAILURE",
# which names neither the command nor the line — on 2026-07-28 that cost two
# incidents their evidence and left the failure unexplained. Reporting is
# best-effort and must never itself abort the handler.
panic_on_err() {
    local rc=$? cmd="$BASH_COMMAND" line="${BASH_LINENO[0]:-?}"
    log_error "panic.sh aborted: rc=${rc} line=${line}: ${cmd}" || true
    exit "$rc"
}
trap panic_on_err ERR

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

# Rapid D-state capture — the answer to "WHAT were the blocked tasks waiting on".
#
# Blocked tasks are transient: during a stall they block and unblock every few
# milliseconds, so a single instantaneous `ps` usually catches none, which is why
# earlier reports read "Wait channels: unavailable" even mid-stall. This samples
# the D-state set PANIC_DSTATE_SAMPLES times at PANIC_DSTATE_INTERVAL, writing
# each pass under a "D-state only" header so the analysis wait-channel histogram
# tallies wchan across all of them, and unions the PIDs seen. For each unique PID
# it then reads wchan, the current syscall (arg0 is usually the fd), and the
# kernel stack — the call path that names the wait (jbd2 journal commit vs page
# writeback vs read).
#
# Runs entirely from /proc — no disk I/O to the (possibly stalled) filesystem —
# capped by PANIC_DSTATE_MAX_PIDS so a storm of blocked tasks cannot make the
# recorder fan out, and every deep read is timeout-bounded. Skips gracefully when
# the kernel or permissions withhold the stack (needs root; some hardened kernels
# restrict /proc/<pid>/stack entirely).
capture_dstate_kernel_stacks() {
    local file="$1"
    local dir="${2:-}"
    local max="${PANIC_DSTATE_MAX_PIDS:-25}"
    local samples="${PANIC_DSTATE_SAMPLES:-6}"
    local interval="${PANIC_DSTATE_INTERVAL:-0.5}"
    local tmo="${PANIC_DSTATE_READ_TIMEOUT:-2}"
    local -A seen=()
    local -A endpoint=()
    local -a order=()
    local k line p pid comm
    local began_epoch stacks=0 syscalls=0

    began_epoch="$(now_epoch)"

    for ((k = 1; k <= samples; k++)); do
        append_header "$file" "ps wchan (D-state only) sample ${k}/${samples}"
        while IFS= read -r line; do
            printf '%s\n' "$line" >>"$file"
            read -r p _ <<<"$line"
            if [[ "$p" =~ ^[0-9]+$ && -z "${seen[$p]:-}" ]]; then
                seen[$p]=1
                order+=("$p")
                # mod_lsapi rewrites a worker's argv to "lsphp:<script>", so the
                # blocked task can name its own endpoint. This is the join that
                # turns "something blocked in jbd2" into "this request blocked".
                endpoint[$p]="$(dstate_endpoint_of "$line")"
            fi
        done < <(ps -eo pid,user,state,wchan:40,comm,args 2>/dev/null | awk 'NR==1 || $3 ~ /^D/')
        if [[ "$k" -lt "$samples" ]]; then
            sleep "$interval" 2>/dev/null || true
        fi
    done

    if ! sf_bool "${PANIC_CAPTURE_KERNEL_STACK:-1}"; then
        dstate_write_stats "$file" "$dir" "$samples" "$interval" \
            "${#order[@]}" 0 0 "$began_epoch" "skipped (PANIC_CAPTURE_KERNEL_STACK=0)"
        return 0
    fi

    append_header "$file" "kernel stacks + syscall (D-state union, capped ${max})"
    if [[ "${#order[@]}" -eq 0 ]]; then
        printf 'no D-state processes caught across %s samples\n' "$samples" >>"$file"
        dstate_write_stats "$file" "$dir" "$samples" "$interval" \
            0 0 0 "$began_epoch" "completed; no blocked tasks present during the capture window"
        return 0
    fi

    local n=0
    for pid in "${order[@]}"; do
        ((n++))
        ((n > max)) && break
        comm="$(cat "/proc/${pid}/comm" 2>/dev/null || printf '?')"
        {
            printf '\n--- pid %s (%s) ---\n' "$pid" "$comm"
            [[ -n "${endpoint[$pid]:-}" ]] && printf 'endpoint: %s\n' "${endpoint[$pid]}"
            printf 'wchan:   '
            cat "/proc/${pid}/wchan" 2>/dev/null || printf '[unavailable]'
            printf '\nsyscall: '
            run_with_timeout "$tmo" cat "/proc/${pid}/syscall" 2>/dev/null || printf '[unavailable]'
            printf 'stack:\n'
            if [[ -r "/proc/${pid}/stack" ]]; then
                run_with_timeout "$tmo" cat "/proc/${pid}/stack" 2>/dev/null || printf '[stack unreadable]\n'
            else
                printf '[stack unavailable — needs root / permitted kernel]\n'
            fi
        } >>"$file"
        [[ -r "/proc/${pid}/syscall" ]] && syscalls=$((syscalls + 1))
        [[ -r "/proc/${pid}/stack" ]] && stacks=$((stacks + 1))
    done

    dstate_write_stats "$file" "$dir" "$samples" "$interval" \
        "${#order[@]}" "$stacks" "$syscalls" "$began_epoch" "completed; blocked tasks captured"
}

# Extracts the served PHP script from a D-state `ps` row, using the same
# last-two-components key the ring buffer uses so the two can be joined.
dstate_endpoint_of() {
    local line="$1"
    printf '%s\n' "$line" | awk '
        {
            gsub(/lsphp:/, " ")
            gsub(/php-fpm:/, " ")
            script = ""
            for (i = 1; i <= NF; i++) {
                tok = $i
                sub(/\?.*$/, "", tok)
                if (tok ~ /\.php$/) script = tok
            }
            if (script == "") exit
            base = script
            sub(/.*\//, "", base)
            rest = script
            if (sub(/\/[^\/]*$/, "", rest) && rest != "") {
                parent = rest
                sub(/.*\//, "", parent)
                if (parent != "") { print parent "/" base; exit }
            }
            print base
        }'
}

# Machine-readable record of what the rapid sampler actually did. The analysis
# reads this to distinguish "the recorder cannot capture wait channels" from
# "the recorder looked six times and the stall had already cleared" — an
# absence of evidence is itself evidence, but only if it is recorded as one.
dstate_write_stats() {
    local file="$1" dir="$2" samples="$3" interval="$4"
    local pids="$5" stacks="$6" syscalls="$7" began="$8" outcome="$9"
    local trigger lag=-1 now

    now="$(now_epoch)"
    if [[ -n "$dir" ]]; then
        trigger="$(incident_meta_get "$dir" started_epoch 0)"
        [[ "$trigger" -gt 0 ]] && lag=$((began - trigger))
    fi

    {
        printf '\n\n===== rapid D-state sampler stats =====\n'
        printf 'dstate_sampler samples=%s interval=%s window_s=%s unique_pids=%s stacks=%s syscalls=%s trigger_lag_s=%s duration_s=%s\n' \
            "$samples" "$interval" \
            "$(awk -v s="$samples" -v i="$interval" 'BEGIN{printf "%.1f", (s-1)*i}')" \
            "$pids" "$stacks" "$syscalls" "$lag" "$((now - began))"
        printf 'dstate_sampler_outcome %s\n' "$outcome"
    } >>"$file"

    [[ -n "$dir" ]] || return 0
    incident_meta_set "$dir" dstate_sampler_pids "$pids"
    incident_meta_set "$dir" dstate_sampler_samples "$samples"
    incident_meta_set "$dir" dstate_sampler_stacks "$stacks"
    incident_meta_set "$dir" dstate_sampler_syscalls "$syscalls"
    incident_meta_set "$dir" dstate_sampler_lag "$lag"

    # Closest any capture got to the trigger. The analysis uses this to decide
    # whether the per-process evidence describes the event that opened the
    # incident or something that happened long afterwards.
    if [[ "$lag" -ge 0 ]]; then
        local best
        best="$(incident_meta_get "$dir" capture_lag_min "")"
        if [[ -z "$best" || "$lag" -lt "$best" ]]; then
            incident_meta_set "$dir" capture_lag_min "$lag"
        fi
    fi
    return 0
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
#
# PERISHABLE HALF. Blocked tasks and pressure readings survive for seconds, so
# nothing may run ahead of this — see capture_snapshot for the ordering rule.
capture_forensics() {
    local dir="$1"
    local index="$2"
    local file="${dir}/dstate-${index}.log"

    {
        printf 'Server Forensics D-state / Blocking Snapshot\n'
        printf 'snapshot=%s\n' "$index"
        printf 'created_at=%s\n' "$(now_iso)"
    } >"$file"

    # Full process table with wait channels, then rapid D-state sampling — the
    # single most valuable signal for "high load, low CPU". The rapid sampler
    # emits the repeated "D-state only" blocks (and, gated by
    # PANIC_CAPTURE_KERNEL_STACK, the per-PID stacks + syscall).
    run_diag "$file" "ps wchan (all)" ps -eo pid,user,state,wchan:40,comm,args
    capture_dstate_kernel_stacks "$file" "$dir"

    # PSI: how long tasks were actually stalled on I/O, CPU, and memory — the
    # measurement that distinguishes a storage stall from CPU or memory pressure.
    if sf_bool "${PANIC_CAPTURE_PSI:-1}"; then
        capture_psi "$dir" "$file"
    fi

    incident_meta_set "$dir" last_dstate_log "$file"
    log_warn "captured d-state forensics ${index}: ${file}"
}

# CONTEXT HALF. Process tree, schedules and maintenance detection describe
# conditions that persist for minutes, so they run after the perishable capture
# and after the sampling windows. Appends to the same dstate-N.log.
capture_forensics_context() {
    local dir="$1"
    local index="$2"
    local file="${dir}/dstate-${index}.log"

    [[ -f "$file" ]] || return 0

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

    # ---- TIER 1: perishable. Nothing may be added above this. ----------------
    #
    # Ordering here is not cosmetic. Blocked tasks unblock within seconds, so
    # every command that runs before the D-state capture is subtracted from the
    # chance of catching one. Production incident-20260728-143130 was triggered
    # BY D-state (8 tasks) and caught zero, because `vmstat 1 5` (4s),
    # `iostat -xz 1 3` (2s), `ss -antp` (17s) and `lsof -nP` (6s) ran first and
    # the sampler did not start until 29s after the trigger. Across four
    # consecutive incidents the sampler reported "no D-state processes caught"
    # 8 times out of 8. The evidence was never missing; it had expired.
    #
    # Rule for anything added later: sub-second /proc reads may go here, and
    # everything with a sampling window or a full-/proc walk goes in tier 3.
    if sf_bool "${ENABLE_DSTATE_FORENSICS:-1}"; then
        capture_forensics "$dir" "$index" || log_warn "d-state forensics failed (continuing)"
    fi

    # ---- TIER 2: instantaneous. Single reads, no sampling window. ------------
    run_diag "$file" "date" date
    run_diag "$file" "uptime" uptime
    run_diag "$file" "free -m" free -m
    run_diag "$file" "top -b -n1" top -b -n1
    run_diag "$file" "ps auxfww" ps auxfww

    # Per-process I/O attribution. This is what names the process actually moving
    # bytes, as opposed to naming services that merely exist. It owns a sampling
    # window, so it runs after the perishable capture but before the /proc
    # walkers; the three samplers inside it run concurrently so it costs one
    # window, not three.
    if sf_bool "${ENABLE_IO_FORENSICS:-1}"; then
        capture_io_forensics "$dir" "$index" || log_warn "io forensics failed (continuing)"
    fi

    # ---- TIER 3: sampling windows and full-/proc walks. ----------------------
    run_diag "$file" "vmstat 1 5" vmstat 1 5
    run_diag "$file" "iostat -xz 1 3" iostat -xz 1 3
    run_diag "$file" "df -h" df -h
    run_diag_shell "$file" "dmesg | tail -100" "dmesg | tail -100"
    run_diag "$file" "journalctl --since -5 min" journalctl --since "-5 min" --no-pager

    local -a mysqladmin_base
    mapfile -t mysqladmin_base < <(mysqladmin_base_args)
    run_diag "$file" "mysqladmin processlist" "${mysqladmin_base[@]}" --connect-timeout=2 processlist
    run_diag "$file" "mysqladmin status" "${mysqladmin_base[@]}" --connect-timeout=2 status
    run_diag "$file" "apachectl status" apachectl status

    # Slowest observed collectors, both of which walk every /proc/<pid>/fd on the
    # box: ss -antp measured at 17s and lsof -nP at 6s during a live stall.
    run_diag "$file" "ss -antp" ss -antp
    run_diag "$file" "lsof -nP" lsof -nP

    # Process tree, schedules, maintenance detection — conditions that persist.
    if sf_bool "${ENABLE_DSTATE_FORENSICS:-1}"; then
        capture_forensics_context "$dir" "$index" || log_warn "d-state context failed (continuing)"
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

# The single close path: summary, web attribution, analysis, rotation. Shared by
# the recovery branch of the panic loop and by the watcher's orphan sweep so an
# incident closed either way produces an identical, complete report.
incident_finalize() {
    local dir="$1"
    local metric_line="$2"
    local how="${3:-recovered}"

    incident_close "$dir" "$metric_line"
    web_capture "$dir" || log_warn "web request capture failed"
    analysis_generate "$dir" || log_warn "analysis generation failed"
    log_warn "incident closed (${how}): ${dir}"
    "${SCRIPT_DIR}/rotate.sh" >/dev/null 2>&1 || log_warn "rotation failed"
}

# Closes an incident that is still marked active while the server is healthy.
#
# incident_close was previously reachable only from the panic loop, so any death
# of panic.sh orphaned the incident until the next unhealthy tick wandered in and
# closed it against an unrelated event. That is how incident-20260728-183224 came
# to span 3h27m and be judged on a package-manager burst three hours after its
# trigger, and incident-20260728-143917 3h13m. The watcher sees "healthy" every
# cycle; it is the only component that can notice.
finalize_orphan() {
    local dir metric_line
    dir="$(incident_active_dir)" || return 0

    metric_line="$(collect_metrics_line)"
    printf '%s\n' "$metric_line" >>"$CURRENT_LOG"
    log_warn "closing orphaned incident (server healthy, no active panic): ${dir}"
    incident_finalize "$dir" "$metric_line" "orphan-swept"
}

main() {
    log_init

    local reason="${1:-manual}"
    local metric_line="${2:-}"
    local dir index
    local test_panic=0

    if [[ "$reason" == "--finalize" ]]; then
        finalize_orphan
        return 0
    fi

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

    while true; do
        index="$(incident_reserve_snapshot_index "$dir")"
        incident_update_peaks "$dir" "$metric_line"
        capture_snapshot "$dir" "$index" "$metric_line"

        sleep "$PANIC_SNAPSHOT_INTERVAL"

        metric_line="$(collect_metrics_line)"
        printf '%s\n' "$metric_line" >>"$CURRENT_LOG"
        incident_update_peaks "$dir" "$metric_line"

        if metrics_are_healthy "$metric_line"; then
            incident_finalize "$dir" "$metric_line" "recovered"
            return 0
        fi
    done
}

main "$@"
