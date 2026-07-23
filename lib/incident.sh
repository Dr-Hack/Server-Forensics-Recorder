#!/usr/bin/env bash
# Incident lifecycle helpers.
# shellcheck disable=SC2153,SC2154

active_incident_file() {
    printf '%s\n' "${STATE_DIR}/active_incident"
}

last_closed_file() {
    printf '%s\n' "${STATE_DIR}/last_closed_epoch"
}

incident_meta_set() {
    local incident_dir="$1"
    local key="$2"
    local value="$3"
    printf '%s\n' "$value" >"${incident_dir}/.${key}"
}

incident_meta_get() {
    local incident_dir="$1"
    local key="$2"
    local fallback="${3:-}"
    local path="${incident_dir}/.${key}"

    if [[ -r "$path" ]]; then
        cat "$path"
    else
        printf '%s\n' "$fallback"
    fi
}

incident_active_dir() {
    local active_file
    active_file="$(active_incident_file)"

    if [[ -r "$active_file" ]]; then
        local dir
        dir="$(cat "$active_file")"
        if [[ -d "$dir" ]]; then
            printf '%s\n' "$dir"
            return 0
        fi
    fi

    return 1
}

incident_in_cooldown() {
    local closed_file
    closed_file="$(last_closed_file)"

    [[ -r "$closed_file" ]] || return 1

    local last_closed current_epoch age
    last_closed="$(cat "$closed_file")"
    current_epoch="$(now_epoch)"
    age=$((current_epoch - last_closed))

    [[ "$age" -lt "$PANIC_COOLDOWN" ]]
}

incident_start() {
    local reason="$1"
    local metric_line="$2"
    local id dir started started_epoch

    if incident_active_dir >/dev/null; then
        incident_active_dir
        return 0
    fi

    id="incident-$(now_id)"
    dir="${INCIDENT_DIR}/${id}"
    started="$(now_iso)"
    started_epoch="$(now_epoch)"

    ensure_dir "$dir"
    printf '%s\n' "$dir" >"$(active_incident_file)"

    incident_meta_set "$dir" id "$id"
    incident_meta_set "$dir" started "$started"
    incident_meta_set "$dir" started_epoch "$started_epoch"
    incident_meta_set "$dir" reason "$reason"
    incident_meta_set "$dir" snapshots 0
    incident_meta_set "$dir" peak_load "$(metric_value "$metric_line" load1)"
    incident_meta_set "$dir" peak_lsphp "$(metric_value "$metric_line" lsphp_count)"
    incident_meta_set "$dir" lowest_mem_available "$(metric_value "$metric_line" mem_available_mb)"
    incident_meta_set "$dir" peak_established "$(metric_value "$metric_line" tcp_established)"
    incident_meta_set "$dir" peak_dstate "$(metric_value "$metric_line" dstate_processes)"
    incident_meta_set "$dir" peak_iowait "$(metric_value "$metric_line" iowait_pct)"
    # PSI peaks are captured from /proc/pressure during panic, not from the
    # lightweight metric line, so they start at 0 and are raised by
    # incident_update_psi_peaks as snapshots are taken.
    incident_meta_set "$dir" peak_psi_io_full 0
    incident_meta_set "$dir" peak_psi_cpu_some 0
    incident_meta_set "$dir" peak_psi_mem_full 0
    # Worst single-process disk throughput seen during the incident, raised by
    # io_update_peaks as each snapshot's offender table is ranked. This survives
    # rotation of the verbose per-snapshot captures.
    incident_meta_set "$dir" peak_io_kbs 0
    incident_meta_set "$dir" peak_io_pid none
    incident_meta_set "$dir" peak_io_comm none

    {
        printf 'Incident ID: %s\n' "$id"
        printf 'Started: %s\n' "$started"
        printf 'Reason Triggered: %s\n' "$reason"
        printf '\nInitial lightweight metrics:\n%s\n' "$metric_line"
    } >"${dir}/summary.txt"

    printf '%s\n' "$dir"
}

incident_update_peaks() {
    local dir="$1"
    local metric_line="$2"
    local load1 lsphp mem_available established dstate iowait
    local old_peak_load old_peak_lsphp old_low_mem old_peak_established
    local old_peak_dstate old_peak_iowait

    load1="$(metric_value "$metric_line" load1)"
    lsphp="$(metric_value "$metric_line" lsphp_count)"
    mem_available="$(metric_value "$metric_line" mem_available_mb)"
    established="$(metric_value "$metric_line" tcp_established)"
    dstate="$(metric_value "$metric_line" dstate_processes)"
    iowait="$(metric_value "$metric_line" iowait_pct)"

    old_peak_load="$(incident_meta_get "$dir" peak_load 0)"
    old_peak_lsphp="$(incident_meta_get "$dir" peak_lsphp 0)"
    old_low_mem="$(incident_meta_get "$dir" lowest_mem_available "$mem_available")"
    old_peak_established="$(incident_meta_get "$dir" peak_established 0)"
    old_peak_dstate="$(incident_meta_get "$dir" peak_dstate 0)"
    old_peak_iowait="$(incident_meta_get "$dir" peak_iowait 0)"

    incident_meta_set "$dir" peak_load "$(num_max "${load1:-0}" "${old_peak_load:-0}")"
    incident_meta_set "$dir" peak_lsphp "$(num_max "${lsphp:-0}" "${old_peak_lsphp:-0}")"
    incident_meta_set "$dir" lowest_mem_available "$(num_min "${mem_available:-0}" "${old_low_mem:-0}")"
    incident_meta_set "$dir" peak_established "$(num_max "${established:-0}" "${old_peak_established:-0}")"
    # iowait_pct is NA until a CPU baseline exists; num_max treats NA as 0, so a
    # transient NA never clobbers a real peak.
    incident_meta_set "$dir" peak_dstate "$(num_max "${dstate:-0}" "${old_peak_dstate:-0}")"
    incident_meta_set "$dir" peak_iowait "$(num_max "${iowait:-0}" "${old_peak_iowait:-0}")"
}

# Raises the tracked PSI peaks from a set of avg10 readings. Arguments, in the
# order read_psi_avg10 emits them: io_some io_full cpu_some mem_some mem_full.
# Only the three most diagnostic values are retained as peaks: io "full" (all
# tasks stalled on I/O — storage-bound), cpu "some" (scheduling delay), and mem
# "full" (memory stall). num_max treats the NA sentinel as 0, so a kernel without
# PSI never clobbers a real peak.
incident_update_psi_peaks() {
    local dir="$1"
    local io_full="${3:-NA}"
    local cpu_some="${4:-NA}"
    local mem_full="${6:-NA}"
    local old_io old_cpu old_mem

    old_io="$(incident_meta_get "$dir" peak_psi_io_full 0)"
    old_cpu="$(incident_meta_get "$dir" peak_psi_cpu_some 0)"
    old_mem="$(incident_meta_get "$dir" peak_psi_mem_full 0)"

    incident_meta_set "$dir" peak_psi_io_full "$(num_max "${io_full:-0}" "${old_io:-0}")"
    incident_meta_set "$dir" peak_psi_cpu_some "$(num_max "${cpu_some:-0}" "${old_cpu:-0}")"
    incident_meta_set "$dir" peak_psi_mem_full "$(num_max "${mem_full:-0}" "${old_mem:-0}")"
}

incident_increment_snapshots() {
    local dir="$1"
    local current
    current="$(incident_meta_get "$dir" snapshots 0)"
    current=$((current + 1))
    incident_meta_set "$dir" snapshots "$current"
    printf '%s\n' "$current"
}

incident_close() {
    local dir="$1"
    local final_metric_line="$2"
    local ended ended_epoch started_epoch duration id reason snapshots

    ended="$(now_iso)"
    ended_epoch="$(now_epoch)"
    started_epoch="$(incident_meta_get "$dir" started_epoch "$ended_epoch")"
    duration=$((ended_epoch - started_epoch))
    # Persist the end boundary so the analysis engine can slice current.log to the
    # incident window when reconstructing the timeline.
    incident_meta_set "$dir" ended_epoch "$ended_epoch"
    id="$(incident_meta_get "$dir" id "$(basename "$dir")")"
    reason="$(incident_meta_get "$dir" reason unknown)"
    snapshots="$(incident_meta_get "$dir" snapshots 0)"

    {
        printf 'Incident ID: %s\n' "$id"
        printf 'Started: %s\n' "$(incident_meta_get "$dir" started unknown)"
        printf 'Ended: %s\n' "$ended"
        printf 'Duration: %s seconds\n' "$duration"
        printf 'Peak Load: %s\n' "$(incident_meta_get "$dir" peak_load 0)"
        printf 'Peak lsphp: %s\n' "$(incident_meta_get "$dir" peak_lsphp 0)"
        printf 'Peak D-state Processes: %s\n' "$(incident_meta_get "$dir" peak_dstate 0)"
        printf 'Peak IO Wait: %s%%\n' "$(incident_meta_get "$dir" peak_iowait 0)"
        printf 'Peak PSI io (full avg10): %s\n' "$(incident_meta_get "$dir" peak_psi_io_full 0)"
        printf 'Peak PSI cpu (some avg10): %s\n' "$(incident_meta_get "$dir" peak_psi_cpu_some 0)"
        printf 'Peak PSI memory (full avg10): %s\n' "$(incident_meta_get "$dir" peak_psi_mem_full 0)"
        printf 'Lowest Available Memory: %s MB\n' "$(incident_meta_get "$dir" lowest_mem_available 0)"
        printf 'Peak Connections: %s established\n' "$(incident_meta_get "$dir" peak_established 0)"
        printf 'Reason Triggered: %s\n' "$reason"
        printf 'Snapshots Taken: %s\n' "$snapshots"
        printf 'Top I/O Process: %s (pid %s) at %s kB/s\n' \
            "$(incident_meta_get "$dir" peak_io_comm none)" \
            "$(incident_meta_get "$dir" peak_io_pid none)" \
            "$(incident_meta_get "$dir" peak_io_kbs 0)"
        printf '\nFinal lightweight metrics:\n%s\n' "$final_metric_line"
    } >"${dir}/summary.txt"

    rm -f -- "$(active_incident_file)"
    printf '%s\n' "$ended_epoch" >"$(last_closed_file)"
}
