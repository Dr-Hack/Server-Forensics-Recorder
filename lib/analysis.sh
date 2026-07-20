#!/usr/bin/env bash
# First-pass forensic analysis engine.
#
# Turns the raw evidence captured during panic mode (dstate-*.log, incident
# meta, final metrics) into a human-readable analysis.txt that names the most
# likely responsible subsystem, a confidence level, the supporting evidence, and
# the recommended next investigation step.
#
# Everything here is pure text parsing of files already on disk. It runs once,
# at incident close, never during the live blocking window, so it adds no load
# to a server that is already struggling.
# shellcheck disable=SC2154

# --- evidence extraction -----------------------------------------------------

# Lists the D-state forensic logs for an incident, oldest first.
analysis_dstate_logs() {
    local dir="$1"
    find "$dir" -maxdepth 1 -type f -name 'dstate-*.log' 2>/dev/null | sort
}

# Aggregates one field of the "D-state only" ps sections across every snapshot
# and prints "count<TAB>value" lines, most frequent first. Field 4 is the wait
# channel (wchan); field 5 is the executable (comm). Counting across snapshots
# is deliberate: a channel that shows up in sample after sample is a stronger
# signal than one that appeared once.
analysis_field_counts() {
    local dir="$1"
    local field="$2"
    local -a files=()

    mapfile -t files < <(analysis_dstate_logs "$dir")
    [[ "${#files[@]}" -gt 0 ]] || return 0

    awk -v f="$field" '
        /^===== / { insec = ($0 ~ /D-state only/); next }
        insec && $1 ~ /^[0-9]+$/ {
            v = $f
            if (v != "-" && v != "0" && v != "" && v != "?") c[v]++
        }
        END { for (k in c) printf "%d\t%s\n", c[k], k }
    ' "${files[@]}" | sort -rn
}

# Prints the single most common value and its count as "value<TAB>count", or
# nothing when there is no data.
analysis_top() {
    local dir="$1"
    local field="$2"
    local top count value

    top="$(analysis_field_counts "$dir" "$field" | head -n 1)"
    [[ -n "$top" ]] || return 0

    count="${top%%$'\t'*}"
    value="${top#*$'\t'}"
    printf '%s\t%s\n' "$value" "$count"
}

# Distinct maintenance / package / backup executables detected during the
# incident, one per line. Field 6 of that section is comm.
analysis_maintenance() {
    local dir="$1"
    local -a files=()

    mapfile -t files < <(analysis_dstate_logs "$dir")
    [[ "${#files[@]}" -gt 0 ]] || return 0

    awk '
        /^===== / { insec = ($0 ~ /maintenance\/package/); next }
        insec && $1 ~ /^[0-9]+$/ { print $6 }
    ' "${files[@]}" | sort -u
}

# --- classification ----------------------------------------------------------

# Maps a wait channel to a subsystem token, or empty when unrecognised.
analysis_wchan_subsystem() {
    local w
    w="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    case "$w" in
        *ext4* | *jbd2* | *xfs* | *btrfs* | *writeback* | *balance_dirty* | *wait_on_page* | *filemap* | *folio* | *read_pages* | *do_fsync* | *sync_inode* | *wb_*)
            printf 'Filesystem\n' ;;
        *blk* | *bio* | *scsi* | *nvme* | *io_schedule* | *wbt_wait* | *rq_qos*)
            printf 'Disk\n' ;;
        *nfs* | *rpc* | *sock* | *tcp* | *sk_wait*)
            printf 'Network\n' ;;
        *mutex* | *rwsem* | *down_* | *semaphore* | *futex*)
            printf 'Kernel\n' ;;
        *)
            printf '\n' ;;
    esac
}

# Maps a blocked executable to a subsystem token, or empty when unrecognised.
analysis_comm_subsystem() {
    local c
    c="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    case "$c" in
        *rsync* | *mysqldump* | *xtrabackup* | *mariabackup* | *cpbackup* | *pkgacct* | *jetbackup* | *backup* | tar) printf 'Backup\n' ;;
        mariadbd | mysqld | mysql) printf 'MariaDB\n' ;;
        *httpd* | *apache2* | *lsapi*) printf 'Apache\n' ;;
        *lsphp* | *php-fpm* | php*) printf 'PHP\n' ;;
        *dnf* | *yum* | *rpm* | *packagekit* | *gpg* | *leapp*) printf 'Package manager\n' ;;
        *clamscan* | *freshclam* | *imunify* | *cagefs* | *updatedb* | *mlocate*) printf 'Maintenance\n' ;;
        *jbd2* | *xfsaild* | *flush* | kworker*) printf 'Filesystem\n' ;;
        *kswapd* | *kcompactd* | *khugepaged*) printf 'Memory\n' ;;
        *) printf '\n' ;;
    esac
}

# Runs the weighted-evidence classifier. Populates:
#   SF_SUBSYSTEM   winning subsystem token
#   SF_CONFIDENCE  integer 0-95
#   SF_EVIDENCE[]  human-readable supporting facts
# The model is intentionally transparent: every point added is tied to a named
# signal, so the confidence figure can be explained rather than trusted blindly.
analysis_classify() {
    local dir="$1"
    local metric_line="$2"

    local reason peak_dstate peak_iowait peak_load
    reason="$(incident_meta_get "$dir" reason unknown)"
    peak_dstate="$(incident_meta_get "$dir" peak_dstate 0)"
    peak_iowait="$(incident_meta_get "$dir" peak_iowait 0)"
    peak_load="$(incident_meta_get "$dir" peak_load 0)"

    local cpu_busy threads_running apache_workers
    cpu_busy="$(metric_value "$metric_line" cpu_busy_pct)"
    threads_running="$(metric_value "$metric_line" threads_running)"
    apache_workers="$(metric_value "$metric_line" apache_workers)"

    local top_wchan top_wchan_n top_comm top_comm_n pair
    pair="$(analysis_top "$dir" 4)"
    top_wchan="${pair%%$'\t'*}"
    top_wchan_n="${pair#*$'\t'}"
    [[ "$pair" == *$'\t'* ]] || { top_wchan=""; top_wchan_n=0; }
    pair="$(analysis_top "$dir" 5)"
    top_comm="${pair%%$'\t'*}"
    top_comm_n="${pair#*$'\t'}"
    [[ "$pair" == *$'\t'* ]] || { top_comm=""; top_comm_n=0; }

    declare -A score=()
    SF_EVIDENCE=()

    local sub
    # D-state count is the trigger; record it and, when large, lean on the story.
    if num_gt "${peak_dstate:-0}" 0; then
        SF_EVIDENCE+=("${peak_dstate} D-state (uninterruptible) processes at peak")
    fi

    # Wait channel — the strongest "where is the block" signal.
    if [[ -n "$top_wchan" ]]; then
        SF_EVIDENCE+=("most blocked on wait channel '${top_wchan}' (${top_wchan_n} samples)")
        sub="$(analysis_wchan_subsystem "$top_wchan")"
        [[ -n "$sub" ]] && score["$sub"]=$(( ${score["$sub"]:-0} + 40 ))
    else
        SF_EVIDENCE+=("no readable wait channels captured (kernel may restrict /proc/<pid>/stack)")
    fi

    # Blocked executable — the strongest "what is the block" signal.
    if [[ -n "$top_comm" ]]; then
        SF_EVIDENCE+=("most common blocked executable '${top_comm}' (${top_comm_n} samples)")
        sub="$(analysis_comm_subsystem "$top_comm")"
        [[ -n "$sub" ]] && score["$sub"]=$(( ${score["$sub"]:-0} + 35 ))
    fi

    # Maintenance / package / backup activity is strong corroboration when a
    # matching subsystem is already in play, and a lead in its own right.
    local maint maint_list=""
    while IFS= read -r maint; do
        [[ -n "$maint" ]] || continue
        maint_list+="${maint} "
        sub="$(analysis_comm_subsystem "$maint")"
        [[ -n "$sub" ]] && score["$sub"]=$(( ${score["$sub"]:-0} + 20 ))
    done < <(analysis_maintenance "$dir")
    if [[ -n "$maint_list" ]]; then
        SF_EVIDENCE+=("maintenance/package activity running: ${maint_list% }")
    fi

    # IO wait corroborates storage-bound subsystems.
    if num_gt "${peak_iowait:-0}" 20; then
        SF_EVIDENCE+=("peak IO wait ${peak_iowait}% (storage-bound)")
        score["Filesystem"]=$(( ${score["Filesystem"]:-0} + 15 ))
        score["Disk"]=$(( ${score["Disk"]:-0} + 12 ))
    elif [[ "$peak_iowait" != "NA" ]]; then
        SF_EVIDENCE+=("peak IO wait ${peak_iowait}%")
    fi

    # Trigger reason seeds subsystem hints the D-state data alone may miss.
    case "$reason" in
        *mem_available*)
            score["Memory"]=$(( ${score["Memory"]:-0} + 25 )) ;;
    esac
    case "$reason" in
        *lsphp*) score["PHP"]=$(( ${score["PHP"]:-0} + 20 )) ;;
    esac
    case "$reason" in
        *tcp_established*) score["Network"]=$(( ${score["Network"]:-0} + 12 )) ;;
    esac

    # Low CPU beside high load is the signature of a blocking (not compute) stall.
    if [[ "$cpu_busy" != "NA" && -n "$cpu_busy" ]] && num_lt "$cpu_busy" 30; then
        SF_EVIDENCE+=("CPU only ${cpu_busy}% despite load ${peak_load} — blocking, not compute")
    fi
    if [[ -n "$apache_workers" && "$apache_workers" != "NA" ]]; then
        num_lt "$apache_workers" 50 && SF_EVIDENCE+=("Apache near-idle (${apache_workers} workers)")
    fi
    if [[ -n "$threads_running" && "$threads_running" != "NA" ]]; then
        num_lt "$threads_running" 4 && SF_EVIDENCE+=("MariaDB near-idle (${threads_running} threads running)")
    fi

    # Pick the winner and derive an explainable confidence.
    local best="" best_score=0 total=0 k
    for k in "${!score[@]}"; do
        total=$(( total + score["$k"] ))
        if [[ "${score[$k]}" -gt "$best_score" ]]; then
            best_score="${score[$k]}"
            best="$k"
        fi
    done

    if [[ -z "$best" || "$total" -eq 0 ]]; then
        SF_SUBSYSTEM="Unknown"
        SF_CONFIDENCE=30
        return 0
    fi

    local conf=$(( best_score * 100 / total ))
    # Corroboration bonus when independent signals agree with the winner.
    if [[ "$cpu_busy" != "NA" && -n "$cpu_busy" ]] && num_lt "$cpu_busy" 30; then
        conf=$(( conf + 5 ))
    fi
    if num_gt "${peak_iowait:-0}" 20; then
        case "$best" in
            Filesystem | Disk | MariaDB | Backup) conf=$(( conf + 5 )) ;;
        esac
    fi
    (( conf < 35 )) && conf=35
    (( conf > 95 )) && conf=95

    SF_SUBSYSTEM="$best"
    SF_CONFIDENCE="$conf"
}

# Recommended next investigation steps, keyed to the winning subsystem. Printed
# one per line.
analysis_next_steps() {
    case "$1" in
        Filesystem)
            printf 'Check dmesg for filesystem/journal errors (ext4/jbd2/xfs)\n'
            printf 'Run iostat -x 1: inspect %%util and await on the busy device\n'
            printf 'Identify the mount under pressure and what is writing to it\n'
            printf 'Correlate the incident window with backup/snapshot schedules\n'
            ;;
        Disk)
            printf 'Run iostat -x 1 and look for a device at ~100%% util with high await\n'
            printf 'Check dmesg and smartctl -a for I/O errors or a failing disk\n'
            printf 'If cloud/SAN, check for throttled IOPS or a noisy neighbour\n'
            ;;
        MariaDB)
            printf 'Capture SHOW ENGINE INNODB STATUS during the next incident\n'
            printf 'Review the slow query log and check for a long-running transaction\n'
            printf 'Check disk latency under the datadir; MariaDB stalls follow storage\n'
            ;;
        Apache)
            printf 'Enable/collect mod_status to see BusyWorkers vs a backend stall\n'
            printf 'Check whether workers are blocked on a slow backend (PHP/DB/disk)\n'
            ;;
        PHP)
            printf 'Inspect lsphp process ages and args for a stuck script or endpoint\n'
            printf 'Check the slowest site/vhost and any external calls it makes\n'
            ;;
        Backup)
            printf 'Confirm the backup window (cPanel/JetBackup/rsync) vs incident time\n'
            printf 'Throttle backup I/O (ionice/nice) or reschedule off peak\n'
            ;;
        'Package manager')
            printf 'Check dnf/yum history and cPanel upcp timing vs the incident\n'
            printf 'Look for an unattended update or a stuck rpm transaction/lock\n'
            ;;
        Maintenance)
            printf 'Identify the scan (ClamAV/Imunify/updatedb) and its schedule\n'
            printf 'Throttle or reschedule it off peak; exclude large hot paths\n'
            ;;
        Memory)
            printf 'Check for swap thrash and kswapd/kcompactd activity in the samples\n'
            printf 'Review the top memory consumers and any OOM events in dmesg\n'
            ;;
        Network)
            printf 'Check for NFS/remote mount stalls or socket exhaustion\n'
            printf 'Inspect ss -s and connection churn during the window\n'
            ;;
        Kernel)
            printf 'Kernel lock contention: capture /proc/<pid>/stack for the blocked set\n'
            printf 'Check dmesg for hung-task warnings and correlate the common stack\n'
            ;;
        *)
            printf 'Inspect the newest dstate-*.log for the blocked process set\n'
            printf 'Ensure the recorder runs as root so kernel stacks are captured\n'
            ;;
    esac
}

# --- output ------------------------------------------------------------------

# Generates analysis.txt for an incident and appends a condensed headline to
# summary.txt. Safe to call even when no D-state logs were captured.
analysis_generate() {
    local dir="$1"
    local metric_line="${2:-}"
    local file="${dir}/analysis.txt"
    local id
    id="$(incident_meta_get "$dir" id "$(basename "$dir")")"

    SF_SUBSYSTEM="Unknown"
    SF_CONFIDENCE=30
    SF_EVIDENCE=()
    analysis_classify "$dir" "$metric_line"

    local top_wchan_pair top_comm_pair maint_list
    top_wchan_pair="$(analysis_top "$dir" 4)"
    top_comm_pair="$(analysis_top "$dir" 5)"
    maint_list="$(analysis_maintenance "$dir" | tr '\n' ' ')"

    {
        printf 'Server Forensics Incident Analysis\n'
        printf 'Incident: %s\n' "$id"
        printf 'Generated: %s\n' "$(now_iso)"
        printf '\n'
        printf 'Likely Cause:\n%s\n' "$SF_SUBSYSTEM"
        printf '\n'
        printf 'Confidence:\n%s%%\n' "$SF_CONFIDENCE"
        printf '\n'
        printf 'Evidence:\n'
        if [[ "${#SF_EVIDENCE[@]}" -gt 0 ]]; then
            local ev
            for ev in "${SF_EVIDENCE[@]}"; do
                printf '  - %s\n' "$ev"
            done
        else
            printf '  - insufficient forensic detail was captured\n'
        fi
        printf '\n'
        printf 'Blocking detail:\n'
        printf '  - Peak D-state processes: %s\n' "$(incident_meta_get "$dir" peak_dstate 0)"
        printf '  - Peak IO wait: %s%%\n' "$(incident_meta_get "$dir" peak_iowait 0)"
        printf '  - Peak load: %s\n' "$(incident_meta_get "$dir" peak_load 0)"
        if [[ -n "$top_wchan_pair" ]]; then
            printf '  - Most common wait channel: %s (%s samples)\n' \
                "${top_wchan_pair%%$'\t'*}" "${top_wchan_pair#*$'\t'}"
        fi
        if [[ -n "$top_comm_pair" ]]; then
            printf '  - Most common blocked executable: %s (%s samples)\n' \
                "${top_comm_pair%%$'\t'*}" "${top_comm_pair#*$'\t'}"
        fi
        if [[ -n "${maint_list// /}" ]]; then
            printf '  - Maintenance/package activity: %s\n' "${maint_list% }"
        fi
        printf '\n'
        printf 'Recommended next investigation:\n'
        analysis_next_steps "$SF_SUBSYSTEM" | while IFS= read -r step; do
            printf '  - %s\n' "$step"
        done
        printf '\n'
        printf 'Note: automated first-pass classification from captured evidence.\n'
        printf 'Confirm against the raw snapshot-*.log and dstate-*.log before acting.\n'
    } >"$file"

    # Fold a one-line verdict into the incident summary for quick scanning.
    if [[ -w "${dir}/summary.txt" || -e "${dir}/summary.txt" ]]; then
        {
            printf '\nLikely Cause: %s (confidence %s%%)\n' "$SF_SUBSYSTEM" "$SF_CONFIDENCE"
            printf 'See analysis.txt for evidence and next steps.\n'
        } >>"${dir}/summary.txt"
    fi

    printf '%s\n' "$file"
}
