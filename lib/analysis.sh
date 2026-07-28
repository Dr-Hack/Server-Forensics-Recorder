#!/usr/bin/env bash
# Evidence-based forensic analysis engine.
#
# Turns the raw evidence captured during panic mode (dstate-*.log with wchan,
# kernel stacks and PSI, the incident meta peaks, and the current.log samples
# spanning the incident window) into a human-readable analysis.txt that reasons
# like a Linux incident investigator. It deliberately separates:
#
#     Observed  ->  Inference  ->  Evidence ledger  ->  Confidence
#               ->  Proven / Inferred / Unknown  ->  Timeline
#               ->  Recurring patterns  ->  Next steps  ->  Missing evidence
#
# The confidence distribution is GATED by missing evidence: when the decisive
# kernel signals (wait channel, blocked stack) were not captured, specific-cause
# confidence is capped and the cap is stated explicitly. The reporter never
# claims certainty it cannot support and never reaches 100%.
#
# Everything here is pure text parsing of files already on disk. It runs once, at
# incident close, never during the live blocking window, so it adds no load to a
# server that is already struggling.
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

# True when two process names refer to the same executable. `ps comm` truncates
# to 15 characters and pidstat may report a slightly different form, so a plain
# equality test would miss real matches; prefix containment in either direction
# is the usable comparison.
analysis_comm_matches() {
    local a b
    a="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    b="$(printf '%s' "${2:-}" | tr '[:upper:]' '[:lower:]')"

    [[ -n "$a" && -n "$b" ]] || return 1
    # Compare on the executable only; pidstat can append state text such as
    # "lfd - sleeping".
    b="${b%% *}"
    [[ -n "$b" ]] || return 1
    [[ "$a" == "$b" || "$a" == "$b"* || "$b" == "$a"* ]]
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

# True when at least one readable kernel wait channel was captured for a D-state
# process (the top wchan is non-empty). The strongest "where is the block" proof.
analysis_wchan_present() {
    local dir="$1"
    [[ -n "$(analysis_top "$dir" 4)" ]]
}

# True when at least one real kernel stack frame was captured. /proc/<pid>/stack
# frames carry a "+0x<offset>"; the unavailable sentinels do not.
analysis_stack_present() {
    local dir="$1"
    local -a files=()
    mapfile -t files < <(analysis_dstate_logs "$dir")
    [[ "${#files[@]}" -gt 0 ]] || return 1
    grep -qE '\+0x[0-9a-fA-F]+' "${files[@]}" 2>/dev/null
}

# True when PSI was captured at all (a "some"/"full avg10=" line is present).
analysis_psi_present() {
    local dir="$1"
    local -a files=()
    mapfile -t files < <(analysis_dstate_logs "$dir")
    [[ "${#files[@]}" -gt 0 ]] || return 1
    grep -qE 'avg10=' "${files[@]}" 2>/dev/null
}

# --- classification maps -----------------------------------------------------

# Maps a wait channel to a subsystem token, or empty when unrecognised.
analysis_wchan_subsystem() {
    local w
    w="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    case "$w" in
        *ext4* | *jbd2* | *xfs* | *btrfs* | *writeback* | *balance_dirty* | *wait_on_page* | *filemap* | *folio* | *read_pages* | *do_fsync* | *sync_inode* | *wb_*)
            printf 'Filesystem\n'
            ;;
        *blk* | *bio* | *scsi* | *nvme* | *io_schedule* | *wbt_wait* | *rq_qos*)
            printf 'Disk\n'
            ;;
        *nfs* | *rpc* | *sock* | *tcp* | *sk_wait*)
            printf 'Network\n'
            ;;
        *mutex* | *rwsem* | *down_* | *semaphore* | *futex*)
            printf 'Kernel\n'
            ;;
        *)
            printf '\n'
            ;;
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
        *dnf* | *yum* | *rpm* | *packagekit* | *leapp* | *upcp*) printf 'Package manager\n' ;;
        *clamscan* | *freshclam* | *imunify* | *cagefs* | *updatedb* | *mlocate*) printf 'Maintenance\n' ;;
        *jbd2* | *xfsaild* | *flush* | kworker*) printf 'Filesystem\n' ;;
        *kswapd* | *kcompactd* | *khugepaged*) printf 'Memory\n' ;;
        *) printf '\n' ;;
    esac
}

# Maps a subsystem token to the human hypothesis label used in the distribution.
analysis_subsystem_label() {
    case "$1" in
        CPU) printf 'CPU saturation\n' ;;
        Filesystem) printf 'Filesystem wait\n' ;;
        Disk) printf 'Disk / block layer\n' ;;
        MariaDB) printf 'MariaDB bottleneck\n' ;;
        Apache) printf 'Apache overload\n' ;;
        PHP) printf 'PHP overload\n' ;;
        Memory) printf 'Memory exhaustion\n' ;;
        Network) printf 'Network / remote FS\n' ;;
        Backup) printf 'Maintenance interaction\n' ;;
        Maintenance) printf 'Maintenance interaction\n' ;;
        'Package manager') printf 'Package manager\n' ;;
        Kernel) printf 'Kernel lock contention\n' ;;
        *) printf '\n' ;;
    esac
}

# --- measured offender tables ------------------------------------------------

# Reads the top row of the aggregated CPU or I/O offender ranking for an incident
# and prints "comm<TAB>value<TAB>pid", or nothing when no ranking exists. This is
# the measured counterpart to the process-name pattern matching above: it reports
# what a process actually consumed, not that it was running.
analysis_top_measured() {
    local dir="$1"
    local kind="$2"
    local top

    # lib/ioforensics.sh is sourced alongside this file by the panic path and the
    # CLI, but analysis.sh must stay usable on its own, so the dependency is
    # checked rather than assumed.
    case "$kind" in
        cpu)
            declare -F io_aggregate_cpu >/dev/null 2>&1 || return 0
            top="$(io_aggregate_cpu "$dir" 2>/dev/null | head -n 1)"
            ;;
        *)
            declare -F io_aggregate_offenders >/dev/null 2>&1 || return 0
            top="$(io_aggregate_offenders "$dir" 2>/dev/null | head -n 1)"
            ;;
    esac

    [[ -n "$top" ]] || return 0

    local pid comm total
    IFS=$'\t' read -r pid comm _ _ total _ _ _ <<<"$top"
    [[ -n "$comm" && "$comm" != "?" ]] || return 0
    printf '%s\t%s\t%s\n' "$comm" "$total" "$pid"
}

# The same, but skipping PID 1. init performs writes on behalf of other services
# (journal forwarding, unit state, cgroup bookkeeping), so it tops I/O rankings
# routinely without being a workload. Attributing an incident to it is nearly
# always wrong, so the leader is taken from the first non-init row and PID 1 is
# reported separately with its delegated-activity note.
analysis_top_measured_real() {
    local dir="$1"
    local kind="$2"
    local rows

    case "$kind" in
        cpu)
            declare -F io_aggregate_cpu >/dev/null 2>&1 || return 0
            rows="$(io_aggregate_cpu "$dir" 2>/dev/null)"
            ;;
        *)
            declare -F io_aggregate_offenders >/dev/null 2>&1 || return 0
            rows="$(io_aggregate_offenders "$dir" 2>/dev/null)"
            ;;
    esac
    [[ -n "$rows" ]] || return 0

    local pid comm total
    while IFS=$'\t' read -r pid comm _ _ total _ _ _; do
        [[ -n "$pid" ]] || continue
        [[ "$pid" == "1" ]] && continue
        [[ -n "$comm" && "$comm" != "?" ]] || continue
        printf '%s\t%s\t%s\n' "$comm" "$total" "$pid"
        return 0
    done <<<"$rows"

    return 0
}

# True when PID 1 leads the I/O ranking, so the report can say why that is not
# an accusation.
analysis_pid1_leads_io() {
    local dir="$1"
    local top

    declare -F io_aggregate_offenders >/dev/null 2>&1 || return 1
    top="$(io_aggregate_offenders "$dir" 2>/dev/null | head -n 1)"
    [[ -n "$top" ]] || return 1
    [[ "${top%%$'\t'*}" == "1" ]]
}

# --- window statistics -------------------------------------------------------

# Parses current.log for the samples inside the incident window and sets globals
# describing what actually happened while load was high, rather than trusting the
# single (already-recovered) final metric line:
#   W_SAMPLES     number of samples found in the window
#   W_MAX_LOAD    peak load1
#   W_CPU_AT_PEAK cpu_busy_pct on the peak-load sample (NA if that sample had none)
#   W_MIN_CPU     lowest non-NA cpu_busy_pct
#   W_MAX_IOWAIT  peak iowait_pct
#   W_MAX_DSTATE  peak dstate_processes
#   W_MIN_APACHE  lowest apache_workers seen
#   W_MIN_DBTHR   lowest non-NA threads_running seen
analysis_window_stats() {
    local dir="$1"
    local start end log
    start="$(incident_meta_get "$dir" started_epoch 0)"
    end="$(incident_meta_get "$dir" ended_epoch 0)"
    log="${CURRENT_LOG:-}"

    W_SAMPLES=0
    W_MAX_LOAD="$(incident_meta_get "$dir" peak_load 0)"
    W_CPU_AT_PEAK="NA"
    W_MIN_CPU="NA"
    W_MAX_IOWAIT="$(incident_meta_get "$dir" peak_iowait 0)"
    W_MAX_DSTATE="$(incident_meta_get "$dir" peak_dstate 0)"
    W_MIN_APACHE="NA"
    W_MIN_DBTHR="NA"

    [[ -n "$log" && -r "$log" ]] || return 0
    [[ "$end" -gt 0 ]] || end=9999999999

    local stats
    stats="$(awk -v start="$start" -v end="$end" '
        function field(line, key,   n, i, a, kv) {
            n = split(line, a, " ")
            for (i = 1; i <= n; i++) {
                if (index(a[i], key "=") == 1) { kv = a[i]; sub(key "=", "", kv); return kv }
            }
            return ""
        }
        {
            ep = field($0, "epoch") + 0
            if (ep < start - 90 || ep > end + 90) next
            n++
            load = field($0, "load1") + 0
            cpu = field($0, "cpu_busy_pct")
            iow = field($0, "iowait_pct")
            ds  = field($0, "dstate_processes") + 0
            aw  = field($0, "apache_workers")
            db  = field($0, "threads_running")
            if (load > maxload) { maxload = load; cpuatpeak = cpu }
            if (cpu != "NA" && cpu != "") { c = cpu + 0; if (!seencpu || c < mincpu) { mincpu = c; seencpu = 1 } }
            if (iow != "NA" && iow != "") { w = iow + 0; if (w > maxiow) maxiow = w }
            if (ds > maxds) maxds = ds
            if (aw != "NA" && aw != "") { a = aw + 0; if (!seenaw || a < minaw) { minaw = a; seenaw = 1 } }
            if (db != "NA" && db != "") { d = db + 0; if (!seendb || d < mindb) { mindb = d; seendb = 1 } }
        }
        END {
            printf "%d|%s|%s|%s|%s|%s|%s|%s\n", n, maxload+0, \
                (cpuatpeak == "" ? "NA" : cpuatpeak), \
                (seencpu ? mincpu : "NA"), maxiow+0, maxds+0, \
                (seenaw ? minaw : "NA"), (seendb ? mindb : "NA")
        }
    ' "$log" 2>/dev/null)"

    [[ -n "$stats" ]] || return 0
    IFS='|' read -r W_SAMPLES W_MAX_LOAD W_CPU_AT_PEAK W_MIN_CPU W_MAX_IOWAIT \
        W_MAX_DSTATE W_MIN_APACHE W_MIN_DBTHR <<<"$stats"
    # Prefer the retained meta peaks when the window scan found nothing bigger.
    W_MAX_LOAD="$(num_max "$W_MAX_LOAD" "$(incident_meta_get "$dir" peak_load 0)")"
    W_MAX_IOWAIT="$(num_max "$W_MAX_IOWAIT" "$(incident_meta_get "$dir" peak_iowait 0)")"
    W_MAX_DSTATE="$(num_max "$W_MAX_DSTATE" "$(incident_meta_get "$dir" peak_dstate 0)")"
}

# --- confidence model --------------------------------------------------------

# The full hypothesis list, always printed so ruled-out causes stay visible.
# "Blocked (uninterruptible) tasks" is the mechanism, not a root cause, and is
# scored/gated separately from the specific-cause hypotheses.
SF_HYPOTHESES=(
    "Blocked (uninterruptible) tasks"
    "CPU saturation"
    "Filesystem wait"
    "Disk / block layer"
    "MariaDB bottleneck"
    "Apache overload"
    "PHP overload"
    "Memory exhaustion"
    "Network / remote FS"
    "Maintenance interaction"
    "Package manager"
    "Kernel lock contention"
)

# Hypotheses that can only ever be supported by *presence* of a named process
# unless a measurement corroborates them. Presence is correlation: on a cPanel
# box the Imunify360 daemons, gpg-agent and friends are resident 24/7, so their
# appearance in the process table carries no information about any specific
# incident. These are capped below SF_INCONCLUSIVE_FLOOR until a measured
# offender table shows the same process actually consuming CPU or I/O.
SF_PRESENCE_HYPOTHESES=(
    "Maintenance interaction"
    "Package manager"
)

# A specific cause must clear this to be named at all.
SF_INCONCLUSIVE_FLOOR=15

sf_is_presence_hypothesis() {
    local h
    for h in "${SF_PRESENCE_HYPOTHESES[@]}"; do
        [[ "$h" == "$1" ]] && return 0
    done
    return 1
}

# The mechanism hypothesis, referenced by name in several places. Kept in a
# variable so array subscripts never contain a literal '(' (which the formatter's
# parser cannot handle in a bare subscript).
SF_MECH="Blocked (uninterruptible) tasks"

sf_add() {
    # $1 label, $2 points
    local label="$1"
    SF_SCORE["$label"]=$((${SF_SCORE["$label"]:-0} + $2))
}

# Runs the weighted-evidence classifier. Every point is tied to a named signal so
# the resulting distribution is explainable rather than trusted blindly.
# Populates: SF_SCORE[] SF_PCT[] SF_CAP_SPECIFIC SF_LEADER SF_LEADER_PCT
#            SF_EVIDENCE[] and the boolean flags used by the ledger.
analysis_classify() {
    local dir="$1"

    declare -gA SF_SCORE=()
    declare -gA SF_PCT=()
    SF_EVIDENCE=()

    local peak_dstate peak_iowait reason
    peak_dstate="$(incident_meta_get "$dir" peak_dstate 0)"
    peak_iowait="$(incident_meta_get "$dir" peak_iowait 0)"
    reason="$(incident_meta_get "$dir" reason unknown)"

    local psi_io psi_cpu psi_mem
    psi_io="$(incident_meta_get "$dir" peak_psi_io_full 0)"
    psi_cpu="$(incident_meta_get "$dir" peak_psi_cpu_some 0)"
    psi_mem="$(incident_meta_get "$dir" peak_psi_mem_full 0)"

    analysis_window_stats "$dir"

    # Evidence availability decides how far specific-cause confidence may go.
    SF_WCHAN_PRESENT=0
    analysis_wchan_present "$dir" && SF_WCHAN_PRESENT=1
    SF_STACK_PRESENT=0
    analysis_stack_present "$dir" && SF_STACK_PRESENT=1
    SF_PSI_PRESENT=0
    analysis_psi_present "$dir" && SF_PSI_PRESENT=1

    # Priors — small, so a hypothesis with no supporting evidence stays near the
    # floor instead of reading as a real possibility.
    local -A prior=(
        ["Blocked (uninterruptible) tasks"]=10
        ["CPU saturation"]=4
        ["Filesystem wait"]=8
        ["Disk / block layer"]=6
        ["MariaDB bottleneck"]=3
        ["Apache overload"]=2
        ["PHP overload"]=4
        ["Memory exhaustion"]=3
        ["Network / remote FS"]=3
        ["Maintenance interaction"]=5
        ["Package manager"]=3
        ["Kernel lock contention"]=4
    )
    local h
    for h in "${SF_HYPOTHESES[@]}"; do SF_SCORE["$h"]="${prior[$h]}"; done

    # --- mechanism: were tasks genuinely blocked? -----------------------------
    local dstate_pts=0
    if num_gt "${peak_dstate:-0}" 0; then
        dstate_pts=$((peak_dstate * 4))
        ((dstate_pts > 60)) && dstate_pts=60
        sf_add "Blocked (uninterruptible) tasks" "$dstate_pts"
        SF_EVIDENCE+=("${peak_dstate} process(es) in uninterruptible D-state at peak")
    fi

    local low_cpu=0 cpu_show="$W_CPU_AT_PEAK"
    [[ "$cpu_show" == "NA" || -z "$cpu_show" ]] && cpu_show="$W_MIN_CPU"
    if [[ "$cpu_show" != "NA" && -n "$cpu_show" ]] && num_lt "$cpu_show" 30 && num_gt "${W_MAX_LOAD:-0}" 0; then
        low_cpu=1
        sf_add "Blocked (uninterruptible) tasks" 25
        SF_EVIDENCE+=("CPU only ${cpu_show}% at load ${W_MAX_LOAD} — blocking, not compute")
    fi

    # --- compute-bound: the mirror image of the above -------------------------
    # Without this the engine cannot express "the box was simply busy", and a
    # CPU-bound spike falls through to whatever noise-floor hypothesis is left.
    SF_CPU_BOUND=0
    if [[ "$cpu_show" != "NA" && -n "$cpu_show" ]]; then
        if num_gt "$cpu_show" 70; then
            SF_CPU_BOUND=1
            sf_add "CPU saturation" 40
            SF_EVIDENCE+=("CPU ${cpu_show}% at load ${W_MAX_LOAD} — compute-bound, not blocking")
        elif num_gt "$cpu_show" 50; then
            SF_CPU_BOUND=1
            sf_add "CPU saturation" 25
            SF_EVIDENCE+=("CPU ${cpu_show}% at load ${W_MAX_LOAD} — substantially compute-bound")
        fi
    fi

    # A single process holding a core is the strongest CPU evidence there is, and
    # unlike a process name it is a measurement.
    SF_TOP_CPU_COMM=""
    SF_TOP_CPU_PCT=0
    SF_TOP_CPU_PID=""
    local cpu_row
    cpu_row="$(analysis_top_measured "$dir" cpu)"
    if [[ -n "$cpu_row" ]]; then
        IFS=$'\t' read -r SF_TOP_CPU_COMM SF_TOP_CPU_PCT SF_TOP_CPU_PID <<<"$cpu_row"
        SF_EVIDENCE+=("top CPU process '${SF_TOP_CPU_COMM}' (pid ${SF_TOP_CPU_PID}) at ${SF_TOP_CPU_PCT}% CPU")
        if num_gt "${SF_TOP_CPU_PCT:-0}" 80; then
            sf_add "CPU saturation" 30
        elif num_gt "${SF_TOP_CPU_PCT:-0}" 40; then
            sf_add "CPU saturation" 15
        fi
    fi

    # The measured I/O leader, excluding PID 1 for the reason documented on
    # analysis_top_measured_real.
    SF_TOP_IO_COMM=""
    SF_TOP_IO_KBS=0
    SF_TOP_IO_PID=""
    SF_PID1_LEADS_IO=0
    analysis_pid1_leads_io "$dir" && SF_PID1_LEADS_IO=1
    local io_row
    io_row="$(analysis_top_measured_real "$dir" io)"
    if [[ -n "$io_row" ]]; then
        IFS=$'\t' read -r SF_TOP_IO_COMM SF_TOP_IO_KBS SF_TOP_IO_PID <<<"$io_row"
        SF_EVIDENCE+=("top I/O process '${SF_TOP_IO_COMM}' (pid ${SF_TOP_IO_PID}) at ${SF_TOP_IO_KBS} kB/s")
    fi
    if [[ "$SF_PID1_LEADS_IO" -eq 1 ]]; then
        SF_EVIDENCE+=("PID 1 (init) led the I/O ranking — it writes on behalf of other services (journal, unit state), so this is delegated activity and not a cause; see the PID 1 note in io-*.log")
    fi

    # --- distributed load: no single PID explains the spike -------------------
    # Without this, a worker-pool incident reads as "nothing was using the CPU"
    # because the largest single process is small.
    SF_DISTRIBUTED=0
    if declare -F agg_distributed_notice >/dev/null 2>&1; then
        if agg_distributed_notice "$cpu_show" "${SF_TOP_CPU_PCT:-0}" >/dev/null 2>&1; then
            SF_DISTRIBUTED=1
            sf_add "CPU saturation" 15
            SF_EVIDENCE+=("CPU usage is distributed across multiple processes; inspect aggregated executable totals rather than individual PIDs")
        fi
    fi

    # --- where is the block? wait channel is the strongest signal -------------
    local top_wchan top_wchan_n pair sub label
    pair="$(analysis_top "$dir" 4)"
    top_wchan="${pair%%$'\t'*}"
    top_wchan_n="${pair#*$'\t'}"
    [[ "$pair" == *$'\t'* ]] || {
        top_wchan=""
        top_wchan_n=0
    }
    if [[ -n "$top_wchan" ]]; then
        SF_EVIDENCE+=("most blocked on wait channel '${top_wchan}' (${top_wchan_n} samples)")
        sub="$(analysis_wchan_subsystem "$top_wchan")"
        label="$(analysis_subsystem_label "$sub")"
        [[ -n "$label" ]] && sf_add "$label" 40
    else
        SF_EVIDENCE+=("no readable wait channels captured (needs root / permitted kernel)")
    fi

    # --- what is the block? the blocked executable ----------------------------
    local top_comm top_comm_n
    pair="$(analysis_top "$dir" 5)"
    top_comm="${pair%%$'\t'*}"
    top_comm_n="${pair#*$'\t'}"
    [[ "$pair" == *$'\t'* ]] || {
        top_comm=""
        top_comm_n=0
    }
    if [[ -n "$top_comm" ]]; then
        SF_EVIDENCE+=("most common blocked executable '${top_comm}' (${top_comm_n} samples)")
        sub="$(analysis_comm_subsystem "$top_comm")"
        case "$sub" in
            Backup)
                sf_add "Maintenance interaction" 30
                sf_add "Filesystem wait" 12
                ;;
            Maintenance)
                sf_add "Maintenance interaction" 25
                sf_add "Filesystem wait" 8
                ;;
            'Package manager')
                sf_add "Package manager" 25
                ;;
            "")
                :
                ;;
            *)
                label="$(analysis_subsystem_label "$sub")"
                [[ -n "$label" ]] && sf_add "$label" 30
                ;;
        esac
    fi

    # --- maintenance / package / backup present ------------------------------
    # Present-but-not-proven: running maintenance is correlation, not causation,
    # so it earns only modest points. This is the exact weakness this rewrite is
    # meant to fix ("Imunify running -> Maintenance" is not sufficient evidence).
    local maint maint_list=""
    SF_IMUNIFY=0
    SF_PKGMGR=0
    SF_BACKUP=0
    SF_MAINT_CORROBORATED=0
    while IFS= read -r maint; do
        [[ -n "$maint" ]] || continue
        maint_list+="${maint} "
        case "$(printf '%s' "$maint" | tr '[:upper:]' '[:lower:]')" in
            *imunify*) SF_IMUNIFY=1 ;;
        esac
        sub="$(analysis_comm_subsystem "$maint")"
        case "$sub" in
            Backup) SF_BACKUP=1 ;;
            'Package manager') SF_PKGMGR=1 ;;
        esac

        # Presence alone scores almost nothing. It becomes real evidence only if
        # the SAME process shows up in a measured offender table — i.e. it was
        # actually burning CPU or moving bytes during the window.
        if analysis_comm_matches "$maint" "$SF_TOP_CPU_COMM" \
            || analysis_comm_matches "$maint" "$SF_TOP_IO_COMM"; then
            SF_MAINT_CORROBORATED=1
            case "$sub" in
                Backup | Maintenance) sf_add "Maintenance interaction" 35 ;;
                'Package manager') sf_add "Package manager" 35 ;;
            esac
            SF_EVIDENCE+=("maintenance process '${maint}' is ALSO the measured top consumer — corroborated")
        else
            case "$sub" in
                Backup | Maintenance) sf_add "Maintenance interaction" 2 ;;
                'Package manager') sf_add "Package manager" 2 ;;
            esac
        fi
    done < <(analysis_maintenance "$dir")
    if [[ -n "$maint_list" ]]; then
        if [[ "$SF_MAINT_CORROBORATED" -eq 1 ]]; then
            SF_EVIDENCE+=("maintenance/package/backup processes present: ${maint_list% }")
        else
            SF_EVIDENCE+=("maintenance/package/backup processes present but NONE consumed measurable CPU or I/O: ${maint_list% } (presence is not evidence)")
        fi
    fi

    # --- IO wait corroborates storage-bound causes ----------------------------
    if num_gt "${peak_iowait:-0}" 20; then
        SF_EVIDENCE+=("peak IO wait ${peak_iowait}% (storage-bound)")
        sf_add "Filesystem wait" 15
        sf_add "Disk / block layer" 12
        num_gt "${peak_iowait:-0}" 40 && {
            sf_add "Filesystem wait" 8
            sf_add "Disk / block layer" 6
        }
    elif [[ "$peak_iowait" != "NA" ]]; then
        SF_EVIDENCE+=("peak IO wait ${peak_iowait}%")
    fi

    # --- PSI: the direct measurement of how long tasks were stalled -----------
    if [[ "$SF_PSI_PRESENT" -eq 1 ]]; then
        if num_gt "${psi_io:-0}" 20; then
            SF_EVIDENCE+=("PSI io full avg10 ${psi_io} — tasks genuinely stalled on I/O")
            sf_add "Filesystem wait" 20
            sf_add "Disk / block layer" 15
            sf_add "Blocked (uninterruptible) tasks" 10
        fi
        if num_gt "${psi_mem:-0}" 10; then
            SF_EVIDENCE+=("PSI memory full avg10 ${psi_mem} — memory stall")
            sf_add "Memory exhaustion" 30
            sf_add "Blocked (uninterruptible) tasks" 8
        fi
        if num_gt "${psi_cpu:-0}" 40 && [[ "$low_cpu" -eq 0 ]]; then
            SF_EVIDENCE+=("PSI cpu some avg10 ${psi_cpu} — CPU scheduling delay")
            sf_add "Kernel lock contention" 8
        fi
    else
        SF_EVIDENCE+=("PSI not captured (kernel lacks CONFIG_PSI or capture disabled)")
    fi

    # --- trigger reason seeds hints the D-state data alone may miss -----------
    case "$reason" in
        *mem_available*) sf_add "Memory exhaustion" 25 ;;
    esac
    case "$reason" in
        *lsphp*) sf_add "PHP overload" 20 ;;
    esac
    case "$reason" in
        *tcp_established*) sf_add "Network / remote FS" 12 ;;
    esac

    # --- evidence against the application tiers -------------------------------
    if [[ "$W_MIN_APACHE" != "NA" && -n "$W_MIN_APACHE" ]] && num_lt "$W_MIN_APACHE" 50; then
        SF_EVIDENCE+=("Apache near-idle (${W_MIN_APACHE} workers) — not an Apache overload")
    fi
    if [[ "$W_MIN_DBTHR" != "NA" && -n "$W_MIN_DBTHR" ]] && num_lt "$W_MIN_DBTHR" 4; then
        SF_EVIDENCE+=("MariaDB near-idle (${W_MIN_DBTHR} threads running) — not a DB bottleneck")
    fi

    # --- caps and conversion to percentages -----------------------------------
    # Specific causes cannot be proven without pinning the layer. If the kernel
    # withheld both wchan and stack, cap them; PSI proves the *class* of stall so
    # it lifts the cap partway.
    if [[ "$SF_WCHAN_PRESENT" -eq 1 || "$SF_STACK_PRESENT" -eq 1 ]]; then
        SF_CAP_SPECIFIC=95
    elif [[ "$SF_PSI_PRESENT" -eq 1 ]]; then
        SF_CAP_SPECIFIC=80
    else
        SF_CAP_SPECIFIC=65
    fi

    # Stale-capture guard. Per-process evidence is only evidence OF the incident
    # if it was measured near the incident. On production
    # incident-20260728-183224 the sole snapshot landed 3h27m after the trigger,
    # during an unrelated nightly dnf run, and the report named "Package manager"
    # as the cause of a storage stall that had happened three hours earlier —
    # while the incident's own facts (13.3% CPU at load 21.79, 81.8% iowait)
    # described the original event. Two different events, one verdict.
    SF_CAPTURE_STALE=0
    SF_CAPTURE_LAG_MIN="$(incident_meta_get "$dir" capture_lag_min "")"
    if [[ -n "$SF_CAPTURE_LAG_MIN" ]] && num_gt "$SF_CAPTURE_LAG_MIN" "${STALE_CAPTURE_SECONDS:-300}"; then
        SF_CAPTURE_STALE=1
        # The mechanism (blocked vs compute) still comes from the lightweight
        # samples, which span the whole window, so it survives. Everything that
        # depends on the offender tables does not.
        SF_CAP_SPECIFIC="$SF_INCONCLUSIVE_FLOOR"
    fi

    # CPU saturation is measured directly from cpu_busy_pct and the per-process
    # CPU ranking, so it does not depend on the kernel signals that gate the
    # storage-side hypotheses and is not capped by their absence.
    local cap pct
    for h in "${SF_HYPOTHESES[@]}"; do
        if [[ "$h" == "$SF_MECH" || "$h" == "CPU saturation" ]]; then
            cap=90
        elif sf_is_presence_hypothesis "$h"; then
            # Uncorroborated presence can never clear the floor, so it can never
            # be named as the cause. Corroboration by a measured offender table
            # lifts the cap — but only if that table was measured near the
            # trigger. A stale capture corroborates itself: dnf was genuinely the
            # top consumer at 21:59, which says nothing about the 18:32 stall.
            if [[ "${SF_MAINT_CORROBORATED:-0}" -eq 1 && "${SF_CAPTURE_STALE:-0}" -eq 0 ]]; then
                cap=60
            else
                cap="$SF_INCONCLUSIVE_FLOOR"
            fi
        else
            cap="$SF_CAP_SPECIFIC"
        fi
        pct="${SF_SCORE[$h]:-0}"
        ((pct > cap)) && pct="$cap"
        ((pct < 1)) && pct=1
        SF_PCT["$h"]="$pct"
    done

    # Leader = top specific cause (the mechanism is reported separately). When no
    # specific cause clears the noise floor, the verdict is inconclusive.
    SF_LEADER=""
    SF_LEADER_PCT=0
    for h in "${SF_HYPOTHESES[@]}"; do
        [[ "$h" == "$SF_MECH" ]] && continue
        if ((${SF_PCT[$h]} > SF_LEADER_PCT)); then
            SF_LEADER_PCT="${SF_PCT[$h]}"
            SF_LEADER="$h"
        fi
    done
    if [[ -z "$SF_LEADER" || "$SF_LEADER_PCT" -le "$SF_INCONCLUSIVE_FLOOR" ]]; then
        SF_LEADER="Inconclusive (insufficient evidence)"
        SF_LEADER_PCT="${SF_PCT[$SF_MECH]}"
    fi
}

# --- output helpers ----------------------------------------------------------

# Prints a dotted-leader confidence row: "  Label ....... NN%".
sf_conf_row() {
    local label="$1" val="$2" width=34 pad dots
    pad=$((width - ${#label}))
    ((pad < 1)) && pad=1
    dots="$(printf '%*s' "$pad" '' | tr ' ' '.')"
    printf '  %s %s %3s%%\n' "$label" "$dots" "$val"
}

sf_check() { printf '    [x] %s\n' "$1"; }
sf_cross() { printf '    [ ] %s\n' "$1"; }

# The evidence ledger: why the leader is suspected, and what is missing.
analysis_ledger() {
    local dir="$1"
    local leader="$SF_LEADER"

    local cpu_show="$W_CPU_AT_PEAK"
    [[ "$cpu_show" == "NA" || -z "$cpu_show" ]] && cpu_show="$W_MIN_CPU"

    printf 'Evidence ledger (%s):\n' "$leader"

    # Only evidence that actually argues FOR the leader belongs here. Listing
    # exclusions as support is how "no Apache pressure" ended up presented as a
    # reason to believe a maintenance interaction.
    printf '  Supported by:\n'
    local any=0
    case "$leader" in
        "CPU saturation")
            if [[ "$cpu_show" != "NA" && -n "$cpu_show" ]] && num_gt "$cpu_show" 50; then
                sf_check "CPU ${cpu_show}% at load ${W_MAX_LOAD} (measured)"
                any=1
            fi
            if [[ -n "${SF_TOP_CPU_COMM:-}" ]]; then
                sf_check "top CPU process '${SF_TOP_CPU_COMM}' (pid ${SF_TOP_CPU_PID}) at ${SF_TOP_CPU_PCT}%"
                any=1
            fi
            ;;
        "Filesystem wait" | "Disk / block layer")
            if num_gt "${W_MAX_IOWAIT:-0}" 20; then
                sf_check "high IO wait (${W_MAX_IOWAIT}%)"
                any=1
            fi
            if num_gt "${W_MAX_DSTATE:-0}" 0; then
                sf_check "high D-state (${W_MAX_DSTATE})"
                any=1
            fi
            if [[ "$SF_PSI_PRESENT" -eq 1 ]] && num_gt "$(incident_meta_get "$dir" peak_psi_io_full 0)" 20; then
                sf_check "PSI io full avg10 high"
                any=1
            fi
            if [[ -n "${SF_TOP_IO_COMM:-}" ]]; then
                sf_check "top I/O process '${SF_TOP_IO_COMM}' at ${SF_TOP_IO_KBS} kB/s"
                any=1
            fi
            if [[ "$SF_WCHAN_PRESENT" -eq 1 ]]; then
                sf_check "wait channel captured"
                any=1
            fi
            ;;
        "Memory exhaustion")
            if [[ "$SF_PSI_PRESENT" -eq 1 ]] && num_gt "$(incident_meta_get "$dir" peak_psi_mem_full 0)" 10; then
                sf_check "PSI memory full avg10 high"
                any=1
            fi
            ;;
        "Maintenance interaction" | "Package manager")
            if [[ "${SF_MAINT_CORROBORATED:-0}" -eq 1 ]]; then
                sf_check "a maintenance process is the measured top consumer"
                any=1
            fi
            ;;
        *)
            if num_gt "${W_MAX_DSTATE:-0}" 0; then
                sf_check "high D-state (${W_MAX_DSTATE})"
                any=1
            fi
            if [[ "$SF_WCHAN_PRESENT" -eq 1 ]]; then
                sf_check "wait channel captured"
                any=1
            fi
            ;;
    esac
    [[ "$any" -eq 1 ]] || printf '    (only weak/prior signals)\n'

    # Exclusions narrow the field but are not support for whatever is left.
    printf '  Alternatives ruled out (not support for %s):\n' "$leader"
    local ruled=0
    if [[ "$W_MIN_APACHE" != "NA" && -n "$W_MIN_APACHE" ]] && num_lt "$W_MIN_APACHE" 50; then
        sf_cross "Apache overload — only ${W_MIN_APACHE} workers"
        ruled=1
    fi
    if [[ "$W_MIN_DBTHR" != "NA" && -n "$W_MIN_DBTHR" ]] && num_lt "$W_MIN_DBTHR" 4; then
        sf_cross "MariaDB bottleneck — only ${W_MIN_DBTHR} threads running"
        ruled=1
    fi
    if num_lt "${W_MAX_IOWAIT:-0}" 5 && [[ "$leader" != "CPU saturation" ]]; then
        sf_cross "storage stall — IO wait only ${W_MAX_IOWAIT}%"
        ruled=1
    fi
    if [[ "${W_MAX_DSTATE:-0}" == "0" ]]; then
        sf_cross "uninterruptible blocking — no D-state tasks seen"
        ruled=1
    fi
    [[ "$ruled" -eq 1 ]] || printf '    (none)\n'

    printf '  Missing evidence:\n'
    local missing=()
    # Wording matters here: these lines are what a reader uses to decide whether
    # to go fix a permissions problem. "No blocked tasks were present" is a
    # measurement; "unavailable" is a false accusation against the recorder.
    local sampler_pids
    sampler_pids="$(analysis_sampler_stat "$dir" pids)"
    [[ "$SF_WCHAN_PRESENT" -eq 1 ]] || {
        if [[ -n "$sampler_pids" && "$sampler_pids" -eq 0 ]]; then
            sf_cross "no D-state tasks observed during rapid sampling (transient stall)"
        else
            sf_cross "kernel wait channel unavailable"
        fi
        missing+=("wait channel")
    }
    [[ "$SF_STACK_PRESENT" -eq 1 ]] || {
        if [[ -n "$sampler_pids" && "$sampler_pids" -eq 0 ]]; then
            sf_cross "no blocked task to read a kernel stack from during sampling"
        else
            sf_cross "blocked kernel stack unavailable"
        fi
        missing+=("kernel stack")
    }
    [[ "$SF_PSI_PRESENT" -eq 1 ]] || {
        sf_cross "PSI pressure metrics unavailable"
        missing+=("PSI")
    }
    [[ "${#missing[@]}" -gt 0 ]] || printf '    (none — decisive evidence was captured)\n'

    if [[ "${SF_CAPTURE_STALE:-0}" -eq 1 ]]; then
        printf '  Capture staleness:\n'
        printf '    [!] nearest per-process capture was %ss after the trigger (limit %ss).\n' \
            "$SF_CAPTURE_LAG_MIN" "${STALE_CAPTURE_SECONDS:-300}"
        printf '    The offender tables describe conditions at capture time, which may be a\n'
        printf '    DIFFERENT event from the one that opened this incident. Specific-cause\n'
        printf '    confidence is held at the inconclusive floor; trust the window facts\n'
        printf '    (load/CPU/iowait/D-state) and the ring buffer over the offender tables.\n'
    fi

    if [[ "${#missing[@]}" -gt 0 && "$SF_LEADER" != Inconclusive* ]]; then
        local IFS=', '
        printf '  => confidence for %s capped at %s%% because %s %s not captured.\n' \
            "$leader" "$SF_CAP_SPECIFIC" "${missing[*]}" \
            "$([[ ${#missing[@]} -eq 1 ]] && echo was || echo were)"
    fi
}

# Proven / Inferred / Unknown — the investigator's honest separation of what the
# evidence establishes from what it merely suggests and what remains unknown.
analysis_verdict_tiers() {
    local dir="$1"
    local psi_io psi_mem
    psi_io="$(incident_meta_get "$dir" peak_psi_io_full 0)"
    psi_mem="$(incident_meta_get "$dir" peak_psi_mem_full 0)"

    printf 'Proven:\n'
    local proven=0
    if num_gt "${W_MAX_DSTATE:-0}" 0; then
        printf '  - Uninterruptible (D-state) blocking occurred: %s task(s) counted directly.\n' "$W_MAX_DSTATE"
        proven=1
    fi
    local cpu_show="$W_CPU_AT_PEAK"
    [[ "$cpu_show" == "NA" || -z "$cpu_show" ]] && cpu_show="$W_MIN_CPU"
    if [[ "$cpu_show" != "NA" && -n "$cpu_show" ]] && num_lt "$cpu_show" 30 && num_gt "${W_MAX_LOAD:-0}" 5; then
        printf '  - Not CPU-bound: CPU %s%% at load %s (measured).\n' "$cpu_show" "$W_MAX_LOAD"
        proven=1
    fi
    if [[ "$cpu_show" != "NA" && -n "$cpu_show" ]] && num_gt "$cpu_show" 50; then
        printf '  - CPU-bound: CPU %s%% at load %s (measured).\n' "$cpu_show" "$W_MAX_LOAD"
        proven=1
    fi
    if [[ -n "${SF_TOP_CPU_COMM:-}" ]] && num_gt "${SF_TOP_CPU_PCT:-0}" 40; then
        printf "  - Largest CPU consumer was '%s' (pid %s) at %s%% (per-process measurement).\\n" \
            "$SF_TOP_CPU_COMM" "$SF_TOP_CPU_PID" "$SF_TOP_CPU_PCT"
        proven=1
    fi
    # On a single-account box 'lsphp' is not an answer; the endpoint the workers
    # were serving is. When the ring caught their rewritten argv, name it — this
    # is a direct measurement of the request behind the load.
    if declare -F ring_window_by_php >/dev/null 2>&1; then
        local ep_start ep_end top_php
        ep_start="$(incident_meta_get "$dir" started_epoch 0)"
        ep_end="$(incident_meta_get "$dir" ended_epoch 0)"
        if [[ "$ep_start" -gt 0 ]]; then
            top_php="$(ring_window_by_php "$ep_start" "$ep_end" 2>/dev/null | head -n 1)"
            if [[ -n "$top_php" ]]; then
                printf "  - Busiest PHP endpoint was '%s' (peak %s%% CPU across its workers, from the ring buffer).\\n" \
                    "$(printf '%s' "$top_php" | cut -f1)" "$(printf '%s' "$top_php" | cut -f3)"
                proven=1
            fi
        fi
    fi
    if [[ -n "${SF_TOP_IO_COMM:-}" ]] && num_gt "${SF_TOP_IO_KBS:-0}" 0; then
        printf "  - Largest disk consumer was '%s' (pid %s) at %s kB/s (per-process measurement).\\n" \
            "$SF_TOP_IO_COMM" "$SF_TOP_IO_PID" "$SF_TOP_IO_KBS"
        proven=1
    fi
    if [[ "$SF_PSI_PRESENT" -eq 1 ]] && num_gt "${psi_io:-0}" 20; then
        printf '  - Stall class was I/O: PSI io full avg10 %s (direct kernel measurement).\n' "$psi_io"
        proven=1
    fi
    if [[ "$SF_PSI_PRESENT" -eq 1 ]] && num_gt "${psi_mem:-0}" 10; then
        printf '  - Memory stall: PSI memory full avg10 %s (direct kernel measurement).\n' "$psi_mem"
        proven=1
    fi
    if [[ "$SF_WCHAN_PRESENT" -eq 1 ]]; then
        local pair
        pair="$(analysis_top "$dir" 4)"
        printf '  - Blocked in kernel path: wait channel %s (direct /proc read).\n' "${pair%%$'\t'*}"
        proven=1
    fi
    [[ "$proven" -eq 1 ]] || printf '  - (nothing could be proven from the captured evidence)\n'

    printf 'Inferred:\n'
    if [[ "$SF_LEADER" == Inconclusive* ]]; then
        printf '  - No single subsystem is supported strongly enough to name a cause.\n'
    else
        printf '  - %s is the most likely layer (%s%%), inferred from the corroborating signals above.\n' \
            "$SF_LEADER" "$SF_LEADER_PCT"
    fi

    printf 'Unknown:\n'
    local unknown=0
    [[ "$SF_WCHAN_PRESENT" -eq 1 ]] || {
        printf '  - The exact kernel wait channel (not captured).\n'
        unknown=1
    }
    [[ "$SF_STACK_PRESENT" -eq 1 ]] || {
        printf '  - The blocked kernel stack (needs root / permitted kernel).\n'
        unknown=1
    }
    [[ "$SF_PSI_PRESENT" -eq 1 ]] || {
        printf '  - PSI pressure metrics (kernel lacks CONFIG_PSI or capture disabled).\n'
        unknown=1
    }
    case "$SF_LEADER" in
        "Filesystem wait" | "Disk / block layer")
            [[ "$SF_WCHAN_PRESENT" -eq 1 ]] || {
                printf '  - The specific device/mount/file under pressure.\n'
                unknown=1
            }
            ;;
    esac
    [[ "$unknown" -eq 1 ]] || printf '  - (none)\n'
}

# Combined-by-executable and by-subsystem totals. This is the view that names a
# worker-pool cause: fourteen lsphp workers at 26% each are invisible in a
# PID-ranked table but obvious as one aggregated row.
analysis_aggregate_section() {
    local dir="$1"
    local cpu_tsv io_tsv combined

    if ! declare -F agg_combine >/dev/null 2>&1; then
        return 0
    fi

    cpu_tsv="$(mktemp 2>/dev/null)" || return 0
    io_tsv="$(mktemp 2>/dev/null)" || {
        rm -f -- "$cpu_tsv"
        return 0
    }

    io_aggregate_cpu "$dir" 2>/dev/null >"$cpu_tsv" || true
    io_aggregate_offenders "$dir" 2>/dev/null >"$io_tsv" || true

    combined="$(agg_combine "$cpu_tsv" "$io_tsv" 2>/dev/null)"
    rm -f -- "$cpu_tsv" "$io_tsv" 2>/dev/null || true

    printf 'Combined by executable (aggregated across all processes):\n'
    if [[ -z "$combined" ]]; then
        printf '  (no per-process attribution captured for this incident)\n'
        return 0
    fi
    printf '%s\n' "$combined" | agg_render_combined | sed 's/^/  /'

    printf '\nCombined by subsystem:\n'
    printf '%s\n' "$combined" | agg_rollup | agg_render_rollup | sed 's/^/  /'
}

# The kernel wait-channel histogram: WHAT the blocked tasks were waiting on,
# counted across the rapid D-state samples (field 4 of the "D-state only" ps
# blocks). On a uniformly slow disk there is no single stuck file — the payoff is
# the wait PATH, which points at the fix: jbd2_log_wait_commit -> journal/fsync
# storm; wait_on_page_writeback -> dirty-page flushing; read/folio paths -> reads.
# Blocked-task attribution: joins each captured wait channel to the endpoint or
# process that was waiting in it.
#
# This is the step from "the system experienced a filesystem stall" to "this
# request was the one blocked in the journal commit path". Two independent
# sources are used, and the report says which is which:
#
#   dstate-*.log — the panic-time sampler, which now records the served script
#                  alongside wchan for each blocked PID.
#   ring buffer  — kind=php rows carrying dstate + wchan, sampled continuously
#                  from before the trigger.
#
# Deliberately labelled co-occurrence, never causation. mod_lsapi does not
# expose the request URI to the process layer, so this proves that a worker
# serving endpoint X was blocked in channel Y at the same instant — not that
# X's code caused Y. Overstating that would be exactly the kind of confident
# prose this reporter exists to replace.
analysis_blocked_attribution_section() {
    local dir="$1"
    local -a files=()
    local pairs="" ring="" start end

    mapfile -t files < <(analysis_dstate_logs "$dir")
    if [[ "${#files[@]}" -gt 0 ]]; then
        pairs="$(awk '
            /^--- pid /       { ep = ""; wc = ""; next }
            /^endpoint: /     { ep = substr($0, 11); next }
            /^wchan:[[:space:]]/ {
                wc = $2
                if (ep != "" && wc != "" && wc != "-" && wc != "0") n[ep "\t" wc]++
                next
            }
            END { for (k in n) printf "%s\t%d\n", k, n[k] }
        ' "${files[@]}" 2>/dev/null | sort -t"$(printf '\t')" -k3,3 -rn | head -n 10)"
    fi

    if declare -F ring_window_php_wchan >/dev/null 2>&1; then
        start="$(incident_meta_get "$dir" started_epoch 0)"
        end="$(incident_meta_get "$dir" ended_epoch 0)"
        ring="$(ring_window_php_wchan "$start" "$end" 2>/dev/null | head -n 10)"
    fi

    [[ -n "$pairs" || -n "$ring" ]] || return 0

    printf 'Blocked-task attribution (which request was waiting on what):\n'
    if [[ -n "$pairs" ]]; then
        printf '  From kernel capture (panic-time sampler):\n'
        printf '    %-42s %-28s %s\n' ENDPOINT WAIT_CHANNEL SAMPLES
        printf '%s\n' "$pairs" | while IFS=$'\t' read -r ep wc cnt; do
            [[ -n "$ep" ]] || continue
            printf '    %-42s %-28s %s\n' "$ep" "$wc" "$cnt"
        done
    fi
    if [[ -n "$ring" ]]; then
        printf '  From ring buffer (continuous, includes pre-trigger):\n'
        printf '    %-42s %-28s %s\n' ENDPOINT WAIT_CHANNEL PEAK_BLOCKED
        printf '%s\n' "$ring" | while IFS=$'\t' read -r ep wc ds _; do
            [[ -n "$ep" ]] || continue
            printf '    %-42s %-28s %s\n' "$ep" "$wc" "$ds"
        done
    fi
    printf '  Note: co-occurrence within a sample (same worker, same instant), not\n'
    printf '  proof of causation — mod_lsapi does not expose the request URI to the\n'
    printf '  process layer, so the endpoint is the served script, not the URL.\n'
}

# Reads the rapid sampler's own record of what it did. Returns "" when the
# incident predates the sampler stats (older builds), so callers can tell
# "never recorded" apart from "recorded a zero".
analysis_sampler_stat() {
    local dir="$1" key="$2"
    incident_meta_get "$dir" "dstate_sampler_${key}" ""
}

# The distinction the previous wording erased. "unavailable" reads as a missing
# capability or a permissions problem; in every incident so far the truth was
# that the sampler ran correctly and the blocked tasks had already cleared. An
# absence of evidence is only informative if it is reported as a RESULT.
analysis_evidence_state() {
    local dir="$1" present="$2" pids

    if [[ "$present" -eq 1 ]]; then
        printf 'captured\n'
        return 0
    fi

    pids="$(analysis_sampler_stat "$dir" pids)"
    if [[ -z "$pids" ]]; then
        printf 'not captured (sampler did not record its result)\n'
    elif [[ "$pids" -eq 0 ]]; then
        printf 'none observed — sampler ran, no tasks were blocked during its window\n'
    else
        printf 'not readable (kernel or permissions withheld it)\n'
    fi
}

# Capture provenance: what the sampler did, when it started relative to the
# trigger, and — when the periodic samples saw blocking that the rapid sampler
# missed — why. This is what makes an empty capture actionable instead of
# mysterious, and it is the measurement that says whether the sampling window
# needs to move earlier or grow.
analysis_capture_section() {
    local dir="$1"
    local samples pids stacks syscalls lag peak_dstate

    samples="$(analysis_sampler_stat "$dir" samples)"
    [[ -n "$samples" ]] || return 0

    pids="$(analysis_sampler_stat "$dir" pids)"
    stacks="$(analysis_sampler_stat "$dir" stacks)"
    syscalls="$(analysis_sampler_stat "$dir" syscalls)"
    lag="$(analysis_sampler_stat "$dir" lag)"
    peak_dstate="$(incident_meta_get "$dir" peak_dstate 0)"

    printf '%s\n' '-- Capture (what the recorder actually measured) --'
    printf '  - Rapid D-state sampling: completed, %s samples\n' "$samples"
    printf '  - Unique D-state processes observed: %s\n' "${pids:-0}"
    printf '  - Kernel stacks captured: %s\n' "${stacks:-0}"
    printf '  - Syscalls captured: %s\n' "${syscalls:-0}"
    if [[ -n "$lag" && "$lag" -ge 0 ]]; then
        printf '  - Capture began %ss after the incident trigger\n' "$lag"
    else
        printf '  - Capture lag: not recorded\n'
    fi

    # The reconciliation. Periodic sampling counts D-state every 60s; the rapid
    # sampler reads kernel state during a ~3s window. Peak > 0 with observed = 0
    # is not a contradiction and not a fault — it dates the stall.
    if [[ "${pids:-0}" -eq 0 ]] && num_gt "${peak_dstate:-0}" 0; then
        printf '  - Reconciliation: periodic sampling recorded up to %s blocked task(s),\n' "$peak_dstate"
        printf '    but none were still blocked when the rapid sampler ran%s.\n' \
            "$([[ -n "$lag" && "$lag" -ge 0 ]] && printf ' %ss later' "$lag" || printf '')"
        printf '    The stall was TRANSIENT and had already recovered before kernel-level\n'
        printf '    evidence could be collected. This bounds its duration rather than\n'
        printf '    leaving it unknown.\n'
        if [[ -n "$lag" && "$lag" -gt 5 ]]; then
            printf '    Tuning: a %ss lag is long for a sub-minute stall — consider raising\n' "$lag"
            printf '    PANIC_DSTATE_SAMPLES / PANIC_DSTATE_INTERVAL, and read the ring\n'
            printf '    buffer (kind=wchan rows), which samples before the trigger fires.\n'
        fi
    fi
    printf '\n'
}

analysis_wchan_section() {
    local dir="$1"
    local hist
    hist="$(analysis_field_counts "$dir" 4 2>/dev/null | head -n 10)"
    [[ -n "$hist" ]] || return 0

    printf 'Kernel wait channels (D-state tasks, counted across samples):\n'
    printf '%s\n' "$hist" | while IFS=$'\t' read -r cnt wch; do
        [[ -n "$wch" ]] || continue
        local sub
        sub="$(analysis_wchan_subsystem "$wch")"
        if [[ -n "$sub" ]]; then
            printf '  %5d  %-34s -> %s\n' "$cnt" "$wch" "$sub"
        else
            printf '  %5d  %s\n' "$cnt" "$wch"
        fi
    done
}

# The pre-incident run-up, reconstructed from the process ring buffer. This is
# the window the panic samplers structurally cannot reach: load1 lags, so by the
# time panic mode starts sampling, a sub-minute burst is already collapsing.
analysis_runup_section() {
    local dir="$1"
    local start end

    declare -F ring_render_runup >/dev/null 2>&1 || return 0

    start="$(incident_meta_get "$dir" started_epoch 0)"
    end="$(incident_meta_get "$dir" ended_epoch 0)"
    [[ "$start" -gt 0 ]] || return 0

    printf 'Run-up (process ring buffer, before and during the incident):\n'
    ring_render_runup "$start" "$end"

    local peak
    peak="$(ring_window_by_exec "$start" "$end" 2>/dev/null | head -n 5)"
    if [[ -n "$peak" ]]; then
        printf '\n  Peak concurrency by executable during the run-up:\n'
        printf '%s\n' "$peak" | awk -F'\t' \
            '{ printf "    %-18.18s peak_procs=%-5d peak_cpu=%-8.1f samples=%d\n", $1, $2, $3, $4 }'
    fi

    # On a single-account box "lsphp" names nothing; the endpoint does. When the
    # ring caught the workers' rewritten argv, this is the request behind the load.
    local php
    if declare -F ring_window_by_php >/dev/null 2>&1; then
        php="$(ring_window_by_php "$start" "$end" 2>/dev/null | head -n 8)"
    fi
    if [[ -n "$php" ]]; then
        printf '\n  Hot PHP endpoints during the run-up (script the workers were serving):\n'
        printf '%s\n' "$php" | awk -F'\t' \
            '{ printf "    %-40.40s peak_procs=%-5d peak_cpu=%-8.1f samples=%d\n", $1, $2, $3, $4 }'
    fi
}

# Reconstructs how the incident evolved from the current.log samples in the
# window, one compact row per sample with annotated transitions.
analysis_timeline() {
    local dir="$1"
    local start end log
    start="$(incident_meta_get "$dir" started_epoch 0)"
    end="$(incident_meta_get "$dir" ended_epoch 0)"
    log="${CURRENT_LOG:-}"

    printf 'Timeline:\n'
    if [[ -z "$log" || ! -r "$log" ]]; then
        printf '  (current.log unavailable — no timeline)\n'
        return 0
    fi
    [[ "$end" -gt 0 ]] || end=9999999999

    awk -v start="$start" -v end="$end" \
        -v loadt="${LOAD_THRESHOLD:-10}" -v dstatet="${DSTATE_THRESHOLD:-5}" '
        function field(line, key,   nf, i, a, kv) {
            nf = split(line, a, " ")
            for (i = 1; i <= nf; i++) {
                if (index(a[i], key "=") == 1) { kv = a[i]; sub(key "=", "", kv); return kv }
            }
            return ""
        }
        BEGIN { n = 0 }
        {
            ep = field($0, "epoch") + 0
            if (ep < start - 90 || ep > end + 90) next
            ts[n] = field($0, "timestamp")
            ld[n] = field($0, "load1")
            cp[n] = field($0, "cpu_busy_pct")
            iw[n] = field($0, "iowait_pct")
            ds[n] = field($0, "dstate_processes")
            aw[n] = field($0, "apache_workers")
            db[n] = field($0, "threads_running")
            n++
        }
        END {
            if (n == 0) { print "  (no samples retained for the incident window)"; exit }
            step = 1
            if (n > 40) step = int((n + 39) / 40)
            for (i = 0; i < n; i += step) {
                clock = ts[i]
                sub(/^.*T/, "", clock); sub(/[+-][0-9].*$/, "", clock)
                note = ""
                if (i > 0) {
                    if ((ld[i-step]+0) <= loadt && (ld[i]+0) > loadt) note = note "  <- load crosses threshold"
                    if ((ds[i]+0) > (ds[i-step]+0) && (ds[i]+0) >= dstatet) note = note "  <- D-state climbing"
                    if (iw[i] != "NA" && iw[i-step] != "NA" && (iw[i]+0) - (iw[i-step]+0) >= 15) note = note "  <- IO wait spike"
                } else {
                    note = "  <- incident window begins"
                }
                printf "  %s  load=%s cpu=%s%% iowait=%s%% dstate=%s apache=%s dbthr=%s%s\n", \
                    clock, ld[i], cp[i], iw[i], ds[i], aw[i], db[i], note
            }
            # Always show the final sample (recovery) if step skipped it.
            if (((n-1) % step) != 0) {
                clock = ts[n-1]; sub(/^.*T/, "", clock); sub(/[+-][0-9].*$/, "", clock)
                printf "  %s  load=%s cpu=%s%% iowait=%s%% dstate=%s apache=%s dbthr=%s  <- recovery\n", \
                    clock, ld[n-1], cp[n-1], iw[n-1], ds[n-1], aw[n-1], db[n-1]
            } else {
                printf "  (recovery: load back below %s)\n", loadt
            }
        }
    ' "$log" 2>/dev/null
}

# --- correlation across incidents --------------------------------------------

# Writes a compact machine-readable .facts file so future incidents can correlate
# against this one even after the verbose dstate-*.log files are rotated away.
analysis_write_facts() {
    local dir="$1"
    local apache_idle=0 mariadb_idle=0 high_dstate=0 iowait_gt20=0
    local psi_io_high=0 psi_mem_high=0

    [[ "$W_MIN_APACHE" != "NA" && -n "$W_MIN_APACHE" ]] && num_lt "$W_MIN_APACHE" 50 && apache_idle=1
    [[ "$W_MIN_DBTHR" != "NA" && -n "$W_MIN_DBTHR" ]] && num_lt "$W_MIN_DBTHR" 4 && mariadb_idle=1
    num_gt "${W_MAX_DSTATE:-0}" "${DSTATE_THRESHOLD:-5}" && high_dstate=1
    num_gt "$(incident_meta_get "$dir" peak_iowait 0)" 20 && iowait_gt20=1
    num_gt "$(incident_meta_get "$dir" peak_psi_io_full 0)" 20 && psi_io_high=1
    num_gt "$(incident_meta_get "$dir" peak_psi_mem_full 0)" 10 && psi_mem_high=1

    {
        printf 'apache_idle=%s\n' "$apache_idle"
        printf 'mariadb_idle=%s\n' "$mariadb_idle"
        printf 'high_dstate=%s\n' "$high_dstate"
        printf 'iowait_gt20=%s\n' "$iowait_gt20"
        printf 'psi_io_high=%s\n' "$psi_io_high"
        printf 'psi_mem_high=%s\n' "$psi_mem_high"
        printf 'imunify_active=%s\n' "${SF_IMUNIFY:-0}"
        printf 'pkgmgr_active=%s\n' "${SF_PKGMGR:-0}"
        printf 'backup_active=%s\n' "${SF_BACKUP:-0}"
        printf 'maint_corroborated=%s\n' "${SF_MAINT_CORROBORATED:-0}"
        printf 'cpu_bound=%s\n' "${SF_CPU_BOUND:-0}"
        printf 'top_cpu_comm=%s\n' "${SF_TOP_CPU_COMM:-none}"
        printf 'top_io_comm=%s\n' "${SF_TOP_IO_COMM:-none}"
        printf 'wchan_present=%s\n' "${SF_WCHAN_PRESENT:-0}"
        printf 'stack_present=%s\n' "${SF_STACK_PRESENT:-0}"
        printf 'leader=%s\n' "$SF_LEADER"
    } >"${dir}/.facts"
}

# Aggregates the .facts of every recorded incident (including this one) into
# recurring-pattern lines. Robust to incidents predating the feature: they simply
# have no .facts and are skipped.
analysis_correlate() {
    printf 'Recurring patterns (across recorded incidents):\n'
    local base="${INCIDENT_DIR:-}"
    if [[ -z "$base" || ! -d "$base" ]]; then
        printf '  (no incident history available)\n'
        return 0
    fi

    local -a facts=()
    mapfile -t facts < <(find "$base" -mindepth 2 -maxdepth 2 -type f -name '.facts' 2>/dev/null)
    local total="${#facts[@]}"
    if [[ "$total" -eq 0 ]]; then
        printf '  (no comparable incidents yet)\n'
        return 0
    fi

    awk -v total="$total" '
        FNR == 1 { }
        /^apache_idle=1/    { apache++ }
        /^mariadb_idle=1/   { mariadb++ }
        /^high_dstate=1/    { dstate++ }
        /^iowait_gt20=1/    { iowait++ }
        /^psi_io_high=1/    { psiio++ }
        /^psi_mem_high=1/   { psimem++ }
        /^imunify_active=1/ { imunify++ }
        /^pkgmgr_active=1/  { pkg++ }
        /^backup_active=1/  { backup++ }
        /^wchan_present=1/  { wchan++ }
        /^cpu_bound=1/      { cpubound++ }
        /^top_cpu_comm=/    { c = $0; sub(/^top_cpu_comm=/, "", c); if (c != "none" && c != "") topcpu[c]++ }
        /^top_io_comm=/     { c = $0; sub(/^top_io_comm=/, "", c); if (c != "none" && c != "") topio[c]++ }
        /^leader=/          { l = $0; sub(/^leader=/, "", l); lead[l]++ }
        END {
            printf "  Apache idle .................. %d/%d\n", apache+0, total
            printf "  MariaDB idle ................. %d/%d\n", mariadb+0, total
            printf "  High D-state ................. %d/%d\n", dstate+0, total
            printf "  IO wait > 20%% ................ %d/%d\n", iowait+0, total
            printf "  PSI io-full high ............. %d/%d\n", psiio+0, total
            printf "  PSI memory-full high ......... %d/%d\n", psimem+0, total
            printf "  Imunify active ............... %d/%d\n", imunify+0, total
            printf "  Package manager active ....... %d/%d\n", pkg+0, total
            printf "  Backup active ................ %d/%d\n", backup+0, total
            printf "  Wait channel captured ........ %d/%d\n", wchan+0, total
            printf "  CPU-bound .................... %d/%d\n", cpubound+0, total
            printf "  Leading cause by incident:\n"
            for (k in lead) printf "    %-32s %d/%d\n", k, lead[k], total
            if (length(topcpu) > 0) {
                printf "  Recurring top CPU process:\n"
                for (k in topcpu) printf "    %-32s %d/%d\n", k, topcpu[k], total
            }
            if (length(topio) > 0) {
                printf "  Recurring top I/O process:\n"
                for (k in topio) printf "    %-32s %d/%d\n", k, topio[k], total
            }
        }
    ' "${facts[@]}"

    # State the denominator honestly: incidents recorded before this feature (or
    # closed by an older build) have no .facts and are silently absent above.
    local all skipped
    all="$(find "$base" -mindepth 1 -maxdepth 1 -type d -name 'incident-*' 2>/dev/null | wc -l | tr -d '[:space:]')"
    skipped=$((all - total))
    if [[ "$skipped" -gt 0 ]]; then
        printf '  (compared across %s of %s recorded incidents; %s predate this analysis and carry no .facts)\n' \
            "$total" "$all" "$skipped"
    fi
}

# Recommended next investigation steps, keyed to the leading subsystem.
analysis_next_steps() {
    case "$1" in
        "CPU saturation")
            printf 'Identify the top CPU process from the CPU offender table (--offenders)\n'
            printf 'Check its age and command line: a long-lived 100%% process is usually stuck\n'
            printf 'Decide whether it is legitimate work, a runaway loop, or an orphaned session\n'
            printf 'If legitimate but disruptive, nice/cpulimit it or move it off this host\n'
            ;;
        "Filesystem wait")
            printf 'Check dmesg for filesystem/journal errors (ext4/jbd2/xfs)\n'
            printf 'Run iostat -x 1: inspect %%util and await on the busy device\n'
            printf 'Identify the mount under pressure and what is writing to it\n'
            printf 'Correlate the incident window with backup/snapshot schedules\n'
            ;;
        "Disk / block layer")
            printf 'Run iostat -x 1 and look for a device at ~100%% util with high await\n'
            printf 'Check dmesg and smartctl -a for I/O errors or a failing disk\n'
            printf 'If cloud/SAN, check for throttled IOPS or a noisy neighbour\n'
            ;;
        "MariaDB bottleneck")
            printf 'Capture SHOW ENGINE INNODB STATUS during the next incident\n'
            printf 'Review the slow query log and check for a long-running transaction\n'
            printf 'Check disk latency under the datadir; MariaDB stalls follow storage\n'
            ;;
        "Apache overload")
            printf 'Enable/collect mod_status to see BusyWorkers vs a backend stall\n'
            printf 'Check whether workers are blocked on a slow backend (PHP/DB/disk)\n'
            ;;
        "PHP overload")
            printf 'Inspect lsphp process ages and args for a stuck script or endpoint\n'
            printf 'Check the slowest site/vhost and any external calls it makes\n'
            ;;
        "Maintenance interaction")
            printf 'Confirm the maintenance/backup window (cPanel/JetBackup/rsync/scan) vs incident time\n'
            printf 'Throttle its I/O (ionice/nice) or reschedule off peak\n'
            printf 'Remember: a maintenance process running is correlation; confirm it is the writer\n'
            ;;
        "Package manager")
            printf 'Check dnf/yum history and cPanel upcp timing vs the incident\n'
            printf 'Look for an unattended update or a stuck rpm transaction/lock\n'
            ;;
        "Memory exhaustion")
            printf 'Check for swap thrash and kswapd/kcompactd activity in the samples\n'
            printf 'Review the top memory consumers and any OOM events in dmesg\n'
            ;;
        "Network / remote FS")
            printf 'Check for NFS/remote mount stalls or socket exhaustion\n'
            printf 'Inspect ss -s and connection churn during the window\n'
            ;;
        "Kernel lock contention")
            printf 'Kernel lock contention: capture /proc/<pid>/stack for the blocked set\n'
            printf 'Check dmesg for hung-task warnings and correlate the common stack\n'
            ;;
        *)
            printf 'Inspect the newest dstate-*.log for the blocked process set\n'
            printf 'Ensure the recorder runs as root so kernel stacks are captured\n'
            printf 'If the kernel supports PSI, confirm PANIC_CAPTURE_PSI=1 for the next incident\n'
            ;;
    esac
}

# --- output ------------------------------------------------------------------

# Generates analysis.txt for an incident and appends a condensed headline to
# summary.txt. Safe to call even when no D-state logs were captured.
analysis_generate() {
    local dir="$1"
    local file="${dir}/analysis.txt"
    local id started
    id="$(incident_meta_get "$dir" id "$(basename "$dir")")"
    started="$(incident_meta_get "$dir" started unknown)"

    analysis_classify "$dir"
    analysis_write_facts "$dir"

    local h
    {
        printf 'Server Forensics Incident Analysis\n'
        printf 'Incident: %s\n' "$id"
        printf 'Generated: %s\n' "$(now_iso)"
        printf 'Window:   started %s, %s sample(s) in the incident window\n' "$started" "${W_SAMPLES:-0}"
        printf '\n'
        printf '========================================\n'
        printf 'LIKELY CAUSE: %s (%s%%)\n' "$SF_LEADER" "$SF_LEADER_PCT"
        printf 'Mechanism:    blocked (uninterruptible) tasks (%s%%)\n' "${SF_PCT[$SF_MECH]}"
        printf '========================================\n'
        if [[ "${SF_DISTRIBUTED:-0}" -eq 1 ]]; then
            printf '\n'
            printf 'NOTE: CPU usage is distributed across multiple processes; inspect\n'
            printf '      aggregated executable totals rather than individual PIDs.\n'
        fi
        printf '\n'

        printf '%s\n' '-- Observed facts (measured, no interpretation) --'
        printf '  - Peak load: %s\n' "$W_MAX_LOAD"
        printf '  - CPU at peak load: %s%% (window min %s%%)\n' "$W_CPU_AT_PEAK" "$W_MIN_CPU"
        printf '  - Peak IO wait: %s%%\n' "$W_MAX_IOWAIT"
        printf '  - Peak D-state processes: %s\n' "$W_MAX_DSTATE"
        printf '  - Lowest Apache workers: %s\n' "$W_MIN_APACHE"
        printf '  - Lowest MariaDB threads running: %s\n' "$W_MIN_DBTHR"
        # Prefer the meta peaks recorded live during the incident, but fall back
        # to the values re-derived from the offender tables. Without the
        # fallback this block contradicts the Inference block below whenever the
        # meta is absent — for an incident closed by an older build, or one whose
        # analysis is regenerated after the fact.
        local of_comm of_pid of_val
        of_comm="$(incident_meta_get "$dir" peak_cpu_comm none)"
        of_pid="$(incident_meta_get "$dir" peak_cpu_pid none)"
        of_val="$(incident_meta_get "$dir" peak_cpu_pct 0)"
        if [[ "$of_comm" == none && -n "${SF_TOP_CPU_COMM:-}" ]]; then
            of_comm="$SF_TOP_CPU_COMM"
            of_pid="$SF_TOP_CPU_PID"
            of_val="$SF_TOP_CPU_PCT"
        fi
        printf '  - Top CPU process: %s (pid %s) at %s%%\n' "$of_comm" "$of_pid" "$of_val"

        of_comm="$(incident_meta_get "$dir" peak_io_comm none)"
        of_pid="$(incident_meta_get "$dir" peak_io_pid none)"
        of_val="$(incident_meta_get "$dir" peak_io_kbs 0)"
        if [[ "$of_comm" == none && -n "${SF_TOP_IO_COMM:-}" ]]; then
            of_comm="$SF_TOP_IO_COMM"
            of_pid="$SF_TOP_IO_PID"
            of_val="$SF_TOP_IO_KBS"
        fi
        printf '  - Top I/O process: %s (pid %s) at %s kB/s%s\n' "$of_comm" "$of_pid" "$of_val" \
            "$([[ "${SF_PID1_LEADS_IO:-0}" -eq 1 ]] && printf ' (PID 1 excluded: delegated writes)' || printf '')"
        if [[ "$SF_PSI_PRESENT" -eq 1 ]]; then
            printf '  - PSI io full avg10 (peak): %s\n' "$(incident_meta_get "$dir" peak_psi_io_full 0)"
            printf '  - PSI cpu some avg10 (peak): %s\n' "$(incident_meta_get "$dir" peak_psi_cpu_some 0)"
            printf '  - PSI memory full avg10 (peak): %s\n' "$(incident_meta_get "$dir" peak_psi_mem_full 0)"
        else
            printf '  - PSI: not captured\n'
        fi
        printf '  - Wait channels: %s\n' "$(analysis_evidence_state "$dir" "$SF_WCHAN_PRESENT")"
        printf '  - Kernel stacks: %s\n' "$(analysis_evidence_state "$dir" "$SF_STACK_PRESENT")"
        printf '\n'

        analysis_capture_section "$dir"

        printf '%s\n' '-- Inference (reasoning from the facts) --'
        if [[ "${#SF_EVIDENCE[@]}" -gt 0 ]]; then
            local ev
            for ev in "${SF_EVIDENCE[@]}"; do printf '  - %s\n' "$ev"; done
        else
            printf '  - insufficient forensic detail was captured\n'
        fi
        printf '\n'

        analysis_aggregate_section "$dir"
        printf '\n'

        analysis_runup_section "$dir"
        printf '\n'

        local wchan_out
        wchan_out="$(analysis_wchan_section "$dir")"
        if [[ -n "$wchan_out" ]]; then
            printf '%s\n\n' "$wchan_out"
        fi

        local blocked_out
        blocked_out="$(analysis_blocked_attribution_section "$dir")"
        if [[ -n "$blocked_out" ]]; then
            printf '%s\n\n' "$blocked_out"
        fi

        analysis_ledger "$dir"
        printf '\n'

        printf 'Confidence distribution:\n'
        # Sort hypotheses by percentage, highest first.
        for h in "${SF_HYPOTHESES[@]}"; do
            printf '%s\t%s\n' "${SF_PCT[$h]}" "$h"
        done | sort -rn | while IFS=$'\t' read -r pct label; do
            sf_conf_row "$label" "$pct"
        done
        printf '  (leading specific cause: %s)\n' "$SF_LEADER"
        printf '\n'

        analysis_verdict_tiers "$dir"
        printf '\n'

        analysis_timeline "$dir"
        printf '\n'

        analysis_correlate
        printf '\n'

        printf 'Recommended next investigation:\n'
        analysis_next_steps "$SF_LEADER" | while IFS= read -r step; do
            printf '  - %s\n' "$step"
        done
        printf '\n'

        printf 'Missing evidence to capture next time:\n'
        [[ "$SF_WCHAN_PRESENT" -eq 1 ]] || printf '  - kernel wait channel (/proc/<pid>/wchan) — run as root\n'
        [[ "$SF_STACK_PRESENT" -eq 1 ]] || printf '  - blocked kernel stack (/proc/<pid>/stack) — root / permitted kernel\n'
        [[ "$SF_PSI_PRESENT" -eq 1 ]] || printf '  - PSI (/proc/pressure/*) — needs CONFIG_PSI and PANIC_CAPTURE_PSI=1\n'
        printf '  - the specific blocking resource (device/mount/file/query)\n'
        printf '\n'

        printf 'Note: automated evidence-based classification. Confidence is gated by\n'
        printf 'missing evidence and is never absolute. Confirm against the raw\n'
        printf 'snapshot-*.log and dstate-*.log before acting.\n'
    } >"$file"

    # Fold a one-line verdict into the incident summary for quick scanning.
    if [[ -w "${dir}/summary.txt" || -e "${dir}/summary.txt" ]]; then
        {
            printf '\nLikely Cause: %s (confidence %s%%)\n' "$SF_LEADER" "$SF_LEADER_PCT"
            printf 'Mechanism: blocked tasks (%s%%). See analysis.txt for evidence, timeline, and next steps.\n' \
                "${SF_PCT[$SF_MECH]}"
        } >>"${dir}/summary.txt"
    fi

    printf '%s\n' "$file"
}
