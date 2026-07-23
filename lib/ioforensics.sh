#!/usr/bin/env bash
# Per-process I/O attribution.
#
# The system-level metrics already answer "is this box storage-stalled?". This
# module answers the only question that follows from a yes: WHICH PROCESS was
# doing the I/O. Service names present on the box are not evidence — a resident
# daemon is not a writer. Everything here measures actual bytes moved per PID.
#
# Capture strategy:
#   - pidstat -d  : per-process read/write rates and block-I/O delay (the ranking)
#   - pidstat -u  : per-process CPU over the same window (separates spin from wait)
#   - iostat -x   : per-device service times over the same window (which disk)
#   - /proc/pressure/{io,cpu,memory} : stall class, instantaneous
#   - /proc/diskstats, mount, findmnt : device and mount context
#   - per-offender /proc detail + open files
#
# The three sampling commands each need SAMPLES*INTERVAL seconds. Run serially
# that is 3x the window and would starve the panic snapshot loop, so they are run
# CONCURRENTLY into separate temp files and merged in a fixed order afterwards.
# All three are passive readers, so overlapping them costs effectively nothing
# and keeps the wall-clock cost at one sampling window.
#
# Nothing here invokes a package manager, touches the network, or writes to the
# filesystem under investigation beyond the incident directory itself.
# shellcheck disable=SC2154

# --- low-level helpers -------------------------------------------------------

io_header() {
    local file="$1"
    local title="$2"
    {
        printf '\n\n===== %s =====\n' "$title"
        printf 'captured_at=%s\n' "$(now_iso)"
    } >>"$file"
}

# Runs a command into its own file in the BACKGROUND. Used for the three
# concurrent samplers. Never allowed to outlive the timeout.
io_run_bg() {
    local out="$1"
    local timeout_s="$2"
    shift 2
    local command_name="$1"

    if ! command_exists "$command_name"; then
        printf 'SKIPPED: command not found: %s\n' "$command_name" >"$out"
        return 0
    fi

    {
        local rc=0
        run_with_timeout "$timeout_s" "$@" >"$out" 2>&1 || rc=$?
        if [[ "$rc" -eq 124 ]]; then
            printf '\n[timed out after %ss]\n' "$timeout_s" >>"$out"
        elif [[ "$rc" -ne 0 ]]; then
            printf '\n[exited with status %s]\n' "$rc" >>"$out"
        fi
    } &
}

# Appends a captured temp file into the snapshot log under a section header.
io_merge() {
    local file="$1"
    local title="$2"
    local src="$3"

    io_header "$file" "$title"
    if [[ -r "$src" ]]; then
        cat "$src" >>"$file"
    else
        printf 'SKIPPED: no output captured\n' >>"$file"
    fi
}

# Runs a cheap, instantaneous command straight into the snapshot log.
io_run_now() {
    local file="$1"
    local title="$2"
    shift 2
    local command_name="$1"
    local rc=0

    io_header "$file" "$title"

    if ! command_exists "$command_name"; then
        printf 'SKIPPED: command not found: %s\n' "$command_name" >>"$file"
        return 0
    fi

    run_with_timeout "${PANIC_IO_DETAIL_TIMEOUT:-5}" "$@" >>"$file" 2>&1 || rc=$?
    [[ "$rc" -eq 0 ]] || printf '\n[exited with status %s]\n' "$rc" >>"$file"
    return 0
}

# --- pidstat parsing ---------------------------------------------------------

# Converts `pidstat -d -h` output into a ranked TSV, one row per PID:
#
#   pid <TAB> comm <TAB> avg_rd_kbs <TAB> avg_wr_kbs <TAB> avg_total_kbs
#       <TAB> max_iodelay <TAB> samples <TAB> pct_of_total
#
# Column positions are resolved from pidstat's own header rather than hardcoded,
# because the column set differs across sysstat versions (older builds have no
# `iodelay`, some emit `kB_ccwr/s`). The header line begins with '#', which shifts
# every header index one to the right of the matching data index.
io_rank_offenders() {
    local pidstat_out="$1"

    [[ -r "$pidstat_out" ]] || return 0

    awk '
        # Resolve column layout from the pidstat header.
        /^#/ && /PID/ {
            for (i = 2; i <= NF; i++) {
                # data index = header index - 1 (the leading "#" token)
                if ($i == "PID")       c_pid = i - 1
                else if ($i == "kB_rd/s")  c_rd = i - 1
                else if ($i == "kB_wr/s")  c_wr = i - 1
                else if ($i == "iodelay")  c_del = i - 1
                else if ($i == "Command")  c_cmd = i - 1
            }
            next
        }
        # Data rows: first field is the epoch timestamp pidstat -h emits.
        $1 ~ /^[0-9]+$/ && c_pid > 0 {
            pid = $c_pid
            if (pid == 0) next
            rd = (c_rd  > 0 ? $c_rd + 0 : 0)
            wr = (c_wr  > 0 ? $c_wr + 0 : 0)
            dl = (c_del > 0 ? $c_del + 0 : 0)

            sum_rd[pid] += rd
            sum_wr[pid] += wr
            n[pid]++
            if (dl > maxdel[pid]) maxdel[pid] = dl

            if (c_cmd > 0) {
                cmd = ""
                for (i = c_cmd; i <= NF; i++) cmd = cmd (i > c_cmd ? " " : "") $i
                comm[pid] = cmd
            }
        }
        END {
            for (p in n) {
                ard = sum_rd[p] / n[p]
                awr = sum_wr[p] / n[p]
                tot[p] = ard + awr
                rdv[p] = ard
                wrv[p] = awr
                grand += tot[p]
            }
            for (p in n) {
                pct = (grand > 0 ? (tot[p] * 100.0) / grand : 0)
                printf "%s\t%s\t%.2f\t%.2f\t%.2f\t%d\t%d\t%.1f\n", \
                    p, (comm[p] == "" ? "?" : comm[p]), rdv[p], wrv[p], tot[p], \
                    maxdel[p], n[p], pct
            }
        }
    ' "$pidstat_out" | sort -t"$(printf '\t')" -k5 -rn
}

# Selects the PIDs worth a full detail block: everything above
# PANIC_IO_OFFENDER_PCT of total observed I/O, always at least the top
# PANIC_IO_MIN_OFFENDERS rows so a diffuse incident still yields something, and
# never more than PANIC_IO_MAX_OFFENDERS so the recorder cannot fan out.
io_select_offenders() {
    local tsv="$1"
    local pct="${PANIC_IO_OFFENDER_PCT:-5}"
    local min_rows="${PANIC_IO_MIN_OFFENDERS:-3}"
    local max_rows="${PANIC_IO_MAX_OFFENDERS:-10}"

    [[ -r "$tsv" ]] || return 0

    awk -F'\t' -v pct="$pct" -v minr="$min_rows" -v maxr="$max_rows" '
        # Rows arrive pre-sorted by total I/O, highest first.
        {
            n++
            if (n > maxr) exit
            # $5 total kB/s, $8 percent of observed total
            if (($8 + 0) > pct || n <= minr) {
                if (($5 + 0) > 0) print $1
            }
        }
    ' "$tsv"
}

# --- per-offender detail -----------------------------------------------------

# Everything the brief asks for about a single offending PID, read straight from
# /proc. Each read is guarded because a process can exit mid-capture and because
# a descriptor pointing at a stalled mount must never hang the recorder.
io_offender_detail() {
    local file="$1"
    local pid="$2"
    local tmo="${PANIC_IO_DETAIL_TIMEOUT:-5}"

    if [[ ! -d "/proc/${pid}" ]]; then
        printf '\n--- pid %s: exited before detail capture ---\n' "$pid" >>"$file"
        return 0
    fi

    {
        printf '\n--- pid %s ---\n' "$pid"

        printf 'comm:      %s\n' "$(cat "/proc/${pid}/comm" 2>/dev/null || printf '?')"
        printf 'ppid:      %s\n' \
            "$(awk '{print $4}' "/proc/${pid}/stat" 2>/dev/null || printf '?')"
        printf 'user:      %s\n' \
            "$(run_with_timeout "$tmo" ps -o user= -p "$pid" 2>/dev/null | trim || printf '?')"
        printf 'state:     %s\n' \
            "$(run_with_timeout "$tmo" ps -o stat= -p "$pid" 2>/dev/null | trim || printf '?')"
        printf 'elapsed_s: %s\n' \
            "$(run_with_timeout "$tmo" ps -o etimes= -p "$pid" 2>/dev/null | trim || printf '?')"
        printf 'exe:       %s\n' \
            "$(run_with_timeout "$tmo" readlink -f "/proc/${pid}/exe" 2>/dev/null || printf '[unreadable]')"
        printf 'cwd:       %s\n' \
            "$(run_with_timeout "$tmo" readlink -f "/proc/${pid}/cwd" 2>/dev/null || printf '[unreadable]')"
        printf 'wchan:     %s\n' "$(cat "/proc/${pid}/wchan" 2>/dev/null || printf '[unavailable]')"
        printf 'cmdline:   %s\n' \
            "$(tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null || printf '[unreadable]')"

        # Cumulative byte counters since process start. read_bytes/write_bytes are
        # the ones that actually hit the block layer; rchar/wchar include cache.
        printf 'io:\n'
        if [[ -r "/proc/${pid}/io" ]]; then
            sed 's/^/  /' "/proc/${pid}/io" 2>/dev/null || printf '  [unreadable]\n'
        else
            printf '  [unavailable — needs root or same-user]\n'
        fi

        # Open files. lsof can block on a stalled mount, so it is timeout-bounded
        # and -b is passed to avoid the kernel calls that stall. /proc/<pid>/fd is
        # read regardless as the reliable fallback.
        printf 'open_files (lsof):\n'
        if command_exists lsof; then
            run_with_timeout "$tmo" lsof -n -P -b -w -p "$pid" 2>/dev/null \
                | head -n "${PANIC_IO_LSOF_LINES:-60}" | sed 's/^/  /' \
                || printf '  [lsof timed out or unavailable]\n'
        else
            printf '  [lsof not installed]\n'
        fi

        printf 'open_files (/proc/%s/fd):\n' "$pid"
        run_with_timeout "$tmo" ls -l "/proc/${pid}/fd" 2>/dev/null \
            | head -n "${PANIC_IO_LSOF_LINES:-60}" | sed 's/^/  /' \
            || printf '  [unreadable]\n'
    } >>"$file" 2>/dev/null

    return 0
}

# --- offender table ----------------------------------------------------------

# Renders the ranked TSV as the human-facing "offending processes" table.
io_render_table() {
    local tsv="$1"
    local limit="${PANIC_IO_TABLE_ROWS:-20}"

    if [[ ! -s "$tsv" ]]; then
        printf 'No per-process I/O recorded in this window.\n'
        printf 'If pidstat is missing, install sysstat; kB_rd/s requires kernel I/O accounting.\n'
        return 0
    fi

    printf '%-8s %-18s %10s %10s %10s %8s %7s  %s\n' \
        PID COMMAND READ_KBs WRITE_KBs TOTAL_KBs IODELAY SAMPLES PCT_IO
    printf '%s\n' '--------------------------------------------------------------------------------------------'
    awk -F'\t' -v lim="$limit" '
        NR > lim { exit }
        { printf "%-8s %-18.18s %10.2f %10.2f %10.2f %8d %7d  %5.1f%%\n", \
            $1, $2, $3, $4, $5, $6, $7, $8 }
    ' "$tsv"
}

# --- entry point -------------------------------------------------------------

# Captures the full I/O attribution set for one panic snapshot.
# Writes:
#   ${dir}/io-${index}.log        human-readable capture
#   ${dir}/offenders-${index}.tsv machine-readable ranked table
# Raises incident meta: peak_io_kbs, peak_io_pid, peak_io_comm.
capture_io_forensics() {
    local dir="$1"
    local index="$2"
    local file="${dir}/io-${index}.log"
    local tsv="${dir}/offenders-${index}.tsv"

    local samples="${PANIC_IO_SAMPLES:-10}"
    local interval="${PANIC_IO_INTERVAL:-1}"
    # Sampling needs samples*interval seconds; add slack for process start-up so a
    # healthy run is never reported as a timeout.
    local window=$((samples * interval))
    local tmo=$((window + 10))

    local work
    work="$(mktemp -d "${dir}/.io-${index}.XXXXXX" 2>/dev/null)" || work=""
    if [[ -z "$work" ]]; then
        log_warn "io forensics: could not create work dir; skipping snapshot ${index}"
        return 0
    fi

    {
        printf 'Server Forensics I/O Attribution Snapshot\n'
        printf 'snapshot=%s\n' "$index"
        printf 'created_at=%s\n' "$(now_iso)"
        printf 'window=%ss (%s samples x %ss)\n' "$window" "$samples" "$interval"
    } >"$file"

    # --- PSI first: instantaneous, and it classifies the stall before anything
    # else has had time to change the picture.
    io_header "$file" "PSI (/proc/pressure)"
    if [[ -d /proc/pressure ]]; then
        local res
        for res in io cpu memory; do
            printf '\n--- /proc/pressure/%s ---\n' "$res" >>"$file"
            cat "/proc/pressure/${res}" 2>/dev/null >>"$file" \
                || printf '[unreadable]\n' >>"$file"
        done
    else
        printf 'SKIPPED: /proc/pressure not present (kernel lacks CONFIG_PSI)\n' >>"$file"
    fi

    # --- the three samplers, concurrently over the same window ----------------
    io_run_bg "${work}/pidstat-d" "$tmo" pidstat -d -h "$interval" "$samples"
    io_run_bg "${work}/pidstat-u" "$tmo" pidstat -u -h "$interval" "$samples"
    io_run_bg "${work}/iostat"    "$tmo" iostat -x "$interval" "$samples"

    # Device and mount context while the samplers run — all instantaneous reads,
    # so they cost nothing and are done before the wait below returns.
    io_header "$file" "/proc/diskstats"
    cat /proc/diskstats 2>/dev/null >>"$file" || printf '[unreadable]\n' >>"$file"

    io_run_now "$file" "mount" mount
    io_run_now "$file" "findmnt" findmnt --real -o SOURCE,TARGET,FSTYPE,OPTIONS
    io_run_now "$file" "findmnt -D (usage)" findmnt -D -o SOURCE,TARGET,FSTYPE,SIZE,USED,AVAIL,USE%

    wait

    io_merge "$file" "pidstat -d -h ${interval} ${samples} (per-process I/O)" "${work}/pidstat-d"
    io_merge "$file" "pidstat -u -h ${interval} ${samples} (per-process CPU)" "${work}/pidstat-u"
    io_merge "$file" "iostat -x ${interval} ${samples} (per-device)" "${work}/iostat"

    # --- ranking --------------------------------------------------------------
    io_rank_offenders "${work}/pidstat-d" >"$tsv" 2>/dev/null || : >"$tsv"

    io_header "$file" "OFFENDING PROCESSES (ranked by disk read+write)"
    io_render_table "$tsv" >>"$file"

    # --- per-offender detail --------------------------------------------------
    io_header "$file" "offender detail (>${PANIC_IO_OFFENDER_PCT:-5}% of observed I/O)"
    local pid found=0
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        found=1
        io_offender_detail "$file" "$pid"
    done < <(io_select_offenders "$tsv")
    [[ "$found" -eq 1 ]] || printf '\nNo process crossed the I/O threshold in this window.\n' >>"$file"

    # --- raise incident peaks -------------------------------------------------
    io_update_peaks "$dir" "$tsv"

    rm -rf -- "$work" 2>/dev/null || true
    incident_meta_set "$dir" last_io_log "$file"
    log_warn "captured io attribution ${index}: ${file}"
}

# Raises the incident's top-I/O-process meta from a snapshot's ranked table, so
# the worst offender across the whole incident survives even after the verbose
# per-snapshot logs are rotated away.
io_update_peaks() {
    local dir="$1"
    local tsv="$2"
    local top pid comm kbs old

    [[ -s "$tsv" ]] || return 0

    top="$(head -n 1 "$tsv")"
    [[ -n "$top" ]] || return 0

    IFS=$'\t' read -r pid comm _ _ kbs _ _ _ <<<"$top"
    old="$(incident_meta_get "$dir" peak_io_kbs 0)"

    if num_gt "${kbs:-0}" "${old:-0}"; then
        incident_meta_set "$dir" peak_io_kbs "$kbs"
        incident_meta_set "$dir" peak_io_pid "$pid"
        incident_meta_set "$dir" peak_io_comm "$comm"
    fi
}

# --- cross-snapshot aggregation ----------------------------------------------

# Merges every offenders-*.tsv in an incident into one table keyed by PID,
# keeping each PID's PEAK observed rate and summing its sample count. This is the
# incident-level answer to "which process was consuming I/O", as opposed to the
# per-snapshot view.
io_aggregate_offenders() {
    local dir="$1"
    local -a files=()

    mapfile -t files < <(find "$dir" -maxdepth 1 -type f -name 'offenders-*.tsv' 2>/dev/null | sort)
    [[ "${#files[@]}" -gt 0 ]] || return 0

    awk -F'\t' '
        {
            pid = $1
            if (($5 + 0) > (peak[pid] + 0)) {
                peak[pid] = $5 + 0
                rd[pid]   = $3 + 0
                wr[pid]   = $4 + 0
            }
            if (($6 + 0) > (del[pid] + 0)) del[pid] = $6 + 0
            if ($2 != "?" && $2 != "") comm[pid] = $2
            n[pid]  += $7
            seen[pid]++
        }
        END {
            for (p in peak) grand += peak[p]
            for (p in peak) {
                pct = (grand > 0 ? (peak[p] * 100.0) / grand : 0)
                printf "%s\t%s\t%.2f\t%.2f\t%.2f\t%d\t%d\t%.1f\n", \
                    p, (comm[p] == "" ? "?" : comm[p]), rd[p], wr[p], peak[p], \
                    del[p], n[p], pct
            }
        }
    ' "${files[@]}" | sort -t"$(printf '\t')" -k5 -rn
}
