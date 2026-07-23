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

# PIDs of the samplers started by io_run_bg, so io_wait_jobs can wait on exactly
# those. A bare `wait` would also block on any unrelated background job in the
# caller's shell, which would hang the capture for as long as that job runs.
SF_IO_JOBS=()

# Runs a command into its own file in the BACKGROUND. Used for the three
# concurrent samplers. Never allowed to outlive the timeout, and never allowed to
# write more than PANIC_IO_MAX_LINES — a box with thousands of processes must not
# be able to fill the disk it is already stalled on.
io_run_bg() {
    local out="$1"
    local timeout_s="$2"
    shift 2
    local command_name="$1"
    local max_lines="${PANIC_IO_MAX_LINES:-20000}"

    if ! command_exists "$command_name"; then
        printf 'SKIPPED: command not found: %s\n' "$command_name" >"$out"
        return 0
    fi

    (
        # The producer is killed by SIGPIPE once head has taken its fill, which
        # pipefail would otherwise report as a failure, so the pipeline status is
        # inspected explicitly rather than trusted.
        set +e
        run_with_timeout "$timeout_s" "$@" 2>&1 | head -n "$max_lines" >"$out"
        rc=${PIPESTATUS[0]}
        if [[ "$rc" -eq 124 ]]; then
            printf '\n[timed out after %ss]\n' "$timeout_s" >>"$out"
        elif [[ "$rc" -eq 141 ]]; then
            printf '\n[output capped at %s lines]\n' "$max_lines" >>"$out"
        elif [[ "$rc" -ne 0 ]]; then
            printf '\n[exited with status %s]\n' "$rc" >>"$out"
        fi
    ) &
    SF_IO_JOBS+=("$!")
}

# Waits for exactly the samplers this capture started, then clears the list.
io_wait_jobs() {
    local job
    for job in "${SF_IO_JOBS[@]:-}"; do
        [[ -n "$job" ]] || continue
        wait "$job" 2>/dev/null || true
    done
    SF_IO_JOBS=()
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
# `iodelay`, some emit `kB_ccwr/s`).
#
# The comment marker is stripped from the header BEFORE splitting, because
# sysstat emits both "# Time ..." (marker as its own token) and "#Time ..."
# (marker attached to the first column). Splitting the raw line makes those two
# forms disagree by one field, which silently resolves PID to the UID column and
# yields an empty offender table with no error — the worst possible failure for
# this module. After stripping, header index maps 1:1 onto data field index.
io_rank_offenders() {
    local pidstat_out="$1"

    io_rank_pidstat "$pidstat_out" 'kB_rd/s' 'kB_wr/s' '' 'iodelay'
}

# Ranks the per-process CPU sampler the same way, so a compute-bound incident
# names its culprit as directly as a storage-bound one does. %CPU is taken as the
# total rather than summing %usr and %system, because pidstat reports it directly
# and the two components do not always add up to it.
io_rank_cpu() {
    local pidstat_out="$1"

    io_rank_pidstat "$pidstat_out" '%usr' '%system' '%CPU' '%wait'
}

# The shared pidstat ranker. Emits one TSV row per PID:
#
#   pid <TAB> comm <TAB> colA <TAB> colB <TAB> total <TAB> extra
#       <TAB> samples <TAB> pct_of_total
#
# Column positions are resolved by NAME from pidstat's own header, never
# hardcoded, because the layout varies across sysstat versions AND locales:
#
#   - The comment marker is emitted both as its own token ("# Time ...") and
#     attached to the first column ("#Time ..."), so it is stripped before the
#     header is split.
#   - The timestamp occupies ONE field when pidstat emits an epoch or a 24-hour
#     clock, but TWO when the locale is 12-hour ("07:27:10 PM"). sysstat 11.7.3
#     on el8 does exactly this. The width is detected from the data row and every
#     column index is anchored from the left by that offset. It cannot be derived
#     from the field count, because Command itself contains spaces for some
#     processes ("lfd - sleeping").
#   - Older builds omit iodelay, %guest or %wait entirely.
#
# Getting this wrong is silent: indices shift, PID resolves to the UID column,
# and every row is discarded, leaving an empty table and no error at all.
io_rank_pidstat() {
    local pidstat_out="$1"
    local col_a="$2"
    local col_b="$3"
    local col_total="$4"
    local col_extra="$5"
    local max_pids="${PANIC_IO_MAX_TRACKED_PIDS:-5000}"

    [[ -r "$pidstat_out" ]] || return 0

    awk -v ca="$col_a" -v cb="$col_b" -v ct="$col_total" -v cx="$col_extra" \
        -v maxpids="$max_pids" '
        # --- header: resolve column layout by name -------------------------
        /^#/ && /PID/ {
            head = $0
            sub(/^#[ \t]*/, "", head)
            nh = split(head, hdr, /[ \t]+/)
            h_pid = h_a = h_b = h_t = h_x = h_cmd = 0
            for (i = 1; i <= nh; i++) {
                if (hdr[i] == "PID")            h_pid = i
                else if (hdr[i] == "Command")   h_cmd = i
                else if (ca != "" && hdr[i] == ca) h_a = i
                else if (cb != "" && hdr[i] == cb) h_b = i
                else if (ct != "" && hdr[i] == ct) h_t = i
                else if (cx != "" && hdr[i] == cx) h_x = i
            }
            next
        }

        # --- data rows -----------------------------------------------------
        # Accepts an epoch timestamp, a 24-hour clock, or a 12-hour clock whose
        # AM/PM suffix occupies a second field.
        (h_pid > 0) && ($1 ~ /^[0-9]+$/ || $1 ~ /^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9]$/) {
            off = ($2 == "AM" || $2 == "PM") ? 2 : 1
            d_pid = h_pid + off - 1
            if (d_pid > NF) next

            pid = $d_pid
            if (pid !~ /^[0-9]+$/ || pid == 0) next

            # Bound the tracked set. pidstat only lists active tasks, so this is
            # generous in practice, but a fork storm must not be able to grow the
            # ranking arrays without limit.
            if (!(pid in n) && tracked >= maxpids) next
            if (!(pid in n)) tracked++

            a = (h_a > 0 && h_a + off - 1 <= NF) ? $(h_a + off - 1) + 0 : 0
            b = (h_b > 0 && h_b + off - 1 <= NF) ? $(h_b + off - 1) + 0 : 0
            x = (h_x > 0 && h_x + off - 1 <= NF) ? $(h_x + off - 1) + 0 : 0
            t = (h_t > 0 && h_t + off - 1 <= NF) ? $(h_t + off - 1) + 0 : a + b

            sum_a[pid] += a
            sum_b[pid] += b
            sum_t[pid] += t
            n[pid]++
            if (x > maxx[pid]) maxx[pid] = x

            if (h_cmd > 0) {
                d_cmd = h_cmd + off - 1
                cmd = ""
                for (i = d_cmd; i <= NF; i++) cmd = cmd (i > d_cmd ? " " : "") $i
                if (cmd != "") comm[pid] = cmd
            }
        }

        END {
            for (p in n) {
                av_a[p] = sum_a[p] / n[p]
                av_b[p] = sum_b[p] / n[p]
                av_t[p] = sum_t[p] / n[p]
                grand += av_t[p]
            }
            for (p in n) {
                pct = (grand > 0 ? (av_t[p] * 100.0) / grand : 0)
                printf "%s\t%s\t%.2f\t%.2f\t%.2f\t%d\t%d\t%.1f\n", \
                    p, (comm[p] == "" ? "?" : comm[p]), av_a[p], av_b[p], av_t[p], \
                    maxx[p], n[p], pct
            }
        }
    ' "$pidstat_out" | sort -t"$(printf '\t')" -k5,5 -rn
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

# Renders ranked TSV rows on STDIN as the human-facing "offending processes"
# table. Stream-based so that read-only inspection commands never have to write a
# scratch file — writing one into the incident directory would fail for a
# non-root caller, and writing one at all is needless work during an outage.
# Column labels differ between the two rankings, so they are passed in rather
# than hardcoded; the row shape is identical for both.
io_render_stream() {
    local limit="${PANIC_IO_TABLE_ROWS:-20}"
    local kind="${1:-io}"
    local l_a l_b l_t l_x l_pct empty1 empty2

    if [[ "$kind" == "cpu" ]]; then
        l_a="USR_PCT" l_b="SYS_PCT" l_t="CPU_PCT" l_x="WAIT_PCT" l_pct="PCT_CPU"
        empty1="No per-process CPU recorded in this window."
        empty2="If pidstat is missing, install sysstat."
    else
        l_a="READ_KBs" l_b="WRITE_KBs" l_t="TOTAL_KBs" l_x="IODELAY" l_pct="PCT_IO"
        empty1="No per-process I/O recorded in this window."
        empty2="If pidstat is missing, install sysstat; kB_rd/s also requires kernel I/O accounting."
    fi

    awk -F'\t' -v lim="$limit" -v la="$l_a" -v lb="$l_b" -v lt="$l_t" \
        -v lx="$l_x" -v lp="$l_pct" -v e1="$empty1" -v e2="$empty2" '
        NR == 1 {
            printf "%-8s %-20s %10s %10s %10s %9s %7s  %s\n", \
                "PID", "COMMAND", la, lb, lt, lx, "SAMPLES", lp
            printf "%s\n", "----------------------------------------------------------------------------------------------"
        }
        NR > lim { exit }
        { printf "%-8s %-20.20s %10.2f %10.2f %10.2f %9d %7d  %5.1f%%\n", \
            $1, $2, $3, $4, $5, $6, $7, $8 }
        END {
            if (NR == 0) { print e1; print e2 }
        }
    '
}

# File-based wrapper, used by the capture path where the TSV is already on disk.
io_render_table() {
    local tsv="$1"
    local kind="${2:-io}"

    if [[ ! -s "$tsv" ]]; then
        io_render_stream "$kind" </dev/null
        return 0
    fi

    io_render_stream "$kind" <"$tsv"
}

# --- entry point -------------------------------------------------------------

# Captures the full resource-attribution set for one panic snapshot.
# Writes:
#   ${dir}/io-${index}.log            human-readable capture
#   ${dir}/offenders-${index}.tsv     ranked by disk read+write
#   ${dir}/cpuoffenders-${index}.tsv  ranked by CPU
# Raises incident meta: peak_io_{kbs,pid,comm} and peak_cpu_{pct,pid,comm}.
capture_io_forensics() {
    local dir="$1"
    local index="$2"
    local file="${dir}/io-${index}.log"
    local tsv="${dir}/offenders-${index}.tsv"
    local cputsv="${dir}/cpuoffenders-${index}.tsv"

    local samples="${PANIC_IO_SAMPLES:-10}"
    local interval="${PANIC_IO_INTERVAL:-1}"
    # Sampling needs samples*interval seconds; add slack for process start-up so a
    # healthy run is never reported as a timeout.
    local window=$((samples * interval))
    local tmo=$((window + 10))

    # Clear any work directory left by a previous run that was killed mid-capture,
    # so a repeatedly-interrupted panic loop cannot accumulate them inside the
    # incident (which rotate.sh would then archive verbatim).
    rm -rf -- "${dir}/.io-${index}."* 2>/dev/null || true

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
    # S_TIME_FORMAT=ISO and LC_ALL=C ask sysstat for an unambiguous 24-hour clock
    # instead of a locale-dependent one. The parser copes with either, but a
    # deterministic format is one less thing that can silently vary per host.
    export S_TIME_FORMAT=ISO
    export LC_ALL=C
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

    io_wait_jobs

    io_merge "$file" "pidstat -d -h ${interval} ${samples} (per-process I/O)" "${work}/pidstat-d"
    io_merge "$file" "pidstat -u -h ${interval} ${samples} (per-process CPU)" "${work}/pidstat-u"
    io_merge "$file" "iostat -x ${interval} ${samples} (per-device)" "${work}/iostat"

    # --- ranking --------------------------------------------------------------
    # Both dimensions are ranked. A spike is either compute-bound or blocked, and
    # the recorder must be able to name the culprit in either case rather than
    # only when the bottleneck happens to be storage.
    io_rank_offenders "${work}/pidstat-d" >"$tsv" 2>/dev/null || : >"$tsv"
    io_rank_cpu "${work}/pidstat-u" >"$cputsv" 2>/dev/null || : >"$cputsv"

    io_header "$file" "OFFENDING PROCESSES (ranked by disk read+write)"
    io_render_table "$tsv" io >>"$file"

    io_header "$file" "OFFENDING PROCESSES (ranked by CPU)"
    io_render_table "$cputsv" cpu >>"$file"

    # --- per-offender detail --------------------------------------------------
    # The union of both rankings, so a compute-bound culprit gets the same /proc
    # detail treatment as a storage-bound one.
    io_header "$file" "offender detail (>${PANIC_IO_OFFENDER_PCT:-5}% of observed I/O or CPU)"
    local pid found=0
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        found=1
        io_offender_detail "$file" "$pid"
    done < <({
        io_select_offenders "$tsv"
        io_select_offenders "$cputsv"
    } | awk '!seen[$0]++' | head -n "${PANIC_IO_MAX_OFFENDERS:-10}")
    [[ "$found" -eq 1 ]] || printf '\nNo process crossed the I/O or CPU threshold in this window.\n' >>"$file"

    # --- raise incident peaks -------------------------------------------------
    io_update_peaks "$dir" "$tsv"
    io_update_cpu_peaks "$dir" "$cputsv"

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

# The CPU equivalent. Kept separate from io_update_peaks because the two rankings
# have different leaders and both are worth retaining: an incident can be driven
# by one process burning CPU while a different one moves the bytes.
io_update_cpu_peaks() {
    local dir="$1"
    local tsv="$2"
    local top pid comm pct old

    [[ -s "$tsv" ]] || return 0

    top="$(head -n 1 "$tsv")"
    [[ -n "$top" ]] || return 0

    IFS=$'\t' read -r pid comm _ _ pct _ _ _ <<<"$top"
    old="$(incident_meta_get "$dir" peak_cpu_pct 0)"

    if num_gt "${pct:-0}" "${old:-0}"; then
        incident_meta_set "$dir" peak_cpu_pct "$pct"
        incident_meta_set "$dir" peak_cpu_pid "$pid"
        incident_meta_set "$dir" peak_cpu_comm "$comm"
    fi
}

# --- cross-snapshot aggregation ----------------------------------------------

# Merges every offenders-*.tsv in an incident into one table keyed by PID,
# keeping each PID's PEAK observed rate and summing its sample count. This is the
# incident-level answer to "which process was consuming I/O", as opposed to the
# per-snapshot view.
io_aggregate_offenders() {
    io_aggregate_tsv "$1" 'offenders-*.tsv'
}

# The CPU equivalent of io_aggregate_offenders.
io_aggregate_cpu() {
    io_aggregate_tsv "$1" 'cpuoffenders-*.tsv'
}

io_aggregate_tsv() {
    local dir="$1"
    local pattern="$2"
    local -a files=()

    # -name anchors at the start of the basename, so 'offenders-*.tsv' does not
    # also pick up 'cpuoffenders-*.tsv'. The two rankings stay separate.
    mapfile -t files < <(find "$dir" -maxdepth 1 -type f -name "$pattern" 2>/dev/null | sort)
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
    ' "${files[@]}" | sort -t"$(printf '\t')" -k5,5 -rn
}
