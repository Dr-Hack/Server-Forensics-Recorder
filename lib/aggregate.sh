#!/usr/bin/env bash
# Aggregation of per-process measurements by executable and subsystem.
#
# Ranking by PID is misleading for worker-pool workloads. On this server a spike
# to 93% CPU showed a top single process of 9%, because the load was spread
# across fourteen short-lived `lsphp` workers. No PID-ranked table can express
# "PHP took the box"; only a combined-by-executable view can.
#
# Two levels are produced:
#   - by executable  (lsphp, httpd, mariadbd, ...)   the actionable unit
#   - by subsystem   (PHP, Apache, MariaDB, ...)     the rollup, which collapses
#                                                    the ~9 differently-named
#                                                    Imunify daemons into one row
#
# Both are derived from the same offender TSVs the samplers already produce, so
# aggregation costs one awk pass over data already on disk.
# shellcheck disable=SC2154

# --- executable naming -------------------------------------------------------

# Normalises a process name into an executable key.
#
# `ps comm` truncates to 15 characters ("imunify-residen") and pidstat appends
# state text for some processes ("lfd - sleeping", "lfd - (child) c"). Without
# normalisation those become separate rows and the aggregation is defeated by
# the very cosmetics it is meant to see through.
sf_exec_key() {
    local raw="${1:-}"
    # Everything up to the first space; drops pidstat's trailing state text.
    raw="${raw%% *}"
    # Trailing punctuation left by truncation.
    raw="${raw%%,}"
    raw="${raw%-}"
    printf '%s\n' "${raw:-?}"
}

# --- subsystem classification -------------------------------------------------

# The executable -> subsystem map used for GROUPING AND DISPLAY.
#
# This is deliberately separate from `analysis_comm_subsystem` in lib/analysis.sh,
# which maps a *blocked* executable to a hypothesis for SCORING. The two have
# different jobs and must not be merged: this map wants every process attributed
# somewhere so the rollup totals add up (hence Mail, Init, Security, and kernel
# threads), whereas the scoring map must stay silent about processes that imply
# nothing about a root cause. Folding `rcu_sched` into "Filesystem" is right for
# a display rollup and wrong for a verdict.
sf_subsystem_of() {
    local c
    c="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$c" in
        *rsync* | *mysqldump* | *xtrabackup* | *mariabackup* | *cpbackup* | *pkgacct* | *jetbackup* | *backup* | tar) printf 'Backup\n' ;;
        mariadbd | mysqld | mysql) printf 'MariaDB\n' ;;
        *httpd* | *apache2* | *lsapi*) printf 'Apache\n' ;;
        *lsphp* | *php-fpm* | php*) printf 'PHP\n' ;;
        *dnf* | *yum* | *rpm* | *packagekit* | *leapp* | *upcp*) printf 'Package manager\n' ;;
        *clamscan* | *freshclam* | *imunify* | *cagefs* | *updatedb* | *mlocate*) printf 'Maintenance\n' ;;
        *jbd2* | *xfsaild* | *flush* | kworker* | ksoftirqd* | rcu_* | migration*) printf 'Filesystem\n' ;;
        *kswapd* | *kcompactd* | *khugepaged*) printf 'Memory\n' ;;
        *dovecot* | *exim* | *postmaster* | *postfix*) printf 'Mail\n' ;;
        systemd | init) printf 'Init\n' ;;
        *lfd* | *cphulkd* | *tailwatchd* | *p0f*) printf 'Security\n' ;;
        *) printf '\n' ;;
    esac
}

# Same, but never empty — used where a row must be attributed somewhere.
sf_subsystem_or_other() {
    local s
    s="$(sf_subsystem_of "$1")"
    printf '%s\n' "${s:-Other}"
}

# --- combined aggregation -----------------------------------------------------

# Joins the CPU and I/O offender rankings into one row per executable:
#
#   exec <TAB> subsystem <TAB> cpu_pct <TAB> read_kbs <TAB> write_kbs
#        <TAB> procs <TAB> peak_cpu <TAB> avg_cpu <TAB> peak_io <TAB> avg_io
#
# `procs` is the size of the union of PIDs seen under that executable in either
# ranking, so a worker pool is counted once even when its members appear in both.
# Sorted by combined CPU, then by combined I/O.
agg_combine() {
    local cpu_tsv="$1"
    local io_tsv="$2"
    local c="$cpu_tsv" i="$io_tsv"

    # A missing ranking is read as /dev/null rather than special-cased, so the
    # awk body stays a straight two-file join.
    [[ -s "$c" ]] || c=/dev/null
    [[ -s "$i" ]] || i=/dev/null
    [[ "$c" != /dev/null || "$i" != /dev/null ]] || return 0

    awk -F'\t' -v cpuf="$c" -v iof="$i" '
        function key(raw,   k) {
            k = raw
            sub(/ .*$/, "", k)        # drop pidstat state text
            sub(/,$/, "", k)
            if (k == "") k = "?"
            return k
        }
        FILENAME == cpuf {
            k = key($2); p = $1
            cpu[k]   += $5
            if (($5 + 0) > peakcpu[k]) peakcpu[k] = $5 + 0
            if (!((k SUBSEP p) in seen)) { seen[k SUBSEP p] = 1; procs[k]++ }
            ncpu[k]++
            next
        }
        FILENAME == iof {
            k = key($2); p = $1
            rd[k] += $3
            wr[k] += $4
            tot = $3 + $4
            if (tot > peakio[k]) peakio[k] = tot
            if (!((k SUBSEP p) in seen)) { seen[k SUBSEP p] = 1; procs[k]++ }
            nio[k]++
            next
        }
        END {
            for (k in procs) {
                n = procs[k]
                printf "%s\t%.2f\t%.2f\t%.2f\t%d\t%.2f\t%.2f\t%.2f\t%.2f\n", \
                    k, cpu[k] + 0, rd[k] + 0, wr[k] + 0, n, \
                    peakcpu[k] + 0, (n > 0 ? (cpu[k] + 0) / n : 0), \
                    peakio[k] + 0, (n > 0 ? (rd[k] + wr[k]) / n : 0)
            }
        }
    ' "$c" "$i" 2>/dev/null \
        | while IFS=$'\t' read -r k cpu rd wr n pkc avc pki avi; do
            [[ -n "$k" ]] || continue
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$k" "$(sf_subsystem_or_other "$k")" "$cpu" "$rd" "$wr" "$n" "$pkc" "$avc" "$pki" "$avi"
        done \
        | sort -t"$(printf '\t')" -k3,3 -rn
}

# Rolls the combined-by-executable rows up into subsystem totals.
# Input on stdin, output: subsystem <TAB> cpu <TAB> read <TAB> write <TAB> procs
agg_rollup() {
    awk -F'\t' '
        {
            s = $2
            cpu[s] += $3
            rd[s]  += $4
            wr[s]  += $5
            n[s]   += $6
        }
        END {
            for (s in n) printf "%s\t%.2f\t%.2f\t%.2f\t%d\n", s, cpu[s], rd[s], wr[s], n[s]
        }
    ' | sort -t"$(printf '\t')" -k2,2 -rn
}

# --- rendering ----------------------------------------------------------------

agg_render_combined() {
    local limit="${PANIC_IO_TABLE_ROWS:-20}"

    awk -F'\t' -v lim="$limit" '
        NR == 1 {
            printf "%-18s %-14s %8s %11s %11s %6s %8s %8s\n", \
                "EXECUTABLE", "SUBSYSTEM", "CPU%", "READ_KBs", "WRITE_KBs", \
                "PROCS", "PEAK_CPU", "AVG_CPU"
            printf "%s\n", "-----------------------------------------------------------------------------------------------"
        }
        NR > lim { exit }
        { printf "%-18.18s %-14.14s %8.2f %11.2f %11.2f %6d %8.2f %8.2f\n", \
            $1, $2, $3, $4, $5, $6, $7, $8 }
        END { if (NR == 0) print "No per-process data to aggregate." }
    '
}

agg_render_rollup() {
    awk -F'\t' '
        NR == 1 {
            printf "%-16s %8s %11s %11s %6s\n", "SUBSYSTEM", "CPU%", "READ_KBs", "WRITE_KBs", "PROCS"
            printf "%s\n", "--------------------------------------------------------"
        }
        { printf "%-16.16s %8.2f %11.2f %11.2f %6d\n", $1, $2, $3, $4, $5 }
        END { if (NR == 0) print "No subsystem totals available." }
    '
}

# --- distributed-load notice --------------------------------------------------

# States plainly when no single PID explains the load, so the reader is pointed
# at the aggregated totals instead of concluding "nothing was using the CPU".
# Thresholds: system CPU busy over AGG_DISTRIBUTED_CPU_PCT with a top single
# process under AGG_DISTRIBUTED_TOP_PCT.
agg_distributed_notice() {
    local total_cpu="$1"
    local top_single="$2"
    local hi="${AGG_DISTRIBUTED_CPU_PCT:-90}"
    local lo="${AGG_DISTRIBUTED_TOP_PCT:-15}"

    [[ "$total_cpu" != "NA" && -n "$total_cpu" ]] || return 1
    [[ -n "$top_single" ]] || top_single=0

    if num_gt "$total_cpu" "$hi" && num_lt "$top_single" "$lo"; then
        printf 'CPU usage is distributed across multiple processes; inspect aggregated executable totals rather than individual PIDs.\n'
        return 0
    fi
    return 1
}
