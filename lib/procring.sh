#!/usr/bin/env bash
# Pre-incident process ring buffer.
#
# The problem this solves: panic mode is triggered by load1, which is a
# one-minute exponentially-weighted average and therefore LAGS the work that
# caused it. On production incident-20260724-193525 the burst ran from roughly
# 19:34:30 to 19:35:30; the trigger fired at 19:35:25 and the first per-process
# sampler window landed after the workers had already exited. The offender table
# accounted for ~49% of a machine that had been at 374%, and the top process read
# 9% — because the culprits were gone.
#
# No trigger can outrun that. If the first per-process measurement happens after
# the trigger, a sub-minute burst is always measured on its way down. The fix is
# to sample continuously and cheaply, and let the incident look BACKWARDS.
#
# Cost control: a full sample is one `ps` plus one `awk`, aggregated by
# executable, keeping only the top rows. Between samples the watcher polls
# /proc/loadavg, which is a single small read of a file the kernel maintains
# anyway. Sampling runs at RINGBUFFER_SLOW_INTERVAL normally and accelerates to
# RINGBUFFER_FAST_INTERVAL only while load is elevated, so the steady-state cost
# on an idle server is one `ps` per minute.
#
# The ring never triggers an incident. It only records, so enabling it cannot
# change when panic mode fires.
# shellcheck disable=SC2154

ring_file() {
    printf '%s\n' "${LOG_DIR}/procring.log"
}

# Instantaneous load1, read straight from /proc/loadavg. This is the cheap poll
# that decides whether to accelerate; it must stay free enough to run every few
# seconds forever.
ring_load1() {
    local l
    if [[ -r /proc/loadavg ]]; then
        read -r l _ </proc/loadavg 2>/dev/null || l=0
        printf '%s\n' "${l:-0}"
    else
        printf '0\n'
    fi
}

# True while load justifies fast sampling. Deliberately far below
# LOAD_THRESHOLD: the point is to already be sampling quickly by the time the
# panic threshold is crossed.
ring_should_accelerate() {
    num_gt "$(ring_load1)" "${RINGBUFFER_FAST_LOAD:-3}"
}

# Writes one ring sample: per-executable totals plus the top individual PIDs.
#
# `ps pcpu` is a lifetime average rather than an instantaneous rate, which is the
# right trade here — the processes this is meant to catch are seconds old, so
# their lifetime average IS their current burn, and it costs one ps instead of
# two sampling passes.
ring_sample() {
    local file
    file="$(ring_file)"

    command_exists ps || return 0

    # `ps -eo` is not available on every shell environment (notably Git Bash on
    # the development machine), so the process listing and the parsing of it are
    # kept separate: ring_format is fed real captured `ps` output by the test
    # suite. A parser that can only be exercised on the target host is a parser
    # that ships broken — see docs/decisions.md.
    #
    # `args=` is captured LAST because it is the only variable-width field: fields
    # 1-5 stay fixed-position and everything from field 6 on is the command line.
    # It carries the mod_lsapi worker's rewritten argv ("lsphp:<script>"), which is
    # the ONLY place the PHP endpoint is visible — pidstat and comm both show a
    # bare "lsphp". On a single-account box the endpoint is the actionable unit.
    ps -eo pid=,comm=,pcpu=,rss=,stat=,args= 2>/dev/null | ring_format >>"$file" 2>/dev/null || return 0

    return 0
}

# Parses `ps -eo pid=,comm=,pcpu=,rss=,stat=,args=` on stdin into ring lines.
# Fields 1-5 are fixed; field 6 onward is the command line (args=), which is
# optional — captured input without it (older fixtures) simply yields no PHP rows.
ring_format() {
    local now top_execs top_pids top_php
    now="$(now_epoch)"
    top_execs="${RINGBUFFER_TOP_EXECS:-15}"
    top_pids="${RINGBUFFER_TOP_PIDS:-10}"
    top_php="${RINGBUFFER_TOP_PHP:-10}"

    awk -v now="$now" -v iso="$(now_iso)" -v nexec="$top_execs" -v npid="$top_pids" -v nphp="$top_php" '
        # Extracts a stable PHP endpoint key from a worker command line. mod_lsapi
        # rewrites argv to "lsphp:<script path>" and overwrites it IN PLACE, so a
        # long path is FRONT-truncated ("ackne/site.com/wp-admin/admin-post.php").
        # The tail is always intact, so the key is the last two path components:
        # meaningful ("wp-admin/admin-post.php") and stable across truncation.
        # Returns "" for anything that is not actively serving a .php script
        # (idle "lsphp" workers, non-PHP processes).
        function php_endpoint(args,   n, w, i, tok, script, base, rest, parent) {
            gsub(/lsphp:/, " ", args)
            gsub(/php-fpm:/, " ", args)
            n = split(args, w, /[ \t]+/)
            script = ""
            for (i = 1; i <= n; i++) {
                tok = w[i]
                sub(/\?.*$/, "", tok)          # drop any query string
                if (tok ~ /\.php$/) script = tok
            }
            if (script == "") return ""
            base = script
            sub(/.*\//, "", base)              # basename
            rest = script
            if (sub(/\/[^\/]*$/, "", rest) && rest != "") {
                parent = rest
                sub(/.*\//, "", parent)
                if (parent != "") return parent "/" base
            }
            return base
        }
        {
            pid = $1; comm = $2; cpu = $3 + 0; rss = $4 + 0; st = $5
            if (pid == "" || comm == "") next

            key = comm
            sub(/ .*$/, "", key)

            ecpu[key] += cpu
            erss[key] += rss
            eproc[key]++
            if (st ~ /^D/) edstate[key]++

            # Attribute PHP workers to the endpoint they are serving, when args
            # carries it. Everything from field 6 on is the command line.
            if (NF >= 6) {
                args = ""
                for (i = 6; i <= NF; i++) args = args (i > 6 ? " " : "") $i
                ep = php_endpoint(args)
                if (ep != "") { phpcpu[ep] += cpu; phpproc[ep]++ }
            }

            # Track the heaviest individual PIDs for the runaway case.
            np++
            ppid[np] = pid; pcomm[np] = comm; pcpu[np] = cpu; prss[np] = rss
        }
        END {
            # Executable rows, highest CPU first, capped.
            n = 0
            for (k in ecpu) { n++; ord[n] = k }
            for (a = 1; a <= n; a++)
                for (b = a + 1; b <= n; b++)
                    if (ecpu[ord[b]] > ecpu[ord[a]]) { t = ord[a]; ord[a] = ord[b]; ord[b] = t }
            lim = (n < nexec ? n : nexec)
            for (a = 1; a <= lim; a++) {
                k = ord[a]
                printf "ts=%s iso=%s kind=exec comm=%s procs=%d cpu=%.2f rss_mb=%.1f dstate=%d\n", \
                    now, iso, k, eproc[k], ecpu[k], erss[k] / 1024.0, edstate[k] + 0
            }

            # Individual PIDs, highest CPU first, capped.
            for (a = 1; a <= np; a++)
                for (b = a + 1; b <= np; b++)
                    if (pcpu[b] > pcpu[a]) {
                        t = ppid[a]; ppid[a] = ppid[b]; ppid[b] = t
                        t = pcomm[a]; pcomm[a] = pcomm[b]; pcomm[b] = t
                        t = pcpu[a]; pcpu[a] = pcpu[b]; pcpu[b] = t
                        t = prss[a]; prss[a] = prss[b]; prss[b] = t
                    }
            plim = (np < npid ? np : npid)
            for (a = 1; a <= plim; a++) {
                if (pcpu[a] <= 0) break
                printf "ts=%s iso=%s kind=pid pid=%s comm=%s cpu=%.2f rss_mb=%.1f\n", \
                    now, iso, ppid[a], pcomm[a], pcpu[a], prss[a] / 1024.0
            }

            # PHP endpoint rows, highest CPU first, capped. These name the request
            # behind the load on a single-account box, where by-executable is blind.
            m = 0
            for (k in phpcpu) { m++; hord[m] = k }
            for (a = 1; a <= m; a++)
                for (b = a + 1; b <= m; b++)
                    if (phpcpu[hord[b]] > phpcpu[hord[a]]) { t = hord[a]; hord[a] = hord[b]; hord[b] = t }
            hlim = (m < nphp ? m : nphp)
            for (a = 1; a <= hlim; a++) {
                k = hord[a]
                printf "ts=%s iso=%s kind=php script=%s procs=%d cpu=%.2f\n", \
                    now, iso, k, phpproc[k], phpcpu[k]
            }
        }
    '
}

# Drops entries older than the retention window. Rewritten in place through a
# temp file so a reader never sees a half-truncated ring.
ring_trim() {
    local file cutoff tmp
    file="$(ring_file)"
    [[ -s "$file" ]] || return 0

    cutoff=$(($(now_epoch) - ${RINGBUFFER_RETAIN_SECONDS:-900}))
    tmp="${file}.$$"

    awk -v cutoff="$cutoff" '
        { ts = $1; sub(/^ts=/, "", ts); if (ts + 0 >= cutoff) print }
    ' "$file" >"$tmp" 2>/dev/null && mv -f -- "$tmp" "$file" 2>/dev/null
    rm -f -- "$tmp" 2>/dev/null || true
    return 0
}

# One full ring cycle: sample, then trim. Safe to call from the watcher on every
# invocation; never fails the caller.
ring_tick() {
    sf_bool "${ENABLE_PROC_RING:-1}" || return 0
    ring_sample
    ring_trim
    return 0
}

# The bounded poll loop the watcher runs when it did NOT enter panic mode.
#
# It polls /proc/loadavg every RINGBUFFER_POLL_INTERVAL seconds and takes a full
# sample only while load is elevated. It deliberately does NOT evaluate panic
# thresholds: panic still fires only on the timer tick, so enabling the ring
# cannot change when incidents are declared.
ring_poll_window() {
    sf_bool "${ENABLE_PROC_RING:-1}" || return 0
    sf_bool "${RINGBUFFER_POLL:-1}" || return 0

    local window="${RINGBUFFER_POLL_WINDOW:-45}"
    local poll="${RINGBUFFER_POLL_INTERVAL:-10}"
    local fast="${RINGBUFFER_FAST_INTERVAL:-10}"
    local started elapsed last_sample=0 now

    [[ "$window" -gt 0 && "$poll" -gt 0 ]] || return 0

    started="$(now_epoch)"
    while true; do
        sleep "$poll"
        now="$(now_epoch)"
        elapsed=$((now - started))
        [[ "$elapsed" -lt "$window" ]] || break

        if ring_should_accelerate && [[ $((now - last_sample)) -ge "$fast" ]]; then
            ring_sample
            last_sample="$now"
        fi
    done

    ring_trim
    return 0
}

# --- retrieval ----------------------------------------------------------------

# Prints the ring entries covering an incident's run-up: from
# RINGBUFFER_LOOKBACK_SECONDS before the incident started, up to when it ended.
# This is the window the panic samplers cannot reach.
ring_window() {
    local start="$1"
    local end="${2:-}"
    local file lookback
    file="$(ring_file)"
    [[ -s "$file" ]] || return 0

    lookback="${RINGBUFFER_LOOKBACK_SECONDS:-300}"
    [[ -n "$end" && "$end" -gt 0 ]] || end=9999999999

    awk -v lo="$((start - lookback))" -v hi="$end" '
        { ts = $1; sub(/^ts=/, "", ts); ts += 0; if (ts >= lo && ts <= hi) print }
    ' "$file" 2>/dev/null
}

# Aggregates the run-up window by executable, so "what was building up before
# the trigger fired" is answerable in one table:
#   comm <TAB> peak_procs <TAB> peak_cpu <TAB> samples
ring_window_by_exec() {
    ring_window "$1" "${2:-}" | awk '
        $0 ~ /kind=exec/ {
            comm = ""; procs = 0; cpu = 0
            for (i = 1; i <= NF; i++) {
                if (index($i, "comm=") == 1)  { comm = substr($i, 6) }
                else if (index($i, "procs=") == 1) { procs = substr($i, 7) + 0 }
                else if (index($i, "cpu=") == 1)   { cpu = substr($i, 5) + 0 }
            }
            if (comm == "") next
            if (procs > maxp[comm]) maxp[comm] = procs
            if (cpu > maxc[comm]) maxc[comm] = cpu
            n[comm]++
        }
        END { for (c in n) printf "%s\t%d\t%.2f\t%d\n", c, maxp[c], maxc[c], n[c] }
    ' | sort -t"$(printf '\t')" -k3,3 -rn
}

# Aggregates the run-up window by PHP endpoint, so "which request was building"
# is answerable directly on a single-account box:
#   script <TAB> peak_procs <TAB> peak_cpu <TAB> samples
ring_window_by_php() {
    ring_window "$1" "${2:-}" | awk '
        $0 ~ /kind=php/ {
            script = ""; procs = 0; cpu = 0
            for (i = 1; i <= NF; i++) {
                if (index($i, "script=") == 1)     { script = substr($i, 8) }
                else if (index($i, "procs=") == 1) { procs = substr($i, 7) + 0 }
                else if (index($i, "cpu=") == 1)   { cpu = substr($i, 5) + 0 }
            }
            if (script == "") next
            if (procs > maxp[script]) maxp[script] = procs
            if (cpu > maxc[script]) maxc[script] = cpu
            n[script]++
        }
        END { for (s in n) printf "%s\t%d\t%.2f\t%d\n", s, maxp[s], maxc[s], n[s] }
    ' | sort -t"$(printf '\t')" -k3,3 -rn
}

# Renders the run-up as a compact per-sample timeline of the busiest executable,
# which is what actually shows a worker pool building.
ring_render_runup() {
    local start="$1"
    local end="${2:-}"

    ring_window "$start" "$end" | awk '
        $0 ~ /kind=exec/ {
            iso = ""; comm = ""; procs = 0; cpu = 0; ts = 0
            for (i = 1; i <= NF; i++) {
                if (index($i, "ts=") == 1)         ts = substr($i, 4) + 0
                else if (index($i, "iso=") == 1)   iso = substr($i, 5)
                else if (index($i, "comm=") == 1)  comm = substr($i, 6)
                else if (index($i, "procs=") == 1) procs = substr($i, 7) + 0
                else if (index($i, "cpu=") == 1)   cpu = substr($i, 5) + 0
            }
            if (comm == "") next
            if (cpu > best[ts]) { best[ts] = cpu; bcomm[ts] = comm; bprocs[ts] = procs; biso[ts] = iso }
            tot[ts] += cpu
        }
        END {
            n = 0
            for (t in best) { n++; ord[n] = t }
            for (a = 1; a <= n; a++)
                for (b = a + 1; b <= n; b++)
                    if (ord[b] + 0 < ord[a] + 0) { tmp = ord[a]; ord[a] = ord[b]; ord[b] = tmp }
            if (n == 0) { print "  (no ring samples cover this window)"; exit }
            for (a = 1; a <= n; a++) {
                t = ord[a]
                clock = biso[t]
                sub(/^.*T/, "", clock); sub(/[+-][0-9].*$/, "", clock)
                printf "  %s  total_cpu=%-7.1f top=%-16.16s procs=%-4d cpu=%.1f\n", \
                    clock, tot[t], bcomm[t], bprocs[t], best[t]
            }
        }
    '
}
