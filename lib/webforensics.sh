#!/usr/bin/env bash
# Web request attribution.
#
# The per-process capture proves PHP saturated the box; the ring buffer names the
# script (e.g. wp-admin/admin-ajax.php). This module answers the last question a
# single-account operator has: which URL, from which client IP, over the incident
# window. That lives only in the web server's access log, not in /proc.
#
# Two facts about this host shape the whole module:
#   - It is Apache + mod_lsapi on cPanel, so the access logs are per-domain
#     "domlogs" in combined format under /etc/apache2/logs/domlogs (and legacy
#     paths). One file per vhost, appended chronologically.
#   - It sits behind Cloudflare. Every TCP peer is a Cloudflare edge, so `ss` and
#     the log's own client-IP column show Cloudflare, NOT the attacker — unless
#     mod_remoteip/mod_cloudflare restores the real IP. When the client IPs are
#     all a known CDN, this module says so rather than fingering Cloudflare, and
#     points at the CF-Connecting-IP header / Cloudflare analytics instead.
#
# Cost discipline (see docs and forensics-must-not-worsen-outage): logs are read
# with a bounded tail, never fully; every read is timeout-wrapped; nothing here
# touches the network or a package manager. The incident has just closed, so the
# relevant lines are at the END of each active log — a tail covers the window.
# shellcheck disable=SC2154

# Candidate directories holding per-domain access logs, most-preferred first.
# Overridable via WEBLOG_DIRS (space-separated) for non-cPanel layouts.
web_log_dirs() {
    if [[ -n "${WEBLOG_DIRS:-}" ]]; then
        # Intentional word-splitting: WEBLOG_DIRS is a space-separated list.
        # shellcheck disable=SC2086
        printf '%s\n' $WEBLOG_DIRS
        return 0
    fi
    cat <<'DIRS'
/etc/apache2/logs/domlogs
/usr/local/apache/domlogs
/var/log/apache2/domlogs
/usr/local/lsws/logs
DIRS
}

# First existing log directory, or empty. Kept separate so --requests can report
# "no log directory found" distinctly from "directory found but no lines".
web_first_log_dir() {
    local d
    while IFS= read -r d; do
        [[ -n "$d" && -d "$d" ]] || continue
        printf '%s\n' "$d"
        return 0
    done < <(web_log_dirs)
    return 0
}

# True when an IPv4 address falls in a well-known Cloudflare range. Not exhaustive
# and not a security control — it exists only to decide whether the log's client
# IPs are the CDN (so the "top IP" is meaningless) or the real origin traffic.
web_ip_is_cloudflare() {
    case "${1:-}" in
        104.1[6-9].*|104.2[0-7].*|172.6[4-9].*|172.7[01].*|162.158.*|162.159.*|\
        173.245.4[89].*|173.245.5[0-9].*|108.162.*|141.101.6[4-9].*|141.101.[7-9]*.*|\
        141.101.1[0-2][0-9].*|190.93.24*|188.114.9[6-9].*|188.114.1*|197.234.24*|\
        198.41.12[89].*|198.41.1[3-9][0-9].*|198.41.2*|131.0.7[2-5].*|103.21.244.*|\
        103.21.245.*|103.21.246.*|103.21.247.*|103.22.20[0-3].*|103.31.[4-7].*)
            return 0 ;;
        *) return 1 ;;
    esac
}

# The box's own global IP addresses, one per line, discovered at RUNTIME — never
# hardcoded, so nothing here embeds a server address. WordPress and cPanel make
# loopback/self-requests (wp-cron, admin-ajax health pings) that appear in the
# access log as the server hitting itself; labelling them stops the operator
# mistaking their own IP for a client, and makes a real attacker stand alone.
# Always succeeds: a host without `hostname -I` or `ip` simply yields nothing.
web_self_ips() {
    {
        hostname -I 2>/dev/null | tr ' ' '\n'
        ip -o addr show scope global 2>/dev/null | awk '{ print $4 }' | cut -d/ -f1
    } 2>/dev/null | grep -E '[0-9a-fA-F]' | sort -u || true
}

# Renders a "count <TAB> domain" tally (stdin: domain-tagged rows) into the
# per-vhost section. Kept separate so it can be unit-tested with a fixture.
web_render_domain_counts() {
    awk -F'\t' '{ c[$1]++ } END { for (d in c) printf "%d\t%s\n", c[d], d }' \
        | sort -rn | head -n "${WEBLOG_TOP_ROWS:-20}" \
        | awk -F'\t' '{ printf "  %8d  %s\n", $1, $2 }'
}

# Renders the host + URI table (stdin: domain-tagged rows —
# domain <TAB> stamp <TAB> ip <TAB> status <TAB> method <TAB> path <TAB> ua <TAB> dur).
# This is the granular answer WordPress hides: with pretty permalinks every
# front-end request executes index.php, so per-executable/endpoint views collapse
# them — but the access log still carries the real URI (/checkout, /product/…).
# Ranked by request count; adds an average-milliseconds column when the log
# carried %D (dur>0), and otherwise prints a one-line hint on how to enable it.
# Kept separate so it can be unit-tested with a fixture.
web_render_host_uri() {
    awk -F'\t' -v top="${WEBLOG_TOP_ROWS:-20}" '
        {
            key = $1 SUBSEP $6
            if (!(key in cnt)) { dom[key] = $1; uri[key] = $6 }
            cnt[key]++
            dur[key] += ($8 + 0)
            if (($8 + 0) > 0) havedur = 1
        }
        END {
            n = 0
            for (k in cnt) ord[++n] = k
            for (a = 1; a <= n; a++)
                for (b = a + 1; b <= n; b++)
                    if (cnt[ord[b]] > cnt[ord[a]]) { t = ord[a]; ord[a] = ord[b]; ord[b] = t }

            if (havedur)
                printf "  %-26s %-40s %9s %9s\n", "HOST", "URI", "REQUESTS", "AVG_MS"
            else
                printf "  %-26s %-40s %9s\n", "HOST", "URI", "REQUESTS"

            lim = (n < top ? n : top)
            for (a = 1; a <= lim; a++) {
                k = ord[a]
                if (havedur)
                    printf "  %-26.26s %-40.40s %9d %9.1f\n", dom[k], uri[k], cnt[k], (dur[k] / cnt[k]) / 1000.0
                else
                    printf "  %-26.26s %-40.40s %9d\n", dom[k], uri[k], cnt[k]
            }
            if (!havedur)
                printf "  (response time unavailable — add %%D to the domlog LogFormat to rank by time)\n"
        }
    '
}

# Reads combined-format access-log lines on stdin and emits a normalised TSV for
# those whose timestamp falls within [lo, hi], where lo/hi are sortable numeric
# stamps YYYYMMDDHHMMSS. Comparing pre-formatted local time avoids any dependence
# on gawk's mktime (absent on mawk/busybox) and on process timezone: the recorder
# and the logs share one host, one clock.
#
# Output columns:  stamp <TAB> ip <TAB> status <TAB> method <TAB> path <TAB> ua <TAB> dur
# The request/UA are lifted by splitting on the quote character, so leading fields
# (a restored real IP, extra columns) cannot shift them. `dur` is the request
# duration if the LogFormat appends %D after the user-agent (0 otherwise); it is
# a best-effort trailing-number read and the 7th column is additive, so anything
# consuming columns 1-6 is unaffected.
web_filter_window() {
    local lo="$1" hi="$2"
    awk -v lo="$lo" -v hi="$hi" '
        BEGIN {
            split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " ")
            for (i = 1; i <= 12; i++) mon[mn[i]] = sprintf("%02d", i)
        }
        {
            # Locate the "[dd/Mon/yyyy:hh:mm:ss" bracket token anywhere on the line.
            stamp = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^\[[0-9]{2}\/[A-Za-z]{3}\/[0-9]{4}:/) {
                    t = substr($i, 2)              # drop leading [
                    split(t, d, /[\/:]/)           # d: dd Mon yyyy hh mm ss
                    if (d[2] in mon)
                        stamp = d[3] mon[d[2]] d[1] d[4] d[5] d[6]
                    break
                }
            }
            if (stamp == "" || stamp+0 < lo+0 || stamp+0 > hi+0) next

            ip = $1
            n = split($0, q, "\"")
            if (n < 2) next
            req = q[2]                              # GET /path HTTP/1.1
            ua = (n >= 6 ? q[6] : "-")
            split(req, r, " "); method = r[1]; path = r[2]
            # split on a single space collapses the leading blank, so " 200 1234 "
            # yields s[1]=status, s[2]=bytes.
            split(q[3], s, " "); status = s[1]
            # For AJAX/admin endpoints, keep the `action` parameter — it names the
            # plugin/feature responsible (e.g. admin-ajax.php?action=edd_download).
            # Only GET actions reach the log (a POST action is in the body, which
            # Apache does not record). Keep action ONLY, dropping ids/nonces, so
            # the table does not explode by unique query string. Everything else
            # drops the query entirely to keep path aggregation clean.
            if (path ~ /(admin-ajax|admin-post)\.php\?/) {
                query = path; sub(/^[^?]*\?/, "", query)
                base = path;  sub(/\?.*$/, "", base)
                action = ""
                mq = split(query, kv, "&")
                for (j = 1; j <= mq; j++) if (kv[j] ~ /^action=/) { action = kv[j]; break }
                path = (action != "" ? base "?" action : base)
            } else {
                sub(/\?.*$/, "", path)
            }
            if (path == "") path = "-"
            if (method == "") method = "-"
            if (status == "") status = "-"
            # %D (request microseconds), if the LogFormat appended it after the UA
            # quote. Best-effort: the first number in the post-UA remainder.
            dur = 0
            if (n >= 7) { tail = q[7]; if (match(tail, /[0-9]+/)) dur = substr(tail, RSTART, RLENGTH) + 0 }
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", stamp, ip, status, method, path, ua, dur
        }
    '
}

# Aggregates normalised rows (stdin) into the request report. Emits top paths,
# top client IPs, abuse-endpoint tallies, and a CDN caveat when the client IPs
# are Cloudflare. Pure text-processing; safe to unit-test with a fixture.
web_report() {
    local rows top abuse
    rows="$(cat)"
    top="${WEBLOG_TOP_ROWS:-20}"
    abuse="${WEBLOG_ABUSE_ENDPOINTS:-xmlrpc.php wp-login.php admin-ajax.php admin-post.php wp-cron.php}"

    local total
    total="$(printf '%s' "$rows" | grep -c . || true)"
    if [[ "${total:-0}" -eq 0 ]]; then
        printf 'No access-log lines fell within the incident window.\n'
        printf '(Either the site is idle-logged, logs rotated, or the vhost logs elsewhere.)\n'
        return 0
    fi

    printf 'Requests in window: %s\n\n' "$total"

    # Suppressed when the caller already printed the richer host+URI table (which
    # subsumes this cross-vhost path rollup). Kept for the fallback path and for
    # direct/standalone use where no per-domain tagging exists.
    if [[ -z "${WEBLOG_SKIP_PATHS:-}" ]]; then
        printf 'Top request paths (by hits):\n'
        printf '%s\n' "$rows" | awk -F'\t' '{ c[$5]++ } END { for (p in c) printf "%d\t%s\n", c[p], p }' \
            | sort -rn | head -n "$top" \
            | awk '{ printf "  %8d  %s\n", $1, $2 }'
        printf '\n'
    fi

    printf 'Top client IPs (by hits):\n'
    # SF_SELF_IPS (newline/space-separated) marks the server's own addresses so a
    # self-request row is labelled benign rather than read as a client.
    printf '%s\n' "$rows" | awk -F'\t' '{ c[$2]++ } END { for (p in c) printf "%d\t%s\n", c[p], p }' \
        | sort -rn | head -n "$top" \
        | awk -v self="${SF_SELF_IPS:-}" '
            BEGIN { n = split(self, a, /[ \t\n]+/); for (i = 1; i <= n; i++) if (a[i] != "") s[a[i]] = 1 }
            { tag = ($2 in s) ? "   <- this server (loopback / self-request, benign)" : ""
              printf "  %8d  %s%s\n", $1, $2, tag }'

    # CDN caveat: if the busiest client IPs are Cloudflare, the column above is the
    # edge, not the attacker. Decide from the top few IPs by volume.
    local ip cdn=0 seen=0
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        seen=$((seen + 1))
        if web_ip_is_cloudflare "$ip"; then cdn=$((cdn + 1)); fi
    done < <(printf '%s\n' "$rows" | awk -F'\t' '{ c[$2]++ } END { for (p in c) printf "%d\t%s\n", c[p], p }' \
        | sort -rn | head -n 10 | awk '{ print $2 }')
    if [[ "$seen" -gt 0 && $((cdn * 2)) -ge "$seen" ]]; then
        printf '\n  NOTE: the client IPs above are Cloudflare edges, not the real clients.\n'
        printf '        The attacker IP is only in the CF-Connecting-IP / X-Forwarded-For\n'
        printf '        header. Restore it with mod_remoteip, or read it from Cloudflare\n'
        printf '        analytics/firewall. Block abusive traffic at Cloudflare, not CSF\n'
        printf '        (CSF would only ban Cloudflare edges).\n'
    fi

    printf '\nKnown-abuse endpoints hit in window:\n'
    local ep hits found=0
    for ep in $abuse; do
        hits="$(printf '%s\n' "$rows" | awk -F'\t' -v e="$ep" '$5 ~ e { n++ } END { print n + 0 }')"
        if [[ "${hits:-0}" -gt 0 ]]; then
            printf '  %8d  %s\n' "$hits" "$ep"
            found=1
        fi
    done
    [[ "$found" -eq 1 ]] || printf '  (none of the usual WordPress abuse endpoints appeared)\n'

    printf '\nTop user agents (by hits):\n'
    printf '%s\n' "$rows" | awk -F'\t' '{ c[$6]++ } END { for (p in c) printf "%d\t%s\n", c[p], p }' \
        | sort -rn | head -n "$((top / 2 > 0 ? top / 2 : 5))" \
        | awk -F'\t' '{ printf "  %8d  %s\n", $1, substr($2, 1, 90) }' 2>/dev/null \
        || printf '  (unavailable)\n'
}

# Converts an epoch to the sortable local stamp the window filter compares against.
# GNU date on the target; the recorder and logs share the host timezone.
web_epoch_to_stamp() {
    date -d "@${1}" +%Y%m%d%H%M%S 2>/dev/null || printf '0'
}

# Orchestrates a capture for a closed incident: reads a bounded tail of each
# domain log, filters to the incident window, and writes web.txt. Never fails the
# caller — an absent log directory or empty window is reported in the file.
#
# The body runs in a SUBSHELL, not a brace group: it uses `exit` for early
# returns, and inside `{ }` that would terminate the whole recorder (panic.sh
# calls this at incident close). A subshell scopes the exits to the capture.
web_capture() {
    local dir="$1"
    local out="${dir}/web.txt"

    (
        local start end lo hi logdir max tagged
        start="$(incident_meta_get "$dir" started_epoch 0)"
        end="$(incident_meta_get "$dir" ended_epoch 0)"
        max="${WEBLOG_MAX_LINES:-200000}"

        printf '===== Web request attribution =====\n'
        printf 'generated=%s\n' "$(now_iso 2>/dev/null || date -Iseconds)"

        if [[ "${start:-0}" -le 0 ]]; then
            printf 'incident has no recorded start epoch; cannot bound the window.\n'
            exit 0
        fi
        [[ "${end:-0}" -gt 0 ]] || end="$(now_epoch 2>/dev/null || date +%s)"
        lo="$(web_epoch_to_stamp "$start")"
        hi="$(web_epoch_to_stamp "$end")"
        printf 'window=%s..%s\n\n' "$lo" "$hi"

        logdir="$(web_first_log_dir)"
        if [[ -z "$logdir" ]]; then
            printf 'No access-log directory found. Set WEBLOG_DIRS if this host stores\n'
            printf 'domain logs elsewhere. Searched:\n'
            web_log_dirs | sed 's/^/  /'
            exit 0
        fi
        printf 'log_dir=%s\n\n' "$logdir"

        local -a files=()
        mapfile -t files < <(find "$logdir" -maxdepth 1 -type f \
            ! -name '*.gz' ! -name '*.processed' 2>/dev/null | sort)
        if [[ "${#files[@]}" -eq 0 ]]; then
            printf 'log_dir has no active (uncompressed) log files.\n'
            exit 0
        fi

        # Discovered live so web_report can label the box's own loopback rows.
        SF_SELF_IPS="$(web_self_ips)"
        export SF_SELF_IPS

        # Bounded, timeout-wrapped tail of each active log, each row tagged with its
        # domain (the log filename) so the same stream yields both a per-vhost tally
        # and the combined report. The per-file line cap bounds a busy vhost; the
        # window filter discards everything older regardless.
        tagged="$(mktemp 2>/dev/null || true)"
        if [[ -n "$tagged" ]]; then
            local f
            for f in "${files[@]}"; do
                run_with_timeout "${WEBLOG_READ_TIMEOUT:-5}" tail -n "$max" "$f" 2>/dev/null \
                    | web_filter_window "$lo" "$hi" \
                    | awk -v d="$(basename "$f")" 'BEGIN { OFS = "\t" } { print d, $0 }'
            done >"$tagged"

            printf 'Requests per domain (vhost):\n'
            web_render_domain_counts <"$tagged"
            printf '\n'

            # The granular view: real URLs per vhost (index.php resolved to the
            # actual page). Subsumes web_report's cross-vhost path rollup, so
            # WEBLOG_SKIP_PATHS suppresses that to avoid printing it twice.
            printf 'Top requests (host + URI, by hits):\n'
            web_render_host_uri <"$tagged"
            printf '\n'

            cut -f2- "$tagged" | WEBLOG_SKIP_PATHS=1 web_report
            rm -f -- "$tagged" 2>/dev/null || true
        else
            # No temp file available: fall back to the combined report without the
            # per-domain tally rather than failing the capture.
            local f
            for f in "${files[@]}"; do
                run_with_timeout "${WEBLOG_READ_TIMEOUT:-5}" tail -n "$max" "$f" 2>/dev/null
            done | web_filter_window "$lo" "$hi" | web_report
        fi
    ) >"$out" 2>/dev/null

    return 0
}
