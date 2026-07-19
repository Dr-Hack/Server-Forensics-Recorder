#!/usr/bin/env bash
# Lightweight metric collection and threshold evaluation.
# shellcheck disable=SC2154

read_uptime_seconds() {
    awk '{ print int($1) }' /proc/uptime 2>/dev/null || printf '0\n'
}

read_load_fields() {
    awk '{ print $1, $2, $3 }' /proc/loadavg 2>/dev/null || printf '0 0 0\n'
}

read_cpu_busy_pct() {
    # /proc/stat counters are cumulative since boot, so a single reading only
    # yields the lifetime average. We persist the previous sample and report the
    # busy percentage over the delta since the last collection instead. The first
    # sample after boot (or a cleared state dir) has no baseline and reports NA.
    local state_file="${STATE_DIR}/cpu_stat"
    local cpu_now cur_total cur_idle prev_total prev_idle

    cpu_now="$(awk '
        /^cpu / {
            total = 0
            for (i = 2; i <= NF; i++) total += $i
            printf "%d %d\n", total, $5 + $6
            exit
        }
    ' /proc/stat 2>/dev/null || true)"

    if [[ -z "$cpu_now" ]]; then
        printf 'NA\n'
        return 0
    fi
    read -r cur_total cur_idle <<<"$cpu_now"

    if [[ -r "$state_file" ]]; then
        read -r prev_total prev_idle <"$state_file" 2>/dev/null || true
    fi

    printf '%s %s\n' "$cur_total" "$cur_idle" >"$state_file" 2>/dev/null || true

    if [[ -z "${prev_total:-}" ]]; then
        printf 'NA\n'
        return 0
    fi

    awk -v ct="$cur_total" -v ci="$cur_idle" -v pt="$prev_total" -v pi="$prev_idle" '
        BEGIN {
            dt = ct - pt
            di = ci - pi
            if (dt <= 0) { print "NA"; exit }
            busy = (dt - di) / dt * 100
            if (busy < 0) busy = 0
            if (busy > 100) busy = 100
            printf "%.1f\n", busy
        }
    '
}

read_memory_fields() {
    awk '
        /MemTotal:/ { mem_total = int($2 / 1024) }
        /MemAvailable:/ { mem_available = int($2 / 1024) }
        /SwapTotal:/ { swap_total = int($2 / 1024) }
        /SwapFree:/ { swap_free = int($2 / 1024) }
        END {
            printf "%d %d %d %d\n", mem_total, mem_available, swap_total, swap_free
        }
    ' /proc/meminfo 2>/dev/null || printf '0 0 0 0\n'
}

read_apache_workers() {
    local count=0

    if command_exists pgrep; then
        count="$(pgrep -cx httpd 2>/dev/null || true)"
        if [[ "$count" -eq 0 ]]; then
            count="$(pgrep -cx apache2 2>/dev/null || true)"
        fi
    elif command_exists ps; then
        count="$(ps -eo comm= 2>/dev/null | awk '$1 == "httpd" || $1 == "apache2" { c++ } END { print c + 0 }')"
    fi

    printf '%s\n' "${count:-0}"
}

read_lsphp_fields() {
    if ! command_exists ps; then
        printf '0 0 0\n'
        return 0
    fi

    ps -eo comm=,etimes= 2>/dev/null | awk '
        $1 ~ /^lsphp/ {
            count++
            total += $2
            if ($2 > oldest) oldest = $2
        }
        END {
            if (count > 0) avg = int(total / count)
            else avg = 0
            printf "%d %d %d\n", count + 0, avg + 0, oldest + 0
        }
    '
}

read_mariadb_running() {
    if command_exists pgrep && { pgrep -x mariadbd >/dev/null 2>&1 || pgrep -x mysqld >/dev/null 2>&1; }; then
        printf '1\n'
    else
        printf '0\n'
    fi
}

# Prints five fields: threads_running threads_connected questions uptime
# slow_queries. All fields are NA when mysqladmin is missing or authentication
# genuinely fails; a single extended-status call supplies every value.
read_mysql_status_fields() {
    if ! command_exists mysqladmin; then
        printf 'NA NA NA NA NA\n'
        return 0
    fi

    local output
    if ! output="$(run_with_timeout "$COLLECTOR_COMMAND_TIMEOUT" mysqladmin --connect-timeout=1 extended-status 2>/dev/null)"; then
        printf 'NA NA NA NA NA\n'
        return 0
    fi

    awk -F'|' '
        {
            key = $2
            value = $3
            gsub(/^[ \t]+|[ \t]+$/, "", key)
            gsub(/^[ \t]+|[ \t]+$/, "", value)
            vals[key] = value
        }
        END {
            split("Threads_running Threads_connected Questions Uptime Slow_queries", want, " ")
            line = ""
            for (i = 1; i <= 5; i++) {
                v = (want[i] in vals) ? vals[want[i]] : "NA"
                line = line (i > 1 ? " " : "") v
            }
            print line
        }
    ' <<<"$output"
}

read_exim_queue() {
    if ! command_exists exim; then
        printf 'NA\n'
        return 0
    fi

    local output
    if output="$(run_with_timeout "$COLLECTOR_COMMAND_TIMEOUT" exim -bpc 2>/dev/null)"; then
        trim "$output"
    else
        printf 'NA\n'
    fi
}

read_tcp_summary() {
    awk '
        NR > 1 {
            states[$4]++
        }
        END {
            printf "%d %d %d %d\n", states["01"] + 0, states["06"] + 0, states["08"] + 0, states["03"] + 0
        }
    ' /proc/net/tcp /proc/net/tcp6 2>/dev/null || printf '0 0 0 0\n'
}

read_dstate_processes() {
    if ! command_exists ps; then
        printf '0\n'
        return 0
    fi

    ps -eo stat= 2>/dev/null | awk '$1 ~ /^D/ { c++ } END { print c + 0 }'
}

collect_metrics_line() {
    local timestamp epoch uptime load1 load5 load15 cpu_busy
    local mem_total mem_available swap_total swap_free
    local apache_workers lsphp_count lsphp_avg_age lsphp_oldest_age
    local mariadb_running threads_running threads_connected
    local mysql_questions mysql_uptime mysql_slow_queries exim_queue
    local tcp_established tcp_time_wait tcp_close_wait tcp_syn_recv dstate

    timestamp="$(now_iso)"
    epoch="$(now_epoch)"
    uptime="$(read_uptime_seconds)"
    read -r load1 load5 load15 <<<"$(read_load_fields)"
    cpu_busy="$(read_cpu_busy_pct)"
    read -r mem_total mem_available swap_total swap_free <<<"$(read_memory_fields)"
    apache_workers="$(read_apache_workers)"
    read -r lsphp_count lsphp_avg_age lsphp_oldest_age <<<"$(read_lsphp_fields)"
    mariadb_running="$(read_mariadb_running)"
    read -r threads_running threads_connected mysql_questions mysql_uptime mysql_slow_queries \
        <<<"$(read_mysql_status_fields)"
    exim_queue="$(read_exim_queue)"
    read -r tcp_established tcp_time_wait tcp_close_wait tcp_syn_recv <<<"$(read_tcp_summary)"
    dstate="$(read_dstate_processes)"

    printf 'timestamp=%s epoch=%s uptime_seconds=%s load1=%s load5=%s load15=%s cpu_busy_pct=%s mem_total_mb=%s mem_available_mb=%s swap_total_mb=%s swap_free_mb=%s apache_workers=%s lsphp_count=%s lsphp_avg_age=%s lsphp_oldest_age=%s mariadb_running=%s threads_running=%s threads_connected=%s mysql_questions=%s mysql_uptime_seconds=%s mysql_slow_queries=%s exim_queue=%s tcp_established=%s tcp_time_wait=%s tcp_close_wait=%s tcp_syn_recv=%s dstate_processes=%s%s\n' \
        "$timestamp" "$epoch" "$uptime" "$load1" "$load5" "$load15" "$cpu_busy" \
        "$mem_total" "$mem_available" "$swap_total" "$swap_free" "$apache_workers" \
        "$lsphp_count" "$lsphp_avg_age" "$lsphp_oldest_age" "$mariadb_running" \
        "$threads_running" "$threads_connected" "$mysql_questions" "$mysql_uptime" \
        "$mysql_slow_queries" "$exim_queue" "$tcp_established" \
        "$tcp_time_wait" "$tcp_close_wait" "$tcp_syn_recv" "$dstate" "$(collect_plugin_metrics)"
}

metrics_unhealthy_reason() {
    local line="$1"
    local reasons=()
    local load1 lsphp_count mem_available tcp_established dstate

    load1="$(metric_value "$line" load1)"
    lsphp_count="$(metric_value "$line" lsphp_count)"
    mem_available="$(metric_value "$line" mem_available_mb)"
    tcp_established="$(metric_value "$line" tcp_established)"
    dstate="$(metric_value "$line" dstate_processes)"

    if num_gt "${load1:-0}" "$LOAD_THRESHOLD"; then
        reasons+=("load1=${load1}>${LOAD_THRESHOLD}")
    fi

    if num_gt "${lsphp_count:-0}" "$LSPHP_THRESHOLD"; then
        reasons+=("lsphp=${lsphp_count}>${LSPHP_THRESHOLD}")
    fi

    if num_lt "${mem_available:-0}" "$MEMORY_THRESHOLD_MB"; then
        reasons+=("mem_available_mb=${mem_available}<${MEMORY_THRESHOLD_MB}")
    fi

    if num_gt "${tcp_established:-0}" "$ESTABLISHED_THRESHOLD"; then
        reasons+=("tcp_established=${tcp_established}>${ESTABLISHED_THRESHOLD}")
    fi

    if num_gt "${dstate:-0}" "$DSTATE_THRESHOLD"; then
        reasons+=("dstate=${dstate}>${DSTATE_THRESHOLD}")
    fi

    if [[ "${#reasons[@]}" -gt 0 ]]; then
        local IFS=','
        printf '%s\n' "${reasons[*]}"
        return 0
    fi

    return 1
}

metrics_are_healthy() {
    local line="$1"
    ! metrics_unhealthy_reason "$line" >/dev/null
}
