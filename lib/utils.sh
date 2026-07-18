#!/usr/bin/env bash
# Shared utility functions for server-forensics.
# shellcheck disable=SC2034

sf_root() {
    if [[ -n "${SF_ROOT:-}" ]]; then
        printf '%s\n' "$SF_ROOT"
        return 0
    fi

    local source_dir
    source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
    printf '%s\n' "$source_dir"
}

sf_bool() {
    case "${1:-0}" in
        1 | true | TRUE | yes | YES | on | ON) return 0 ;;
        *) return 1 ;;
    esac
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

ensure_dir() {
    mkdir -p -- "$1"
}

now_iso() {
    date '+%Y-%m-%dT%H:%M:%S%z'
}

now_id() {
    date '+%Y%m%d-%H%M%S'
}

now_epoch() {
    date '+%s'
}

trim() {
    local value="${1:-}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s\n' "$value"
}

load_config() {
    SF_ROOT="$(sf_root)"

    # Built-in safe defaults. config.conf normally overrides these.
    INTERVAL="${INTERVAL:-60}"
    LOAD_THRESHOLD="${LOAD_THRESHOLD:-10}"
    LSPHP_THRESHOLD="${LSPHP_THRESHOLD:-40}"
    MEMORY_THRESHOLD_MB="${MEMORY_THRESHOLD_MB:-500}"
    ESTABLISHED_THRESHOLD="${ESTABLISHED_THRESHOLD:-300}"
    DSTATE_THRESHOLD="${DSTATE_THRESHOLD:-5}"
    PANIC_COOLDOWN="${PANIC_COOLDOWN:-300}"
    KEEP_INCIDENTS="${KEEP_INCIDENTS:-100}"
    LOG_DIR="${LOG_DIR:-/var/log/server-forensics}"
    DEBUG="${DEBUG:-0}"
    VERBOSE="${VERBOSE:-1}"
    QUIET="${QUIET:-0}"
    PANIC_SNAPSHOT_INTERVAL="${PANIC_SNAPSHOT_INTERVAL:-10}"
    PANIC_COMMAND_TIMEOUT="${PANIC_COMMAND_TIMEOUT:-20}"

    local bundled_config="${SF_ROOT}/config.conf"
    local system_config="/etc/server-forensics/config.conf"
    local explicit_config="${SF_CONFIG:-}"

    if [[ -r "$bundled_config" ]]; then
        # shellcheck source=/dev/null
        source "$bundled_config"
    fi

    if [[ -r "$system_config" ]]; then
        # shellcheck source=/dev/null
        source "$system_config"
    fi

    if [[ -n "$explicit_config" && -r "$explicit_config" ]]; then
        # shellcheck source=/dev/null
        source "$explicit_config"
    fi

    INCIDENT_DIR="${LOG_DIR}/incidents"
    ARCHIVE_DIR="${LOG_DIR}/archive"
    STATE_DIR="${LOG_DIR}/.state"
    CURRENT_LOG="${LOG_DIR}/current.log"
    DAEMON_LOG="${LOG_DIR}/server-forensics.log"
}

metric_value() {
    local line="${1:-}"
    local key="${2:-}"
    awk -v wanted="${key}=" '
        {
            for (i = 1; i <= NF; i++) {
                if (index($i, wanted) == 1) {
                    sub(wanted, "", $i)
                    print $i
                    exit
                }
            }
        }
    ' <<<"$line"
}

num_gt() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN { exit !(a > b) }'
}

num_lt() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN { exit !(a < b) }'
}

num_max() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN { if (a > b) print a; else print b }'
}

num_min() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN { if (a < b) print a; else print b }'
}

run_with_timeout() {
    local seconds="$1"
    shift

    if command_exists timeout; then
        timeout "$seconds" "$@"
    else
        "$@"
    fi
}

write_file_atomic() {
    local target="$1"
    local tmp="${target}.$$"
    cat >"$tmp"
    mv -f -- "$tmp" "$target"
}
