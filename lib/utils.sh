#!/usr/bin/env bash
# Shared utility functions for server-forensics.
# shellcheck disable=SC2034

SERVER_FORENSICS_VERSION="0.1.0"

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

sf_is_bool_value() {
    case "${1:-}" in
        0 | 1 | true | TRUE | false | FALSE | yes | YES | no | NO | on | ON | off | OFF) return 0 ;;
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
    COLLECTOR_COMMAND_TIMEOUT="${COLLECTOR_COMMAND_TIMEOUT:-1}"
    MYSQL_DEFAULTS_FILE="${MYSQL_DEFAULTS_FILE:-}"
    PANIC_SNAPSHOT_INTERVAL="${PANIC_SNAPSHOT_INTERVAL:-10}"
    PANIC_COMMAND_TIMEOUT="${PANIC_COMMAND_TIMEOUT:-20}"
    PANIC_OUTPUT_LINES="${PANIC_OUTPUT_LINES:-5000}"
    ENABLE_DSTATE_FORENSICS="${ENABLE_DSTATE_FORENSICS:-1}"
    PANIC_CAPTURE_KERNEL_STACK="${PANIC_CAPTURE_KERNEL_STACK:-1}"
    PANIC_DSTATE_MAX_PIDS="${PANIC_DSTATE_MAX_PIDS:-25}"
    PANIC_CAPTURE_PSI="${PANIC_CAPTURE_PSI:-1}"
    ENABLE_IO_FORENSICS="${ENABLE_IO_FORENSICS:-1}"
    PANIC_IO_SAMPLES="${PANIC_IO_SAMPLES:-10}"
    PANIC_IO_INTERVAL="${PANIC_IO_INTERVAL:-1}"
    PANIC_IO_OFFENDER_PCT="${PANIC_IO_OFFENDER_PCT:-5}"
    PANIC_IO_MIN_OFFENDERS="${PANIC_IO_MIN_OFFENDERS:-3}"
    PANIC_IO_MAX_OFFENDERS="${PANIC_IO_MAX_OFFENDERS:-10}"
    PANIC_IO_TABLE_ROWS="${PANIC_IO_TABLE_ROWS:-20}"
    PANIC_IO_MAX_LINES="${PANIC_IO_MAX_LINES:-20000}"
    PANIC_IO_LSOF_LINES="${PANIC_IO_LSOF_LINES:-60}"
    PANIC_IO_DETAIL_TIMEOUT="${PANIC_IO_DETAIL_TIMEOUT:-5}"
    ENABLE_PLUGINS="${ENABLE_PLUGINS:-1}"
    PLUGIN_TIMEOUT="${PLUGIN_TIMEOUT:-1}"
    PLUGIN_DIRS="${PLUGIN_DIRS:-${SF_ROOT}/plugins/metrics:/etc/server-forensics/plugins/metrics}"

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

    validate_config
}

fail_config() {
    printf 'Configuration error: %s\n' "$*" >&2
    return 1
}

is_uint() {
    [[ "${1:-}" =~ ^[0-9]+$ ]]
}

is_number() {
    [[ "${1:-}" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

validate_path_value() {
    local name="$1"
    local value="$2"

    [[ -n "$value" ]] || fail_config "$name must not be empty"
    [[ "$value" == /* ]] || fail_config "$name must be an absolute path: $value"

    case "$value" in
        "/" | "/bin" | "/boot" | "/dev" | "/etc" | "/home" | "/lib" | "/lib64" | "/opt" | "/proc" | "/root" | "/run" | "/sbin" | "/sys" | "/tmp" | "/usr" | "/var" | "/var/log")
            fail_config "$name is too broad: $value"
            ;;
    esac
}

validate_config() {
    local plugin_dir

    is_uint "$INTERVAL" || fail_config "INTERVAL must be a non-negative integer"
    [[ "$INTERVAL" -ge 10 ]] || fail_config "INTERVAL must be at least 10 seconds"

    is_number "$LOAD_THRESHOLD" || fail_config "LOAD_THRESHOLD must be numeric"
    is_uint "$LSPHP_THRESHOLD" || fail_config "LSPHP_THRESHOLD must be a non-negative integer"
    is_uint "$MEMORY_THRESHOLD_MB" || fail_config "MEMORY_THRESHOLD_MB must be a non-negative integer"
    is_uint "$ESTABLISHED_THRESHOLD" || fail_config "ESTABLISHED_THRESHOLD must be a non-negative integer"
    is_uint "$DSTATE_THRESHOLD" || fail_config "DSTATE_THRESHOLD must be a non-negative integer"
    is_uint "$PANIC_COOLDOWN" || fail_config "PANIC_COOLDOWN must be a non-negative integer"
    is_uint "$KEEP_INCIDENTS" || fail_config "KEEP_INCIDENTS must be a non-negative integer"
    is_uint "$COLLECTOR_COMMAND_TIMEOUT" || fail_config "COLLECTOR_COMMAND_TIMEOUT must be a non-negative integer"
    [[ "$COLLECTOR_COMMAND_TIMEOUT" -ge 1 ]] || fail_config "COLLECTOR_COMMAND_TIMEOUT must be at least 1 second"
    is_uint "$PANIC_SNAPSHOT_INTERVAL" || fail_config "PANIC_SNAPSHOT_INTERVAL must be a non-negative integer"
    [[ "$PANIC_SNAPSHOT_INTERVAL" -ge 1 ]] || fail_config "PANIC_SNAPSHOT_INTERVAL must be at least 1 second"
    is_uint "$PANIC_COMMAND_TIMEOUT" || fail_config "PANIC_COMMAND_TIMEOUT must be a non-negative integer"
    [[ "$PANIC_COMMAND_TIMEOUT" -ge 1 ]] || fail_config "PANIC_COMMAND_TIMEOUT must be at least 1 second"
    is_uint "$PANIC_OUTPUT_LINES" || fail_config "PANIC_OUTPUT_LINES must be a non-negative integer"
    [[ "$PANIC_OUTPUT_LINES" -ge 100 ]] || fail_config "PANIC_OUTPUT_LINES must be at least 100"

    sf_is_bool_value "$ENABLE_DSTATE_FORENSICS" || fail_config "ENABLE_DSTATE_FORENSICS must be a boolean value"
    sf_is_bool_value "$PANIC_CAPTURE_KERNEL_STACK" || fail_config "PANIC_CAPTURE_KERNEL_STACK must be a boolean value"
    sf_is_bool_value "$PANIC_CAPTURE_PSI" || fail_config "PANIC_CAPTURE_PSI must be a boolean value"
    is_uint "$PANIC_DSTATE_MAX_PIDS" || fail_config "PANIC_DSTATE_MAX_PIDS must be a non-negative integer"
    [[ "$PANIC_DSTATE_MAX_PIDS" -ge 1 ]] || fail_config "PANIC_DSTATE_MAX_PIDS must be at least 1"

    sf_is_bool_value "$ENABLE_IO_FORENSICS" || fail_config "ENABLE_IO_FORENSICS must be a boolean value"
    is_uint "$PANIC_IO_SAMPLES" || fail_config "PANIC_IO_SAMPLES must be a non-negative integer"
    [[ "$PANIC_IO_SAMPLES" -ge 1 ]] || fail_config "PANIC_IO_SAMPLES must be at least 1"
    is_uint "$PANIC_IO_INTERVAL" || fail_config "PANIC_IO_INTERVAL must be a non-negative integer"
    [[ "$PANIC_IO_INTERVAL" -ge 1 ]] || fail_config "PANIC_IO_INTERVAL must be at least 1"
    is_number "$PANIC_IO_OFFENDER_PCT" || fail_config "PANIC_IO_OFFENDER_PCT must be numeric"
    is_uint "$PANIC_IO_MIN_OFFENDERS" || fail_config "PANIC_IO_MIN_OFFENDERS must be a non-negative integer"
    is_uint "$PANIC_IO_MAX_OFFENDERS" || fail_config "PANIC_IO_MAX_OFFENDERS must be a non-negative integer"
    [[ "$PANIC_IO_MAX_OFFENDERS" -ge 1 ]] || fail_config "PANIC_IO_MAX_OFFENDERS must be at least 1"
    [[ "$PANIC_IO_MAX_OFFENDERS" -ge "$PANIC_IO_MIN_OFFENDERS" ]] \
        || fail_config "PANIC_IO_MAX_OFFENDERS must be >= PANIC_IO_MIN_OFFENDERS"
    is_uint "$PANIC_IO_TABLE_ROWS" || fail_config "PANIC_IO_TABLE_ROWS must be a non-negative integer"
    [[ "$PANIC_IO_TABLE_ROWS" -ge 1 ]] || fail_config "PANIC_IO_TABLE_ROWS must be at least 1"
    is_uint "$PANIC_IO_MAX_LINES" || fail_config "PANIC_IO_MAX_LINES must be a non-negative integer"
    [[ "$PANIC_IO_MAX_LINES" -ge 100 ]] || fail_config "PANIC_IO_MAX_LINES must be at least 100"
    is_uint "$PANIC_IO_LSOF_LINES" || fail_config "PANIC_IO_LSOF_LINES must be a non-negative integer"
    is_uint "$PANIC_IO_DETAIL_TIMEOUT" || fail_config "PANIC_IO_DETAIL_TIMEOUT must be a non-negative integer"
    [[ "$PANIC_IO_DETAIL_TIMEOUT" -ge 1 ]] || fail_config "PANIC_IO_DETAIL_TIMEOUT must be at least 1"

    validate_path_value LOG_DIR "$LOG_DIR"

    if [[ -n "${MYSQL_DEFAULTS_FILE:-}" ]]; then
        [[ "$MYSQL_DEFAULTS_FILE" == /* ]] || fail_config "MYSQL_DEFAULTS_FILE must be absolute: $MYSQL_DEFAULTS_FILE"
    fi

    while IFS= read -r plugin_dir; do
        [[ -n "$plugin_dir" ]] || continue
        [[ "$plugin_dir" == /* ]] || fail_config "PLUGIN_DIRS entries must be absolute paths: $plugin_dir"
    done < <(printf '%s\n' "$PLUGIN_DIRS" | tr ':' '\n')

    if ! sf_is_bool_value "$ENABLE_PLUGINS"; then
        fail_config "ENABLE_PLUGINS must be 0, 1, true, false, yes, no, on, or off"
    fi

    is_uint "$PLUGIN_TIMEOUT" || fail_config "PLUGIN_TIMEOUT must be a non-negative integer"
    [[ "$PLUGIN_TIMEOUT" -ge 1 ]] || fail_config "PLUGIN_TIMEOUT must be at least 1 second"
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

# The numeric helpers force operands through `+0` so a non-numeric value such as
# the `NA` sentinel (emitted when a metric has no baseline yet) collapses to 0
# instead of triggering awk's lexical string comparison — where, for example,
# "NA" > "20" is true. Without this, a missing IO-wait reading would look like
# high storage wait, and num_max could let NA overwrite a real peak.
num_gt() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN { exit !((a + 0) > (b + 0)) }'
}

num_lt() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN { exit !((a + 0) < (b + 0)) }'
}

num_max() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN { if ((a + 0) > (b + 0)) print a; else print b }'
}

num_min() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN { if ((a + 0) < (b + 0)) print a; else print b }'
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

canonical_path() {
    if command_exists realpath; then
        realpath -m -- "$1"
    elif command_exists readlink; then
        readlink -f -- "$1"
    else
        return 1
    fi
}

path_is_under() {
    local child="$1"
    local parent="$2"
    local child_real parent_real

    child_real="$(canonical_path "$child")"
    parent_real="$(canonical_path "$parent")"

    [[ "$child_real" == "$parent_real"/* ]]
}

write_file_atomic() {
    local target="$1"
    local tmp="${target}.$$"
    cat >"$tmp"
    mv -f -- "$tmp" "$target"
}
