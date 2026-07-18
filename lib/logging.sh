#!/usr/bin/env bash
# Console and file logging helpers.
# shellcheck disable=SC2154

log_init() {
    ensure_dir "$LOG_DIR"
    ensure_dir "$INCIDENT_DIR"
    ensure_dir "$ARCHIVE_DIR"
    ensure_dir "$STATE_DIR"
    touch "$DAEMON_LOG" "$CURRENT_LOG"
}

log_line() {
    local level="$1"
    shift
    local message="$*"
    local line
    line="$(printf '%s [%s] %s\n' "$(now_iso)" "$level" "$message")"

    printf '%s\n' "$line" >>"$DAEMON_LOG"

    if ! sf_bool "$QUIET"; then
        case "$level" in
            DEBUG)
                sf_bool "$DEBUG" && printf '%s\n' "$line" >&2
                ;;
            INFO)
                sf_bool "$VERBOSE" && printf '%s\n' "$line" >&2
                ;;
            WARN | ERROR)
                printf '%s\n' "$line" >&2
                ;;
        esac
    fi

    return 0
}

log_debug() {
    if sf_bool "$DEBUG"; then
        log_line DEBUG "$@"
    fi
    return 0
}

log_info() {
    log_line INFO "$@"
    return 0
}

log_warn() {
    log_line WARN "$@"
    return 0
}

log_error() {
    log_line ERROR "$@"
    return 0
}
