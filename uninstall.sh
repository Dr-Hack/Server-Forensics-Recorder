#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/server-forensics}"
CONFIG_DIR="${CONFIG_DIR:-/etc/server-forensics}"
LOG_DIR="${LOG_DIR:-/var/log/server-forensics}"
BIN_DIR="${BIN_DIR:-/usr/local/sbin}"
DELETE_LOGS=0
INSTALL_MARKER=".server-forensics-install"
CONFIG_MARKER=".server-forensics-config"
LOG_MARKER=".server-forensics-logs"

usage() {
    printf 'Usage: %s [--delete-logs]\n' "$0"
}

parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --delete-logs)
                DELETE_LOGS=1
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                usage >&2
                exit 2
                ;;
        esac
        shift
    done
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        printf 'uninstall.sh must be run as root.\n' >&2
        exit 1
    fi
}

stop_systemd() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now server-forensics.timer >/dev/null 2>&1 || true
        systemctl stop server-forensics.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/server-forensics.service /etc/systemd/system/server-forensics.timer
        systemctl daemon-reload
    fi
}

canonical_path() {
    if command -v realpath >/dev/null 2>&1; then
        realpath -m -- "$1"
    elif command -v readlink >/dev/null 2>&1; then
        readlink -f -- "$1"
    else
        printf 'realpath or readlink is required for safe uninstall.\n' >&2
        exit 1
    fi
}

refuse_unsafe_path() {
    local path="$1"
    local resolved
    resolved="$(canonical_path "$path")"

    case "$resolved" in
        "" | "/" | "/bin" | "/boot" | "/dev" | "/etc" | "/home" | "/lib" | "/lib64" | "/opt" | "/proc" | "/root" | "/run" | "/sbin" | "/sys" | "/tmp" | "/usr" | "/var" | "/var/log")
            printf 'Refusing unsafe uninstall path: %s\n' "$resolved" >&2
            exit 1
            ;;
    esac

    printf '%s\n' "$resolved"
}

remove_marked_tree() {
    local path="$1"
    local marker="$2"
    local resolved
    resolved="$(refuse_unsafe_path "$path")"

    if [[ ! -e "$resolved" ]]; then
        return 0
    fi

    if [[ ! -f "$resolved/$marker" ]]; then
        printf 'Refusing to remove unmarked directory: %s\n' "$resolved" >&2
        printf 'Expected marker: %s\n' "$resolved/$marker" >&2
        exit 1
    fi

    rm -rf -- "$resolved"
}

remove_files() {
    rm -f -- "$BIN_DIR/server-forensics"
    remove_marked_tree "$INSTALL_DIR" "$INSTALL_MARKER"
    remove_marked_tree "$CONFIG_DIR" "$CONFIG_MARKER"

    if [[ "$DELETE_LOGS" -eq 1 ]]; then
        remove_marked_tree "$LOG_DIR" "$LOG_MARKER"
    fi
}

main() {
    parse_args "$@"
    require_root
    stop_systemd
    remove_files
    printf 'server-forensics uninstalled.\n'
    if [[ "$DELETE_LOGS" -ne 1 ]]; then
        printf 'Logs preserved at: %s\n' "$LOG_DIR"
    fi
}

main "$@"
