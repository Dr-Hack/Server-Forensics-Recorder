#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/server-forensics}"
CONFIG_DIR="${CONFIG_DIR:-/etc/server-forensics}"
LOG_DIR="${LOG_DIR:-/var/log/server-forensics}"
DELETE_LOGS=0

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

remove_files() {
    rm -rf -- "$INSTALL_DIR"
    rm -rf -- "$CONFIG_DIR"

    if [[ "$DELETE_LOGS" -eq 1 ]]; then
        rm -rf -- "$LOG_DIR"
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
