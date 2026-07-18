#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_DIR="${INSTALL_DIR:-/opt/server-forensics}"
CONFIG_DIR="${CONFIG_DIR:-/etc/server-forensics}"
CONFIG_FILE="${CONFIG_FILE:-${CONFIG_DIR}/config.conf}"
LOG_DIR_DEFAULT="/var/log/server-forensics"
INSTALLED_LOG_DIR="$LOG_DIR_DEFAULT"

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        printf 'install.sh must be run as root.\n' >&2
        exit 1
    fi
}

copy_project() {
    mkdir -p "$INSTALL_DIR"
    cp -R "$PROJECT_DIR"/lib "$INSTALL_DIR"/
    cp -R "$PROJECT_DIR"/scripts "$INSTALL_DIR"/
    cp -R "$PROJECT_DIR"/docs "$INSTALL_DIR"/
    cp "$PROJECT_DIR"/config.conf "$INSTALL_DIR"/
    cp "$PROJECT_DIR"/README.md "$INSTALL_DIR"/
    cp "$PROJECT_DIR"/DESIGN.md "$INSTALL_DIR"/
    cp "$PROJECT_DIR"/CHANGELOG.md "$INSTALL_DIR"/
    cp "$PROJECT_DIR"/LICENSE "$INSTALL_DIR"/
    chmod 0755 "$INSTALL_DIR"/scripts/collector.sh "$INSTALL_DIR"/scripts/watcher.sh "$INSTALL_DIR"/scripts/panic.sh "$INSTALL_DIR"/scripts/rotate.sh
    chmod 0644 "$INSTALL_DIR"/config.conf "$INSTALL_DIR"/lib/*.sh
}

install_config() {
    mkdir -p "$CONFIG_DIR"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cp "$PROJECT_DIR/config.conf" "$CONFIG_FILE"
        chmod 0644 "$CONFIG_FILE"
    fi
}

install_logs() {
    local configured_log_dir="$LOG_DIR_DEFAULT"

    configured_log_dir="$(
        LOG_DIR="$LOG_DIR_DEFAULT"
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        printf '%s\n' "$LOG_DIR"
    )"
    INSTALLED_LOG_DIR="$configured_log_dir"

    mkdir -p "$configured_log_dir/incidents" "$configured_log_dir/archive" "$configured_log_dir/.state"
    touch "$configured_log_dir/current.log" "$configured_log_dir/server-forensics.log"
}

install_systemd() {
    if ! command -v systemctl >/dev/null 2>&1; then
        printf 'systemctl not found; files installed but timer was not enabled.\n' >&2
        return 0
    fi

    cp "$PROJECT_DIR/systemd/service" /etc/systemd/system/server-forensics.service
    cp "$PROJECT_DIR/systemd/timer" /etc/systemd/system/server-forensics.timer

    if [[ "$INSTALL_DIR" != "/opt/server-forensics" || "$CONFIG_FILE" != "/etc/server-forensics/config.conf" ]]; then
        sed -i \
            -e "s|/opt/server-forensics|${INSTALL_DIR}|g" \
            -e "s|/etc/server-forensics/config.conf|${CONFIG_FILE}|g" \
            /etc/systemd/system/server-forensics.service
    fi

    systemctl daemon-reload
    systemctl enable --now server-forensics.timer
}

verify_installation() {
    test -x "$INSTALL_DIR/scripts/watcher.sh"
    test -x "$INSTALL_DIR/scripts/collector.sh"
    test -f "$CONFIG_FILE"

    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-timers --all server-forensics.timer >/dev/null
    fi
}

main() {
    require_root
    copy_project
    install_config
    install_logs
    install_systemd
    verify_installation
    printf 'server-forensics installed successfully.\n'
    printf 'Configuration: %s\n' "$CONFIG_FILE"
    printf 'Logs: %s\n' "$INSTALLED_LOG_DIR"
}

main "$@"
