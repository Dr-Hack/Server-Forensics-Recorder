#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=../lib/utils.sh
source "${ROOT_DIR}/lib/utils.sh"
load_config
# shellcheck source=../lib/logging.sh
source "${ROOT_DIR}/lib/logging.sh"
# shellcheck source=../lib/plugins.sh
source "${ROOT_DIR}/lib/plugins.sh"
# shellcheck source=../lib/metrics.sh
source "${ROOT_DIR}/lib/metrics.sh"

main() {
    log_init
    local line
    line="$(collect_metrics_line)"

    if [[ "${1:-}" == "--print" ]]; then
        printf '%s\n' "$line"
        return 0
    fi

    printf '%s\n' "$line" >>"$CURRENT_LOG"
    log_debug "collected lightweight metrics"
}

main "$@"
