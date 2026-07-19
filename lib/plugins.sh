#!/usr/bin/env bash
# Lightweight metric plugin loader.
# shellcheck disable=SC2154

plugin_metric_files() {
    local dirs="${PLUGIN_DIRS:-}"
    local dir file

    [[ -n "$dirs" ]] || return 0

    while IFS= read -r dir; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r file; do
            [[ -r "$file" ]] || continue
            printf '%s\n' "$file"
        done < <(find "$dir" -maxdepth 1 -type f -name '*.sh' | sort)
    done < <(printf '%s\n' "$dirs" | tr ':' '\n')
}

collect_plugin_metrics() {
    sf_bool "$ENABLE_PLUGINS" || return 0

    local file output rc
    while IFS= read -r file; do
        output=""
        rc=0

        set +e
        if command_exists timeout; then
            output="$(PLUGIN_FILE="$file" timeout "$PLUGIN_TIMEOUT" bash "$file" 2>/dev/null)"
        else
            output="$(PLUGIN_FILE="$file" bash "$file" 2>/dev/null)"
        fi
        rc=$?
        set -e

        if [[ "$rc" -eq 0 && -n "$output" ]]; then
            printf ' %s' "$output"
        fi
    done < <(plugin_metric_files)
}
