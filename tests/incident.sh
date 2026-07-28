#!/usr/bin/env bash
# Incident lifecycle regression tests.
#
# Both behaviours here were proven broken in production on 2026-07-28, and both
# were invisible: the recorder produced a complete-looking report every time.
#
#   incident-20260728-183224  panic.sh died 13s into its first capture. Nothing
#                             closes an incident except the panic loop, so the
#                             incident stayed open 3h27m and was finally closed
#                             against an unrelated nightly dnf run. Its retry
#                             reused snapshot index 1 and overwrote the partial
#                             output that would have explained the crash.
#   incident-20260728-143917  the same orphaning, twice in one day (3h13m).
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

FAILURES=0
pass() { printf '  ok   %s\n' "$1"; }
fail() {
    printf '  FAIL %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}
assert_eq() {
    if [[ "$1" == "$2" ]]; then pass "$3"; else fail "$3 (got '$1', want '$2')"; fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export SF_CONFIG=/dev/null
# shellcheck source=../lib/utils.sh
source "${ROOT_DIR}/lib/utils.sh"
load_config
LOG_DIR="$WORK"
STATE_DIR="${WORK}/state"
INCIDENT_DIR="${WORK}/incidents"
CURRENT_LOG="${WORK}/current.log"
mkdir -p "$STATE_DIR" "$INCIDENT_DIR"
: >"$CURRENT_LOG"
# shellcheck source=../lib/incident.sh
source "${ROOT_DIR}/lib/incident.sh"

METRIC='timestamp=2026-07-28T18:32:24+0500 epoch=1785245544 load1=10.20 cpu_busy_pct=13.3 iowait_pct=81.8 dstate_processes=6 apache_workers=7 threads_running=1 mem_available_mb=2765'

# --- snapshot index reservation -----------------------------------------------
printf 'snapshot index reservation\n'

DIR="$(incident_start "load1=10.20>10" "$METRIC")"
assert_eq "$(incident_meta_get "$DIR" snapshots 0)" "0" "a new incident has no completed snapshots"

i1="$(incident_reserve_snapshot_index "$DIR")"
assert_eq "$i1" "1" "the first capture reserves index 1"

# Simulate a capture that dies part-way: the index was reserved, but the
# completion counter was never incremented.
printf 'partial\n' >"${DIR}/snapshot-${i1}.log"

i2="$(incident_reserve_snapshot_index "$DIR")"
assert_eq "$i2" "2" "a failed capture does not hand its index back"
assert_eq "$(incident_meta_get "$DIR" snapshots 0)" "0" "a failed capture is not counted as taken"
assert_eq "$(cat "${DIR}/snapshot-1.log")" "partial" "the failed capture's output is not overwritten"

incident_increment_snapshots "$DIR" >/dev/null
assert_eq "$(incident_meta_get "$DIR" snapshots 0)" "1" "a completed capture is counted"
i3="$(incident_reserve_snapshot_index "$DIR")"
assert_eq "$i3" "3" "indices stay monotonic across mixed success and failure"

# --- orphan detection ---------------------------------------------------------
printf 'orphan detection\n'

if incident_active_dir >/dev/null; then
    pass "an incident left open is reported as active"
else
    fail "an incident left open should be reported as active"
fi

incident_close "$DIR" "$METRIC"
if incident_active_dir >/dev/null 2>&1; then
    fail "closing an incident must clear the active marker"
else
    pass "closing an incident clears the active marker"
fi
assert_eq "$(incident_meta_get "$DIR" snapshots 0)" "1" "the closed summary reports completed captures only"

# The marker file is the only thing standing between a dead panic process and a
# 3.5-hour orphan, so a stale pointer to a deleted directory must not read as
# an active incident.
printf '%s\n' "${INCIDENT_DIR}/incident-does-not-exist" >"$(active_incident_file)"
if incident_active_dir >/dev/null 2>&1; then
    fail "a marker pointing at a missing directory must not read as active"
else
    pass "a marker pointing at a missing directory does not read as active"
fi
rm -f -- "$(active_incident_file)"

# --- close is idempotent ------------------------------------------------------
# The watcher's orphan sweep and the panic loop can race on a slow box; a second
# close must not error or resurrect the marker.
printf 'close idempotency\n'
DIR2="$(incident_start "dstate=8>5" "$METRIC")"
incident_close "$DIR2" "$METRIC"
if incident_close "$DIR2" "$METRIC" 2>/dev/null; then
    pass "closing an already-closed incident is not an error"
else
    fail "closing an already-closed incident must not error"
fi
if incident_active_dir >/dev/null 2>&1; then
    fail "a second close must not resurrect the active marker"
else
    pass "a second close leaves no active marker"
fi

if [[ "$FAILURES" -gt 0 ]]; then
    printf 'incident tests FAILED: %s\n' "$FAILURES" >&2
    exit 1
fi
printf 'incident tests passed.\n'
