#!/usr/bin/env bash
# Fixture-driven tests for the evidence-based analysis engine (lib/analysis.sh).
#
# Builds synthetic incident directories on disk (dstate logs, meta peaks, and a
# current.log window), runs analysis_generate, and asserts on the resulting
# analysis.txt. No root, no /proc, no live server needed, so it runs under Git
# Bash on the dev box and on Linux CI alike.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

# Source the libraries directly and wire the config globals by hand, so the test
# never touches /etc, /var/log, or config validation.
# shellcheck source=../lib/utils.sh
source "${ROOT_DIR}/lib/utils.sh"
# shellcheck source=../lib/incident.sh
source "${ROOT_DIR}/lib/incident.sh"
# shellcheck source=../lib/analysis.sh
source "${ROOT_DIR}/lib/analysis.sh"

WORK="$(mktemp -d 2>/dev/null || mktemp -d -t sf-analysis)"
trap 'rm -rf -- "$WORK"' EXIT

# These globals are read by the sourced analysis.sh / incident.sh functions, not
# directly here, so shellcheck cannot see the use.
# shellcheck disable=SC2034
{
    INCIDENT_DIR="${WORK}/incidents"
    CURRENT_LOG="${WORK}/current.log"
    LOAD_THRESHOLD=10
    DSTATE_THRESHOLD=5
}
mkdir -p "$INCIDENT_DIR"

FAILURES=0
pass() { printf '  ok   %s\n' "$1"; }
fail() {
    printf '  FAIL %s\n' "$1"
    FAILURES=$((FAILURES + 1))
}

assert_contains() {
    local file="$1" needle="$2" desc="$3"
    if grep -qF -- "$needle" "$file"; then pass "$desc"; else fail "$desc (missing: ${needle})"; fi
}
assert_not_contains() {
    local file="$1" needle="$2" desc="$3"
    if grep -qF -- "$needle" "$file"; then fail "$desc (unexpected: ${needle})"; else pass "$desc"; fi
}

# Appends a window of current.log samples for [start, start+3*step] with rising
# load / D-state / iowait and low CPU — the "high load, idle CPU" signature.
seed_window() {
    local start="$1"
    # ISO timestamps are cosmetic for the timeline; epoch drives the windowing.
    # A rising-load / rising-D-state / rising-iowait window with idle CPU.
    {
        printf 'timestamp=2001-09-09T01:46:40+0000 epoch=%s load1=3.0 cpu_busy_pct=8.0 iowait_pct=4.0 dstate_processes=1 apache_workers=6 threads_running=1 mem_available_mb=800\n' "$start"
        printf 'timestamp=2001-09-09T01:46:50+0000 epoch=%s load1=22.0 cpu_busy_pct=11.0 iowait_pct=24.0 dstate_processes=9 apache_workers=7 threads_running=1 mem_available_mb=780\n' "$((start + 30))"
        printf 'timestamp=2001-09-09T01:47:00+0000 epoch=%s load1=41.2 cpu_busy_pct=12.0 iowait_pct=27.0 dstate_processes=14 apache_workers=8 threads_running=2 mem_available_mb=770\n' "$((start + 60))"
        printf 'timestamp=2001-09-09T01:47:30+0000 epoch=%s load1=4.0 cpu_busy_pct=9.0 iowait_pct=5.0 dstate_processes=1 apache_workers=7 threads_running=1 mem_available_mb=790\n' "$((start + 90))"
    } >>"$CURRENT_LOG"
}

# Builds an incident dir. $1=id $2=start_epoch $3=with_kernel_evidence(0/1)
build_incident() {
    local id="$1" start="$2" with_evidence="$3"
    local dir="${INCIDENT_DIR}/${id}"
    mkdir -p "$dir"

    incident_meta_set "$dir" id "$id"
    incident_meta_set "$dir" started "iso-${id}"
    incident_meta_set "$dir" started_epoch "$start"
    incident_meta_set "$dir" ended_epoch "$((start + 120))"
    incident_meta_set "$dir" reason "dstate=14>5,load1=41.2>10"
    incident_meta_set "$dir" peak_load 41.2
    incident_meta_set "$dir" peak_dstate 14
    incident_meta_set "$dir" peak_iowait 27.0
    incident_meta_set "$dir" peak_psi_io_full 78.4
    incident_meta_set "$dir" peak_psi_cpu_some 5.1
    incident_meta_set "$dir" peak_psi_mem_full 0.0

    local log="${dir}/dstate-1.log"
    {
        printf 'Server Forensics D-state / Blocking Snapshot\n'
        printf '\n\n===== ps wchan (D-state only) =====\n'
        printf 'PID USER STAT WCHAN COMM ARGS\n'
        printf '12345 root D ext4_writepages rsync /usr/bin/rsync -a /home /backup\n'
        printf '12346 root D ext4_writepages rsync /usr/bin/rsync -a /home /backup\n'
        if [[ "$with_evidence" -eq 1 ]]; then
            printf '\n\n===== kernel stacks (D-state, capped 25) =====\n'
            printf -- '--- pid 12345 (rsync) ---\n'
            printf 'wchan: ext4_writepages\n'
            printf 'stack:\n'
            printf '[<0>] ext4_sync_file+0x1a/0x30\n'
            printf '[<0>] do_fsync+0x38/0x60\n'
        fi
        printf '\n\n===== PSI (pressure stall information) =====\n'
        printf -- '--- /proc/pressure/io ---\n'
        printf 'some avg10=80.10 avg60=40.00 avg300=10.00 total=123456\n'
        printf 'full avg10=78.40 avg60=38.00 avg300=9.00 total=100000\n'
        printf '\n\n===== maintenance/package processes (detected) =====\n'
        printf 'PID PPID USER STAT ETIMES COMM ARGS\n'
        printf '12345 1 root D 40 rsync /usr/bin/rsync -a /home /backup\n'
    } >"$log"

    printf '%s\n' "$dir"
}

printf 'test: full kernel evidence (wchan + stack + PSI)\n'
seed_window 1000000000
DIR_A="$(build_incident incident-A 1000000000 1)"
analysis_generate "$DIR_A" >/dev/null
A="${DIR_A}/analysis.txt"

assert_contains "$A" "Observed facts" "observed-facts section present"
assert_contains "$A" "Inference" "inference section present"
assert_contains "$A" "Evidence ledger" "evidence-ledger section present"
assert_contains "$A" "Confidence distribution" "confidence section present"
assert_contains "$A" "Proven:" "proven tier present"
assert_contains "$A" "Inferred:" "inferred tier present"
assert_contains "$A" "Unknown:" "unknown tier present"
assert_contains "$A" "Timeline:" "timeline section present"
assert_contains "$A" "Recurring patterns" "correlation section present"
assert_contains "$A" "Filesystem wait" "filesystem hypothesis listed"
assert_contains "$A" "ext4_writepages" "wchan surfaced as evidence"
assert_contains "$A" "PSI io full avg10 78.4" "PSI evidence surfaced"
assert_contains "$A" "Stall class was I/O" "PSI proves the I/O stall class"
assert_contains "$A" "load=41.2" "timeline reflects the peak-load sample"

# Leader must be Filesystem wait, high but never 100%.
leader_line="$(grep -m1 'LIKELY CAUSE:' "$A")"
if grep -q 'LIKELY CAUSE: Filesystem wait' "$A"; then pass "leader is Filesystem wait"; else fail "leader should be Filesystem wait (${leader_line})"; fi
assert_not_contains "$A" "100%" "confidence never reaches 100%"

printf 'test: no kernel evidence (wchan/stack/PSI absent) -> capped\n'
DIR_B="${INCIDENT_DIR}/incident-B"
mkdir -p "$DIR_B"
incident_meta_set "$DIR_B" id incident-B
incident_meta_set "$DIR_B" started iso-B
incident_meta_set "$DIR_B" started_epoch 1000001000
incident_meta_set "$DIR_B" ended_epoch 1000001120
incident_meta_set "$DIR_B" reason "load1=41.2>10"
incident_meta_set "$DIR_B" peak_load 41.2
incident_meta_set "$DIR_B" peak_dstate 14
incident_meta_set "$DIR_B" peak_iowait 27.0
incident_meta_set "$DIR_B" peak_psi_io_full 0
incident_meta_set "$DIR_B" peak_psi_cpu_some 0
incident_meta_set "$DIR_B" peak_psi_mem_full 0
seed_window 1000001000
analysis_generate "$DIR_B" >/dev/null
B="${DIR_B}/analysis.txt"

assert_contains "$B" "capped at 65%" "specific-cause confidence capped when kernel evidence missing"
assert_contains "$B" "kernel wait channel unavailable" "ledger flags missing wchan"
assert_contains "$B" "PSI pressure metrics unavailable" "ledger flags missing PSI"
assert_not_contains "$B" "100%" "confidence never reaches 100% (no-evidence case)"

# The .facts files should let correlation count both incidents.
if [[ -f "${DIR_A}/.facts" && -f "${DIR_B}/.facts" ]]; then pass ".facts written for correlation"; else fail ".facts not written"; fi
assert_contains "$B" "/2" "recurring patterns count across the two incidents"

if [[ "$FAILURES" -gt 0 ]]; then
    printf 'analysis tests FAILED: %s\n' "$FAILURES" >&2
    exit 1
fi
printf 'analysis tests passed.\n'
