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
# The analysis engine reads the measured offender tables through these helpers,
# so the real implementations are sourced rather than stubbed.
# shellcheck source=../lib/ioforensics.sh
source "${ROOT_DIR}/lib/ioforensics.sh"

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

# --- CPU-bound incident ------------------------------------------------------
# Reproduces production incident-20260723-192658: high load, high CPU, no I/O
# wait, no D-state, and resident Imunify daemons in the process table. The old
# engine had no CPU hypothesis, so the only thing that scored was daemon
# presence and it reported "Maintenance interaction". See docs/decisions.md.
printf 'test: CPU-bound incident (high CPU, no I/O wait, no D-state)\n'

# A window with high CPU beside high load — the compute-bound signature.
seed_cpu_window() {
    local start="$1"
    {
        printf 'timestamp=2001-09-09T01:46:40+0000 epoch=%s load1=3.33 cpu_busy_pct=62.2 iowait_pct=0.1 dstate_processes=0 apache_workers=7 threads_running=1 mem_available_mb=3500\n' "$start"
        printf 'timestamp=2001-09-09T01:46:50+0000 epoch=%s load1=12.46 cpu_busy_pct=80.6 iowait_pct=0.6 dstate_processes=0 apache_workers=7 threads_running=1 mem_available_mb=3457\n' "$((start + 60))"
        printf 'timestamp=2001-09-09T01:47:00+0000 epoch=%s load1=8.75 cpu_busy_pct=60.3 iowait_pct=0.3 dstate_processes=0 apache_workers=7 threads_running=1 mem_available_mb=3457\n' "$((start + 90))"
    } >>"$CURRENT_LOG"
}

DIR_C="${INCIDENT_DIR}/incident-C"
mkdir -p "$DIR_C"
incident_meta_set "$DIR_C" id incident-C
incident_meta_set "$DIR_C" started iso-C
incident_meta_set "$DIR_C" started_epoch 1000002000
incident_meta_set "$DIR_C" ended_epoch 1000002120
incident_meta_set "$DIR_C" reason "load1=12.46>10"
incident_meta_set "$DIR_C" peak_load 12.46
incident_meta_set "$DIR_C" peak_dstate 0
incident_meta_set "$DIR_C" peak_iowait 0.6
incident_meta_set "$DIR_C" peak_psi_io_full 0
incident_meta_set "$DIR_C" peak_psi_cpu_some 0
incident_meta_set "$DIR_C" peak_psi_mem_full 0

# Resident maintenance daemons, exactly as production reports them.
cat >"${DIR_C}/dstate-1.log" <<'EOF'
===== maintenance/package processes (detected) =====
  PID  PPID USER     STAT  ELAPSED COMMAND         ARGS
 1215     1 root     S      600000 imunify-residen /usr/sbin/imunify-resident
 1216     1 root     S      600000 imunify-agent-p /usr/sbin/imunify-agent
EOF

# The measured CPU ranking: `claude` is the actual consumer, and it is NOT one
# of the maintenance daemons.
printf '3323246\tclaude\t99.50\t0.00\t99.50\t1\t2\t71.0\n' >"${DIR_C}/cpuoffenders-1.tsv"
printf '873022\tnetdata\t2.00\t1.00\t3.00\t0\t2\t2.1\n' >>"${DIR_C}/cpuoffenders-1.tsv"
: >"${DIR_C}/offenders-1.tsv"

seed_cpu_window 1000002000
analysis_generate "$DIR_C" >/dev/null
C="${DIR_C}/analysis.txt"

if grep -q 'LIKELY CAUSE: CPU saturation' "$C"; then
    pass "CPU-bound incident is named CPU saturation"
else
    fail "CPU-bound incident misclassified: $(grep -m1 'LIKELY CAUSE:' "$C")"
fi
assert_not_contains "$C" "LIKELY CAUSE: Maintenance interaction" "resident daemons no longer win by default"
assert_contains "$C" "claude" "the measured CPU culprit is named"
assert_contains "$C" "compute-bound" "compute-bound evidence is stated"
assert_contains "$C" "presence is not evidence" "uncorroborated daemon presence is labelled as such"
assert_contains "$C" "Alternatives ruled out" "ledger separates exclusions from support"

# Exclusionary findings must not appear as support for the leader.
support_block="$(sed -n '/Supported by:/,/Alternatives ruled out/p' "$C")"
if printf '%s' "$support_block" | grep -q 'Apache'; then
    fail "Apache exclusion still listed as support for the leader"
else
    pass "Apache exclusion is not listed as support"
fi

# Uncorroborated presence must never clear the floor.
maint_pct="$(grep -oE 'Maintenance interaction \.+ +[0-9]+%' "$C" | grep -oE '[0-9]+%' | tr -d '%')"
if [[ -n "$maint_pct" && "$maint_pct" -le 15 ]]; then
    pass "uncorroborated maintenance capped at the inconclusive floor (${maint_pct}%)"
else
    fail "uncorroborated maintenance not capped (got '${maint_pct}')"
fi

# --- corroborated maintenance ------------------------------------------------
# The mirror of the case above: gating presence behind measurement must not make
# maintenance unnameable. When the maintenance process IS the measured top
# consumer, the cap lifts and it can lead.
printf 'test: maintenance corroborated by measurement\n'

DIR_D="${INCIDENT_DIR}/incident-D"
mkdir -p "$DIR_D"
incident_meta_set "$DIR_D" id incident-D
incident_meta_set "$DIR_D" started iso-D
incident_meta_set "$DIR_D" started_epoch 1000003000
incident_meta_set "$DIR_D" ended_epoch 1000003120
incident_meta_set "$DIR_D" reason "load1=41.2>10"
incident_meta_set "$DIR_D" peak_load 41.2
incident_meta_set "$DIR_D" peak_dstate 14
incident_meta_set "$DIR_D" peak_iowait 27.0
incident_meta_set "$DIR_D" peak_psi_io_full 0
incident_meta_set "$DIR_D" peak_psi_cpu_some 0
incident_meta_set "$DIR_D" peak_psi_mem_full 0

cat >"${DIR_D}/dstate-1.log" <<'EOF'
===== maintenance/package processes (detected) =====
  PID  PPID USER     STAT  ELAPSED COMMAND         ARGS
 4821     1 root     D         900 rsync           /usr/bin/rsync -a /home /backup
EOF

# rsync is both present AND the measured top disk consumer.
printf '4821\trsync\t250.00\t20000.00\t20250.00\t455\t2\t98.0\n' >"${DIR_D}/offenders-1.tsv"
: >"${DIR_D}/cpuoffenders-1.tsv"

seed_window 1000003000
analysis_generate "$DIR_D" >/dev/null
D="${DIR_D}/analysis.txt"

assert_contains "$D" "corroborated" "corroboration is stated explicitly"
assert_contains "$D" "rsync" "the corroborating process is named"
maint_pct_d="$(grep -oE 'Maintenance interaction \.+ +[0-9]+%' "$D" | grep -oE '[0-9]+%' | tr -d '%')"
if [[ -n "$maint_pct_d" && "$maint_pct_d" -gt 15 ]]; then
    pass "corroborated maintenance clears the floor (${maint_pct_d}%)"
else
    fail "corroborated maintenance still capped (got '${maint_pct_d}')"
fi

if [[ "$FAILURES" -gt 0 ]]; then
    printf 'analysis tests FAILED: %s\n' "$FAILURES" >&2
    exit 1
fi
printf 'analysis tests passed.\n'
