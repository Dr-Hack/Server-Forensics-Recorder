#!/usr/bin/env bash
# Fixture-driven tests for per-process I/O attribution (lib/ioforensics.sh).
#
# The ranking is the part that must be right: it decides which process gets
# named as the one consuming I/O. It parses pidstat output whose column layout
# differs across sysstat versions, so the fixtures below deliberately cover both
# the modern layout (with iodelay) and an older one (without), plus the case
# where the kernel reports no per-process I/O at all.
#
# No root, no /proc, no sysstat needed — these run on the dev box and in CI.
#
# The PANIC_IO_* knobs below are read by the sourced ioforensics functions rather
# than referenced in this file, which shellcheck cannot see.
# shellcheck disable=SC2034
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

# shellcheck source=../lib/utils.sh
source "${ROOT_DIR}/lib/utils.sh"
# shellcheck source=../lib/incident.sh
source "${ROOT_DIR}/lib/incident.sh"
# shellcheck source=../lib/ioforensics.sh
source "${ROOT_DIR}/lib/ioforensics.sh"

WORK="$(mktemp -d 2>/dev/null || mktemp -d -t sf-io)"
trap 'rm -rf -- "$WORK"' EXIT

PANIC_IO_OFFENDER_PCT=5
PANIC_IO_MIN_OFFENDERS=3
PANIC_IO_MAX_OFFENDERS=10
PANIC_IO_TABLE_ROWS=20

FAILURES=0
pass() { printf '  ok   %s\n' "$1"; }
fail() {
    printf '  FAIL %s\n' "$1"
    FAILURES=$((FAILURES + 1))
}

assert_eq() {
    local got="$1" want="$2" desc="$3"
    if [[ "$got" == "$want" ]]; then pass "$desc"; else fail "$desc (got '${got}', want '${want}')"; fi
}
assert_contains() {
    local haystack="$1" needle="$2" desc="$3"
    if [[ "$haystack" == *"$needle"* ]]; then pass "$desc"; else fail "$desc (missing: ${needle})"; fi
}

# --- fixtures ----------------------------------------------------------------

# Modern sysstat: "# Time UID PID kB_rd/s kB_wr/s kB_ccwr/s iodelay Command".
# rsync is the heavy writer, mariadbd a distant second, sshd is noise.
write_modern_pidstat() {
    cat >"$1" <<'EOF'
Linux 5.14.0-427.el9.x86_64 (server1)   07/23/2026      _x86_64_        (4 CPU)

# Time        UID       PID   kB_rd/s   kB_wr/s kB_ccwr/s iodelay  Command
 1784773100     0      4821      0.00  18000.00      0.00     412  rsync
 1784773100    27      1190    240.00    120.00      0.00      31  mariadbd
 1784773100     0       902      0.00      4.00      0.00       0  sshd
 1784773101     0      4821    500.00  22000.00      0.00     455  rsync
 1784773101    27      1190    260.00    140.00      0.00      35  mariadbd
 1784773101     0       902      0.00      2.00      0.00       0  sshd
EOF
}

# Older sysstat: no iodelay column, and kB_ccwr/s in a different position.
write_legacy_pidstat() {
    cat >"$1" <<'EOF'
Linux 3.10.0-1160.el7.x86_64 (legacy)   07/23/2026      _x86_64_        (2 CPU)

# Time        UID       PID   kB_rd/s   kB_wr/s kB_ccwr/s  Command
 1784773100     0      7777   9000.00    100.00      0.00  clamscan
 1784773100     0       902      1.00      1.00      0.00  sshd
EOF
}

# Kernel with no per-process I/O accounting: header present, all rates zero.
write_empty_pidstat() {
    cat >"$1" <<'EOF'
Linux 5.14.0-427.el9.x86_64 (server1)   07/23/2026      _x86_64_        (4 CPU)

# Time        UID       PID   kB_rd/s   kB_wr/s kB_ccwr/s iodelay  Command
 1784773100     0       902      0.00      0.00      0.00       0  sshd
EOF
}

# sysstat builds that attach the comment marker to the first column ("#Time"
# rather than "# Time"). Splitting the raw header makes this form disagree with
# the data rows by one field, which resolves PID to the UID column and yields an
# empty table with no error at all. Regression fixture for that failure.
write_attached_hash_pidstat() {
    cat >"$1" <<'EOF'
Linux 5.14.0-427.el9.x86_64 (server1)   07/23/2026      _x86_64_        (4 CPU)

#Time        UID       PID   kB_rd/s   kB_wr/s kB_ccwr/s iodelay  Command
 1784773100     0      4821      0.00  18000.00      0.00     412  rsync
 1784773100    27      1190    240.00    120.00      0.00      31  mariadbd
EOF
}

# --- ranking -----------------------------------------------------------------

printf 'io ranking (modern sysstat layout)\n'
write_modern_pidstat "${WORK}/modern.txt"
io_rank_offenders "${WORK}/modern.txt" >"${WORK}/modern.tsv"

top_line="$(head -n 1 "${WORK}/modern.tsv")"
IFS=$'\t' read -r r_pid r_comm r_rd r_wr r_tot r_del r_n _ <<<"$top_line"

assert_eq "$r_pid" "4821" "heaviest writer ranks first by pid"
assert_eq "$r_comm" "rsync" "heaviest writer is identified by command"
assert_eq "$r_rd" "250.00" "read rate averaged across samples"
assert_eq "$r_wr" "20000.00" "write rate averaged across samples"
assert_eq "$r_tot" "20250.00" "total is read+write"
assert_eq "$r_del" "455" "iodelay keeps the maximum, not the last"
assert_eq "$r_n" "2" "sample count is tracked"

second="$(sed -n '2p' "${WORK}/modern.tsv" | cut -f2)"
assert_eq "$second" "mariadbd" "second-heaviest ranks second"
third="$(sed -n '3p' "${WORK}/modern.tsv" | cut -f2)"
assert_eq "$third" "sshd" "idle process ranks last"

# rsync moved 20250 of 20250+380+3 kB/s, so it must dominate the share.
dominant="$(awk -F'\t' 'NR==1 { print ($8 > 90) ? "yes" : "no" }' "${WORK}/modern.tsv")"
assert_eq "$dominant" "yes" "percentage share reflects actual bytes moved"

printf 'io ranking (legacy sysstat, no iodelay column)\n'
write_legacy_pidstat "${WORK}/legacy.txt"
io_rank_offenders "${WORK}/legacy.txt" >"${WORK}/legacy.tsv"
legacy_top="$(head -n 1 "${WORK}/legacy.tsv")"
IFS=$'\t' read -r l_pid l_comm l_rd _ l_tot _ _ _ <<<"$legacy_top"
assert_eq "$l_pid" "7777" "legacy layout resolves PID column"
assert_eq "$l_comm" "clamscan" "legacy layout resolves Command column"
assert_eq "$l_rd" "9000.00" "legacy layout resolves kB_rd/s despite missing iodelay"
assert_eq "$l_tot" "9100.00" "legacy layout totals correctly"

printf 'io ranking (attached-hash header, "#Time")\n'
write_attached_hash_pidstat "${WORK}/attached.txt"
io_rank_offenders "${WORK}/attached.txt" >"${WORK}/attached.tsv"
attached_rows="$(wc -l <"${WORK}/attached.tsv" | tr -d '[:space:]')"
assert_eq "$attached_rows" "2" "attached-hash header does not silently yield an empty table"
IFS=$'\t' read -r a_pid a_comm _ a_wr a_tot _ _ _ <<<"$(head -n 1 "${WORK}/attached.tsv")"
assert_eq "$a_pid" "4821" "attached-hash header resolves the PID column, not UID"
assert_eq "$a_comm" "rsync" "attached-hash header resolves the Command column"
assert_eq "$a_wr" "18000.00" "attached-hash header resolves kB_wr/s"
assert_eq "$a_tot" "18000.00" "attached-hash header totals correctly"

# --- offender selection ------------------------------------------------------

printf 'offender selection\n'
mapfile -t picked < <(io_select_offenders "${WORK}/modern.tsv")
assert_eq "${#picked[@]}" "3" "min-offenders floor keeps the top three"
assert_eq "${picked[0]}" "4821" "top offender selected first"

# With the floor removed, only processes above the 5% threshold survive: rsync
# alone is >5% of total observed I/O here.
PANIC_IO_MIN_OFFENDERS=0
mapfile -t strict < <(io_select_offenders "${WORK}/modern.tsv")
assert_eq "${#strict[@]}" "1" "threshold alone selects only the real offender"
assert_eq "${strict[0]}" "4821" "threshold selects rsync"
PANIC_IO_MIN_OFFENDERS=3

# A cap below the floor must still be honoured, so a storm cannot fan out.
PANIC_IO_MAX_OFFENDERS=2
mapfile -t capped < <(io_select_offenders "${WORK}/modern.tsv")
assert_eq "${#capped[@]}" "2" "max-offenders cap bounds the detail work"
PANIC_IO_MAX_OFFENDERS=10

# Zero-I/O processes are never worth a detail block even inside the floor.
write_empty_pidstat "${WORK}/empty.txt"
io_rank_offenders "${WORK}/empty.txt" >"${WORK}/empty.tsv"
mapfile -t none_picked < <(io_select_offenders "${WORK}/empty.tsv")
assert_eq "${#none_picked[@]}" "0" "no offenders selected when nothing moved bytes"

# --- rendering ---------------------------------------------------------------

printf 'table rendering\n'
table="$(io_render_table "${WORK}/modern.tsv")"
assert_contains "$table" "rsync" "table names the offending process"
assert_contains "$table" "TOTAL_KBs" "table has a total throughput column"
assert_contains "$table" "IODELAY" "table exposes block-I/O delay"

: >"${WORK}/none.tsv"
empty_table="$(io_render_table "${WORK}/none.tsv")"
assert_contains "$empty_table" "No per-process I/O recorded" "empty table explains itself"
assert_contains "$empty_table" "sysstat" "empty table points at the likely cause"

# The CLI renders from a pipe, never a scratch file, so a non-root caller
# inspecting an incident cannot fail on a write it should never have attempted.
stream_table="$(printf '%s\n' "$(cat "${WORK}/modern.tsv")" | io_render_stream)"
assert_contains "$stream_table" "rsync" "stream rendering names the offending process"
assert_contains "$stream_table" "PCT_IO" "stream rendering emits the header once"
stream_header_count="$(printf '%s\n' "$stream_table" | grep -c 'PCT_IO')"
assert_eq "$stream_header_count" "1" "stream rendering does not repeat the header"

# --- concurrency ------------------------------------------------------------

printf 'sampler concurrency\n'
# A bare `wait` reaps every background job in the shell, including ones the
# capture did not start, which would block the capture for as long as they run.
# io_wait_jobs must wait only on its own samplers.
sleep 6 &
UNRELATED=$!
SF_IO_JOBS=()
PANIC_IO_MAX_LINES=100
io_run_bg "${WORK}/bg1.txt" 5 true
io_run_bg "${WORK}/bg2.txt" 5 true
started="$SECONDS"
io_wait_jobs
elapsed=$((SECONDS - started))
if [[ "$elapsed" -lt 3 ]]; then
    pass "io_wait_jobs ignores unrelated background jobs (${elapsed}s)"
else
    fail "io_wait_jobs blocked on an unrelated job (${elapsed}s)"
fi
assert_eq "${#SF_IO_JOBS[@]}" "0" "job list is cleared after waiting"
kill "$UNRELATED" 2>/dev/null || true
wait "$UNRELATED" 2>/dev/null || true

io_run_bg "${WORK}/missing.txt" 5 sf-definitely-not-a-real-command
assert_contains "$(cat "${WORK}/missing.txt")" "command not found" "missing sampler is reported, not fatal"

# --- incident peaks and aggregation ------------------------------------------

printf 'incident peaks and cross-snapshot aggregation\n'
DIR="${WORK}/incident-20260723-071746"
mkdir -p "$DIR"
incident_meta_set "$DIR" peak_io_kbs 0

cp "${WORK}/modern.tsv" "${DIR}/offenders-1.tsv"
io_update_peaks "$DIR" "${DIR}/offenders-1.tsv"
assert_eq "$(incident_meta_get "$DIR" peak_io_pid none)" "4821" "peak io pid recorded"
assert_eq "$(incident_meta_get "$DIR" peak_io_comm none)" "rsync" "peak io comm recorded"

# A later, quieter snapshot must not lower the recorded peak.
cp "${WORK}/legacy.tsv" "${DIR}/offenders-2.tsv"
io_update_peaks "$DIR" "${DIR}/offenders-2.tsv"
assert_eq "$(incident_meta_get "$DIR" peak_io_comm none)" "rsync" "a quieter snapshot does not lower the peak"

agg="$(io_aggregate_offenders "$DIR")"
agg_top="$(printf '%s\n' "$agg" | head -n 1 | cut -f2)"
assert_eq "$agg_top" "rsync" "aggregate ranks the incident-wide worst offender first"
assert_contains "$agg" "clamscan" "aggregate retains processes from other snapshots"

if [[ "$FAILURES" -gt 0 ]]; then
    printf 'ioforensics tests: %s failure(s)\n' "$FAILURES" >&2
    exit 1
fi
printf 'ioforensics tests: all passed\n'
