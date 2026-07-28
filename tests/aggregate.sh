#!/usr/bin/env bash
# Tests for executable/subsystem aggregation and the process ring buffer.
#
# The driving case is production incident-20260724-193525: the box hit 93.4% CPU
# while the largest single process read 9%, because fourteen short-lived `lsphp`
# workers carried the load. A PID-ranked table cannot express that; these tests
# assert the aggregated view can.
#
# No root, no /proc, no sysstat needed.
#
# The RINGBUFFER_* and AGG_* knobs are read by the sourced functions rather than
# referenced here, which shellcheck cannot see.
# shellcheck disable=SC2034
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

# shellcheck source=../lib/utils.sh
source "${ROOT_DIR}/lib/utils.sh"
# shellcheck source=../lib/aggregate.sh
source "${ROOT_DIR}/lib/aggregate.sh"
# shellcheck source=../lib/procring.sh
source "${ROOT_DIR}/lib/procring.sh"

WORK="$(mktemp -d 2>/dev/null || mktemp -d -t sf-agg)"
trap 'rm -rf -- "$WORK"' EXIT

LOG_DIR="$WORK"
PANIC_IO_TABLE_ROWS=20
AGG_DISTRIBUTED_CPU_PCT=90
AGG_DISTRIBUTED_TOP_PCT=15
RINGBUFFER_RETAIN_SECONDS=900
RINGBUFFER_LOOKBACK_SECONDS=300
RINGBUFFER_TOP_PHP=10

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
    local hay="$1" needle="$2" desc="$3"
    if [[ "$hay" == *"$needle"* ]]; then pass "$desc"; else fail "$desc (missing: ${needle})"; fi
}

# --- executable key normalisation --------------------------------------------

printf 'executable key normalisation\n'
assert_eq "$(sf_exec_key 'lsphp')" "lsphp" "plain comm passes through"
assert_eq "$(sf_exec_key 'lfd - sleeping')" "lfd" "pidstat state text is stripped"
assert_eq "$(sf_exec_key 'lfd - (child) c')" "lfd" "child state text is stripped"
assert_eq "$(sf_exec_key '')" "?" "empty name is marked unknown"

printf 'subsystem classification\n'
assert_eq "$(sf_subsystem_of lsphp)" "PHP" "lsphp maps to PHP"
assert_eq "$(sf_subsystem_of httpd)" "Apache" "httpd maps to Apache"
assert_eq "$(sf_subsystem_of mariadbd)" "MariaDB" "mariadbd maps to MariaDB"
assert_eq "$(sf_subsystem_of imunify-residen)" "Maintenance" "truncated imunify name maps to Maintenance"
assert_eq "$(sf_subsystem_of wafd_imunify_da)" "Maintenance" "differently-named imunify daemon maps to Maintenance"
assert_eq "$(sf_subsystem_of systemd)" "Init" "systemd maps to Init, not a workload"
assert_eq "$(sf_subsystem_or_other 'some-unknown-bin')" "Other" "unknown executables are still attributed"

# --- combined aggregation ----------------------------------------------------

# Fourteen lsphp workers at ~26% each, plus the usual background noise. This is
# the shape of the real incident: no single PID is large, the executable total is.
printf 'combined aggregation (worker-pool shape)\n'
: >"${WORK}/cpu.tsv"
for i in $(seq 1 14); do
    printf '4741%02d\tlsphp\t20.00\t6.00\t26.00\t0\t1\t6.5\n' "$i" >>"${WORK}/cpu.tsv"
done
{
    printf '471732\thttpd\t1.80\t0.00\t1.80\t0\t9\t0.4\n'
    printf '471727\thttpd\t1.25\t0.00\t1.25\t0\t5\t0.3\n'
    printf '39327\tmariadbd\t2.80\t0.60\t3.40\t0\t11\t0.8\n'
    printf '36527\timunify-residen\t0.83\t0.67\t1.50\t0\t11\t0.3\n'
    printf '40064\timunify-realtim\t0.50\t0.75\t1.25\t0\t9\t0.3\n'
    printf '79287\tlfd - sleeping\t0.00\t2.00\t2.00\t0\t3\t0.5\n'
} >>"${WORK}/cpu.tsv"

{
    printf '1\tsystemd\t8708.00\t1372.00\t10080.00\t0\t2\t37.3\n'
    printf '39684\tdovecot\t6164.00\t76.00\t6240.00\t0\t1\t23.1\n'
    printf '472842\tlsphp\t496.00\t0.00\t496.00\t0\t3\t1.8\n'
    printf '39327\tmariadbd\t0.00\t87.33\t87.33\t0\t13\t0.3\n'
} >"${WORK}/io.tsv"

COMBINED="$(agg_combine "${WORK}/cpu.tsv" "${WORK}/io.tsv")"
top_row="$(printf '%s\n' "$COMBINED" | head -n 1)"
IFS=$'\t' read -r a_exec a_sub a_cpu a_rd _ a_procs a_peak a_avg _ _ <<<"$top_row"

assert_eq "$a_exec" "lsphp" "the worker pool leads the combined table"
assert_eq "$a_sub" "PHP" "subsystem is attached to the row"
assert_eq "$a_cpu" "364.00" "combined CPU sums all fourteen workers"
assert_eq "$a_peak" "26.00" "peak single process is retained"
assert_eq "$a_procs" "15" "process count is the union of CPU and I/O PIDs"
assert_eq "$a_rd" "496.00" "combined read joins the I/O ranking to the same executable"
if [[ "$(printf '%s' "$a_avg" | cut -d. -f1)" -lt 26 ]]; then
    pass "average per process is below the peak (${a_avg})"
else
    fail "average should be below peak (got ${a_avg})"
fi

httpd_row="$(printf '%s\n' "$COMBINED" | awk -F'\t' '$1=="httpd"')"
assert_eq "$(printf '%s' "$httpd_row" | cut -f3)" "3.05" "httpd workers are summed"
assert_eq "$(printf '%s' "$httpd_row" | cut -f6)" "2" "httpd process count is correct"

lfd_row="$(printf '%s\n' "$COMBINED" | awk -F'\t' '$1=="lfd"')"
if [[ -n "$lfd_row" ]]; then
    pass "pidstat state text does not create a separate row"
else
    fail "lfd row missing — state-text normalisation failed"
fi

# --- subsystem rollup --------------------------------------------------------

printf 'subsystem rollup\n'
ROLLUP="$(printf '%s\n' "$COMBINED" | agg_rollup)"
php_cpu="$(printf '%s\n' "$ROLLUP" | awk -F'\t' '$1=="PHP" { print $2 }')"
assert_eq "$php_cpu" "364.00" "PHP subsystem total matches the executable total"

maint_cpu="$(printf '%s\n' "$ROLLUP" | awk -F'\t' '$1=="Maintenance" { print $2 }')"
assert_eq "$maint_cpu" "2.75" "the differently-named imunify daemons collapse into one row"

rollup_top="$(printf '%s\n' "$ROLLUP" | head -n 1 | cut -f1)"
assert_eq "$rollup_top" "PHP" "rollup is ordered by CPU"

init_read="$(printf '%s\n' "$ROLLUP" | awk -F'\t' '$1=="Init" { print $3 }')"
assert_eq "$init_read" "8708.00" "PID 1 is attributed to Init rather than a workload"

printf 'rendering\n'
rendered="$(printf '%s\n' "$COMBINED" | agg_render_combined)"
assert_contains "$rendered" "EXECUTABLE" "combined table has a header"
assert_contains "$rendered" "PEAK_CPU" "combined table exposes peak single process"
assert_contains "$rendered" "lsphp" "combined table names the executable"
rendered_rollup="$(printf '%s\n' "$ROLLUP" | agg_render_rollup)"
assert_contains "$rendered_rollup" "SUBSYSTEM" "rollup table has a header"
assert_contains "$rendered_rollup" "PHP" "rollup names the subsystem"

# Aggregation must survive a missing ranking rather than erroring.
: >"${WORK}/empty.tsv"
only_cpu="$(agg_combine "${WORK}/cpu.tsv" "${WORK}/empty.tsv")"
assert_contains "$only_cpu" "lsphp" "aggregation works with no I/O ranking"
only_io="$(agg_combine "${WORK}/empty.tsv" "${WORK}/io.tsv")"
assert_contains "$only_io" "dovecot" "aggregation works with no CPU ranking"
neither="$(agg_combine "${WORK}/empty.tsv" "${WORK}/empty.tsv" || true)"
assert_eq "${neither:-empty}" "empty" "aggregation with no data returns nothing, not an error"

# --- distributed-load notice -------------------------------------------------

printf 'distributed-load notice\n'
if agg_distributed_notice 93.4 9.00 >/dev/null; then
    pass "notice fires at 93.4% total with a 9% top process"
else
    fail "notice should fire for the production case"
fi
notice="$(agg_distributed_notice 93.4 9.00)"
assert_contains "$notice" "distributed across multiple processes" "notice states the distribution"
assert_contains "$notice" "aggregated executable totals" "notice points at the aggregate view"

if agg_distributed_notice 93.4 60.00 >/dev/null 2>&1; then
    fail "notice must not fire when one process dominates"
else
    pass "notice suppressed when a single process dominates"
fi
if agg_distributed_notice 40.0 5.00 >/dev/null 2>&1; then
    fail "notice must not fire when the box is not busy"
else
    pass "notice suppressed when total CPU is low"
fi
if agg_distributed_notice NA 5.00 >/dev/null 2>&1; then
    fail "notice must not fire on a missing CPU reading"
else
    pass "notice suppressed when CPU is unmeasured"
fi

# --- process ring buffer -----------------------------------------------------

printf 'process ring buffer\n'
RING="$(ring_file)"

# Synthesise a run-up: quiet, then lsphp climbing 3 -> 14, matching production.
NOW=1784900000
{
    printf 'ts=%s iso=2026-07-24T19:34:12+0500 kind=exec comm=mariadbd procs=1 cpu=3.00 rss_mb=200 dstate=0\n' "$((NOW - 180))"
    printf 'ts=%s iso=2026-07-24T19:34:12+0500 kind=exec comm=lsphp procs=3 cpu=9.00 rss_mb=90 dstate=0\n' "$((NOW - 180))"
    printf 'ts=%s iso=2026-07-24T19:34:42+0500 kind=exec comm=lsphp procs=9 cpu=180.00 rss_mb=270 dstate=0\n' "$((NOW - 150))"
    printf 'ts=%s iso=2026-07-24T19:35:02+0500 kind=exec comm=lsphp procs=14 cpu=364.00 rss_mb=420 dstate=0\n' "$((NOW - 130))"
    printf 'ts=%s iso=2026-07-24T19:35:02+0500 kind=pid pid=474109 comm=lsphp cpu=26.00 rss_mb=30\n' "$((NOW - 130))"
    printf 'ts=%s iso=2026-07-24T19:40:00+0500 kind=exec comm=lsphp procs=1 cpu=2.00 rss_mb=30 dstate=0\n' "$((NOW + 600))"
} >"$RING"

runup="$(ring_render_runup "$NOW" "$((NOW + 60))")"
assert_contains "$runup" "lsphp" "run-up names the executable that was building"
assert_contains "$runup" "procs=14" "run-up shows peak worker concurrency"
assert_contains "$runup" "19:34:42" "run-up includes samples from before the trigger"
if [[ "$runup" == *"19:40:00"* ]]; then
    fail "run-up must not include samples after the incident ended"
else
    pass "run-up excludes post-incident samples"
fi

by_exec="$(ring_window_by_exec "$NOW" "$((NOW + 60))")"
lsphp_line="$(printf '%s\n' "$by_exec" | awk -F'\t' '$1=="lsphp"')"
assert_eq "$(printf '%s' "$lsphp_line" | cut -f2)" "14" "peak concurrency is the maximum, not the last value"
assert_eq "$(printf '%s' "$lsphp_line" | cut -f3)" "364.00" "peak CPU is retained"
assert_eq "$(printf '%s' "$lsphp_line" | cut -f4)" "3" "sample count covers the run-up window"
assert_eq "$(printf '%s\n' "$by_exec" | head -n 1 | cut -f1)" "lsphp" "run-up aggregate is ordered by CPU"

# Retention must drop stale entries and keep fresh ones.
printf 'ring retention\n'
{
    printf 'ts=%s iso=old kind=exec comm=ancient procs=1 cpu=1.00 rss_mb=1 dstate=0\n' "$(($(now_epoch) - 100000))"
    printf 'ts=%s iso=new kind=exec comm=recent procs=1 cpu=1.00 rss_mb=1 dstate=0\n' "$(now_epoch)"
} >"$RING"
ring_trim
trimmed="$(cat "$RING")"
if [[ "$trimmed" == *"ancient"* ]]; then
    fail "ring_trim did not drop entries beyond the retention window"
else
    pass "ring_trim drops entries beyond the retention window"
fi
assert_contains "$trimmed" "recent" "ring_trim keeps entries inside the retention window"

# An empty or absent ring must degrade quietly.
: >"$RING"
empty_runup="$(ring_render_runup "$NOW" "$((NOW + 60))")"
assert_contains "$empty_runup" "no ring samples" "an empty ring explains itself"
rm -f "$RING"
missing_runup="$(ring_render_runup "$NOW" "$((NOW + 60))" || printf 'ERRORED')"
assert_contains "$missing_runup" "no ring samples" "a missing ring file explains itself rather than erroring"
if [[ "$missing_runup" == *ERRORED* ]]; then
    fail "a missing ring file must not fail the caller"
else
    pass "a missing ring file does not fail the caller"
fi

# --- ps parsing ---------------------------------------------------------------
# `ps -eo` is unavailable in Git Bash, so the parser is fed captured Linux output
# rather than the live process table. The alternative is a parser that can only
# be exercised on the target host, which is precisely how the pidstat timestamp
# bug reached production - see docs/decisions.md.
printf 'ps output parsing\n'

# Shape of `ps -eo pid=,comm=,pcpu=,rss=,stat=` on el8: no header, comm padded,
# rss in kB. Fourteen lsphp workers plus background noise.
{
    for i in $(seq 1 14); do
        printf ' 4741%02d lsphp            26.0  31200 R\n' "$i"
    done
    printf '      1 systemd           0.0   9240 S\n'
    printf '  39327 mariadbd          3.4 220000 S\n'
    printf ' 471732 httpd             1.8  25000 S\n'
    printf ' 471727 httpd             1.2  24000 S\n'
    printf '    365 jbd2/vda2-8       0.0      0 D\n'
    printf '  36527 imunify-residen   0.8  45000 S\n'
} >"${WORK}/ps.txt"

RINGBUFFER_TOP_EXECS=15
RINGBUFFER_TOP_PIDS=10
parsed="$(ring_format <"${WORK}/ps.txt")"

assert_contains "$parsed" "kind=exec" "parser emits executable rows"
assert_contains "$parsed" "kind=pid" "parser emits individual PID rows"

lsphp_exec="$(printf '%s\n' "$parsed" | awk '/kind=exec/ && /comm=lsphp /')"
assert_contains "$lsphp_exec" "procs=14" "worker pool concurrency is counted"
assert_contains "$lsphp_exec" "cpu=364.00" "worker pool CPU is summed (14 x 26.0)"

first_exec="$(printf '%s\n' "$parsed" | awk '/kind=exec/ { print; exit }')"
assert_contains "$first_exec" "comm=lsphp" "executable rows are ordered by CPU"

httpd_exec="$(printf '%s\n' "$parsed" | awk '/kind=exec/ && /comm=httpd /')"
assert_contains "$httpd_exec" "procs=2" "multiple workers of one executable are grouped"
assert_contains "$httpd_exec" "cpu=3.00" "grouped CPU is summed"

jbd2_exec="$(printf '%s\n' "$parsed" | awk '/kind=exec/ && /comm=jbd2/')"
assert_contains "$jbd2_exec" "dstate=1" "D-state processes are counted per executable"

first_pid="$(printf '%s\n' "$parsed" | awk '/kind=pid/ { print; exit }')"
assert_contains "$first_pid" "comm=lsphp" "PID rows are ordered by CPU"

# Zero-CPU processes must not consume PID slots.
if printf '%s\n' "$parsed" | grep -q 'kind=pid.*comm=systemd'; then
    fail "idle processes should not occupy top-PID slots"
else
    pass "idle processes are excluded from top-PID rows"
fi

# Caps must hold.
RINGBUFFER_TOP_EXECS=2
RINGBUFFER_TOP_PIDS=3
capped="$(ring_format <"${WORK}/ps.txt")"
assert_eq "$(printf '%s\n' "$capped" | grep -c 'kind=exec')" "2" "executable rows respect RINGBUFFER_TOP_EXECS"
assert_eq "$(printf '%s\n' "$capped" | grep -c 'kind=pid')" "3" "PID rows respect RINGBUFFER_TOP_PIDS"
RINGBUFFER_TOP_EXECS=15
RINGBUFFER_TOP_PIDS=10

# Empty input must not produce junk.
empty_parsed="$(printf '' | ring_format || printf 'ERRORED')"
assert_eq "${empty_parsed:-none}" "none" "empty ps output yields no ring lines"

# Five-field input (no args) must still parse and must not fabricate PHP rows.
noargs="$(ring_format <"${WORK}/ps.txt")"
if printf '%s\n' "$noargs" | grep -q 'kind=php'; then
    fail "PHP rows must not appear when args were not captured"
else
    pass "absent args yields no PHP endpoint rows (backward compatible)"
fi

# --- PHP endpoint attribution -------------------------------------------------
# The single-account production case: many lsphp workers, all named "lsphp", each
# serving a different WordPress endpoint. mod_lsapi rewrites argv to
# "lsphp:<script>" and front-truncates long paths; only the tail survives. Shape
# of `ps -eo pid=,comm=,pcpu=,rss=,stat=,wchan=,args=` on el8. wchan sits between
# stat and args as a single token ("-" when the task is not blocked).
printf 'PHP endpoint attribution\n'
{
    printf ' 589246 lsphp            80.0  31200 R - lsphp:/home/drhackne/cryptoawaz.com/index.php\n'
    printf ' 589236 lsphp            77.0  31000 R - lsphp:ackne/cryptoawaz.com/wp-admin/admin-post.php\n'
    printf ' 589245 lsphp            60.0  30000 R - lsphp:kne/public_html/blog/wp-admin/admin-ajax.php\n'
    printf ' 589250 lsphp            55.0  30000 R - lsphp:kne/public_html/blog/wp-admin/admin-ajax.php?action=x\n'
    printf ' 588652 lsphp             0.0  20000 S - lsphp\n'
    printf '  39327 mariadbd          3.4 220000 S - /usr/sbin/mariadbd\n'
    printf '      1 systemd           0.0   9240 S - /usr/lib/systemd/systemd --system\n'
} >"${WORK}/psargs.txt"

php_parsed="$(ring_format <"${WORK}/psargs.txt")"
assert_contains "$php_parsed" "kind=php" "PHP endpoint rows are emitted from args"

index_row="$(printf '%s\n' "$php_parsed" | awk '/kind=php/ && /script=cryptoawaz.com\/index.php/')"
assert_contains "$index_row" "cpu=80.00" "front-page endpoint keeps site/script and its CPU"

ajax_row="$(printf '%s\n' "$php_parsed" | awk '/kind=php/ && /script=wp-admin\/admin-ajax.php /')"
assert_contains "$ajax_row" "procs=2" "the two admin-ajax workers collapse to one endpoint despite front-truncation"
assert_contains "$ajax_row" "cpu=115.00" "endpoint CPU sums its workers (60 + 55) and query strings do not split it"

post_row="$(printf '%s\n' "$php_parsed" | awk '/kind=php/ && /script=wp-admin\/admin-post.php/')"
assert_contains "$post_row" "cpu=77.00" "admin-post endpoint is attributed from a truncated path"

first_php="$(printf '%s\n' "$php_parsed" | awk '/kind=php/ { print; exit }')"
assert_contains "$first_php" "script=wp-admin/admin-ajax.php" "PHP rows are ordered by CPU (115 leads)"

if printf '%s\n' "$php_parsed" | grep -q 'kind=php.*script=mariadbd'; then
    fail "non-PHP processes must not become endpoints"
else
    pass "non-PHP processes are excluded from endpoint rows"
fi
if printf '%s\n' "$php_parsed" | awk '/kind=php/' | grep -qE 'script=lsphp( |$)'; then
    fail "idle lsphp workers (no script) must not become an endpoint"
else
    pass "idle lsphp workers are excluded from endpoint rows"
fi

# --- kernel wait channels from the ring ---------------------------------------
# Regression guard for the defect that cost 34 consecutive incidents their
# wait-channel evidence: the panic-time sampler starts 13-29s after the trigger
# and blocked tasks have cleared by then. The ring samples continuously, so it
# catches them — but only if wchan is actually parsed out of the ps row and only
# if a blocked PHP worker can be tied to the channel it is blocked in.
printf 'kernel wait channels from the ring\n'
{
    printf ' 589246 lsphp            62.0  31200 D jbd2_log_wait_commit lsphp:/home/drhackne/cryptoawaz.com/wp-admin/admin-ajax.php\n'
    printf ' 589247 lsphp            40.0  31200 D wait_on_page_writeback lsphp:ackne/cryptoawaz.com/index.php\n'
    printf ' 589248 lsphp            10.0  31200 S - lsphp:ackne/cryptoawaz.com/index.php\n'
    printf '  39327 mariadbd          7.8 220000 D jbd2_log_wait_commit /usr/sbin/mariadbd\n'
    printf '  36527 imunify-residen  21.4  45000 R - /usr/bin/imunify-resident\n'
} >"${WORK}/pswchan.txt"

RINGBUFFER_TOP_PHP=10
wchan_parsed="$(ring_format <"${WORK}/pswchan.txt")"

assert_contains "$wchan_parsed" "kind=wchan" "blocked tasks emit wait-channel rows"
jbd2_row="$(printf '%s\n' "$wchan_parsed" | awk '/kind=wchan/ && /chan=jbd2_log_wait_commit/')"
assert_contains "$jbd2_row" "procs=2" "a channel shared by two processes is counted once with both"

# Unblocked processes must never contribute a channel, or every idle sample
# would manufacture evidence of a stall.
if printf '%s\n' "$wchan_parsed" | grep -q 'kind=wchan.*chan=-'; then
    fail "the not-blocked placeholder must not become a wait channel"
else
    pass "unblocked tasks contribute no wait channel"
fi
if printf '%s\n' "$wchan_parsed" | awk '/kind=wchan/' | grep -q 'comm=imunify-residen'; then
    fail "a running (R) process must not appear as blocked"
else
    pass "running processes are excluded from wait-channel rows"
fi

# The join that names the culprit: endpoint plus the channel it blocked in.
ajax_blocked="$(printf '%s\n' "$wchan_parsed" | awk '/kind=php/ && /script=wp-admin\/admin-ajax.php/')"
assert_contains "$ajax_blocked" "dstate=1" "a blocked PHP worker is counted against its endpoint"
assert_contains "$ajax_blocked" "wchan=jbd2_log_wait_commit" "the endpoint carries the channel it was blocked in"

idx_blocked="$(printf '%s\n' "$wchan_parsed" | awk '/kind=php/ && /script=cryptoawaz.com\/index.php/')"
assert_contains "$idx_blocked" "dstate=1" "only the blocked worker of an endpoint counts, not its idle sibling"
assert_contains "$idx_blocked" "wchan=wait_on_page_writeback" "a second endpoint keeps its own distinct channel"

# A healthy box must add no wait-channel rows at all — this is what keeps the
# ring's steady-state cost at one ps per minute with nothing to store.
healthy="$(ring_format <"${WORK}/psargs.txt")"
if printf '%s\n' "$healthy" | grep -q 'kind=wchan'; then
    fail "an unblocked sample must not emit wait-channel rows"
else
    pass "an unblocked sample emits no wait-channel rows"
fi

# Window aggregation over the ring.
NOW_W="$(date +%s)"
: >"${WORK}/ringw.log"
{
    printf 'ts=%s iso=x kind=wchan chan=jbd2_log_wait_commit procs=3 comm=lsphp\n' "$((NOW_W - 60))"
    printf 'ts=%s iso=x kind=wchan chan=jbd2_log_wait_commit procs=7 comm=lsphp\n' "$((NOW_W - 30))"
    printf 'ts=%s iso=x kind=wchan chan=wait_on_page_writeback procs=2 comm=mariadbd\n' "$((NOW_W - 30))"
    printf 'ts=%s iso=x kind=php script=wp-admin/admin-ajax.php procs=4 cpu=200.00 dstate=3 wchan=jbd2_log_wait_commit\n' "$((NOW_W - 30))"
} >"${WORK}/ringw.log"
LOG_DIR="$WORK"
mv "${WORK}/ringw.log" "${WORK}/procring.log"

w_agg="$(ring_window_by_wchan "$((NOW_W - 120))" "$((NOW_W + 60))")"
top_w="$(printf '%s\n' "$w_agg" | head -n 1)"
assert_eq "$(printf '%s' "$top_w" | cut -f1)" "jbd2_log_wait_commit" "channels rank by peak blocked count"
assert_eq "$(printf '%s' "$top_w" | cut -f2)" "7" "peak blocked count is the maximum, not the last value"

pw="$(ring_window_php_wchan "$((NOW_W - 120))" "$((NOW_W + 60))")"
assert_contains "$pw" "wp-admin/admin-ajax.php" "the endpoint-to-channel join survives window aggregation"
assert_contains "$pw" "jbd2_log_wait_commit" "the joined row keeps its channel"

# Endpoint rows respect their cap.
RINGBUFFER_TOP_PHP=1
capped_php="$(ring_format <"${WORK}/psargs.txt")"
assert_eq "$(printf '%s\n' "$capped_php" | grep -c 'kind=php')" "1" "PHP rows respect RINGBUFFER_TOP_PHP"
RINGBUFFER_TOP_PHP=10

# Run-up aggregation by endpoint: peak concurrency and summed samples.
printf 'PHP run-up aggregation\n'
PNOW=1784900000
{
    printf 'ts=%s iso=2026-07-25T00:13:40+0500 kind=php script=wp-admin/admin-ajax.php procs=4 cpu=200.00\n' "$((PNOW - 120))"
    printf 'ts=%s iso=2026-07-25T00:14:55+0500 kind=php script=wp-admin/admin-ajax.php procs=9 cpu=440.00\n' "$((PNOW - 40))"
    printf 'ts=%s iso=2026-07-25T00:14:55+0500 kind=php script=cryptoawaz.com/index.php procs=2 cpu=90.00\n' "$((PNOW - 40))"
    printf 'ts=%s iso=2026-07-25T00:40:00+0500 kind=php script=wp-admin/admin-ajax.php procs=1 cpu=5.00\n' "$((PNOW + 3000))"
} >"$RING"

by_php="$(ring_window_by_php "$PNOW" "$((PNOW + 60))")"
ajax_agg="$(printf '%s\n' "$by_php" | awk -F'\t' '$1=="wp-admin/admin-ajax.php"')"
assert_eq "$(printf '%s' "$ajax_agg" | cut -f2)" "9" "run-up endpoint peak concurrency is the maximum"
assert_eq "$(printf '%s' "$ajax_agg" | cut -f3)" "440.00" "run-up endpoint peak CPU is retained"
assert_eq "$(printf '%s' "$ajax_agg" | cut -f4)" "2" "run-up endpoint sample count excludes post-incident samples"
assert_eq "$(printf '%s\n' "$by_php" | head -n 1 | cut -f1)" "wp-admin/admin-ajax.php" "run-up endpoints ordered by CPU"

# The accelerate check must read load without failing on an odd environment.
printf 'ring acceleration check\n'
# The real reader is measured here, before the stub below replaces it for the
# watermark cases.
# shellcheck disable=SC2218  # intentional: real function first, stub afterwards
load="$(ring_load1)"
if [[ "$load" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    pass "ring_load1 returns a numeric load (${load})"
else
    fail "ring_load1 returned a non-numeric value: '${load}'"
fi
# The watermark comparison is tested against a stubbed load rather than the
# machine's real one. Reading /proc/loadavg here made the result depend on how
# busy the test host happened to be: on an idle runner the "above the watermark"
# case reads 0.00 and fails, which is a property of the runner, not the code.
ring_load1() { printf '%s\n' "${STUB_LOAD:-0.00}"; }

STUB_LOAD=0.50
RINGBUFFER_FAST_LOAD=999999
if ring_should_accelerate; then
    fail "acceleration must not trigger below the watermark"
else
    pass "acceleration suppressed below the watermark"
fi

STUB_LOAD=7.25
RINGBUFFER_FAST_LOAD=3
if ring_should_accelerate; then
    pass "acceleration triggers above the watermark"
else
    fail "acceleration should trigger above the watermark"
fi

# The boundary: the watermark is a threshold to exceed, not to reach.
STUB_LOAD=3.00
if ring_should_accelerate; then
    fail "load exactly at the watermark must not accelerate"
else
    pass "load exactly at the watermark does not accelerate"
fi

if [[ "$FAILURES" -gt 0 ]]; then
    printf 'aggregate tests: %s failure(s)\n' "$FAILURES" >&2
    exit 1
fi
printf 'aggregate tests: all passed\n'
