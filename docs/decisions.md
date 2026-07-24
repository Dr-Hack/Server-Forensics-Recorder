# Decisions and Superseded Approaches

A record of approaches this project tried that turned out to be wrong, why they
failed, and what replaced them. Kept because several of these failures were
**silent** — the tool produced confident output that was simply incorrect — and
that is the failure mode most worth guarding against in a forensic recorder.

Newest first.

---

## Ranking spikes by PID alone — replaced in 0.3.0

**What it did.** `--offenders` and the analysis named the single highest-CPU and
highest-I/O PID.

**Why it was wrong.** `incident-20260724-193525` hit 93.4% CPU on a 4-core box
(~374% of a core) while the top single process read **9%**. The load was
fourteen short-lived `lsphp` workers at roughly 26% each. A PID-ranked table
cannot express "PHP took the box", so the report named a 9% process and the
whole table summed to ~49% of what was actually consumed.

**What replaced it.** Combined-by-executable and by-subsystem aggregation leads
every report, with process count, peak single process and average per process.
Plus an explicit notice when total CPU exceeds 90% with no single process over
15%, so a distributed cause is never read as "nothing was using the CPU".

## Sampling per-process data only after the trigger — replaced in 0.3.0

**What it did.** All per-process measurement happened inside panic mode, which
starts when `load1` crosses `LOAD_THRESHOLD`.

**Why it was wrong.** `load1` is a one-minute exponentially-weighted average, so
it peaks *after* the work does. On the incident above, load went 0.63 → 22.46
between two 60-second samples; the trigger fired at 19:35:25 and the first
`pidstat` window landed as the workers were exiting. The tool was structurally
guaranteed to measure the recovery rather than the event for any burst shorter
than the collector interval.

**Considered and rejected:** making the trigger faster (`procs_running` from
`/proc/stat`, a lower `LSPHP_THRESHOLD`). These help marginally but cannot fix
the ordering problem — if the first measurement happens after the trigger, a
30-second burst is still measured on its way down. The user also chose to leave
triggers unchanged to avoid alert noise.

**Also rejected:** evaluating an acceleration watermark once per 60-second
sample. At 19:34:12 load was 0.63 — there was nothing to trip on, and the entire
burst then ran inside the 69-second gap. Watermark-on-the-slow-sample buys
nothing for exactly the case it was meant to catch.

**What replaced it.** A continuously-maintained ring buffer, with acceleration
driven by a cheap 10-second poll of `/proc/loadavg` rather than by the 60-second
sample. The ring never declares an incident, so it cannot change trigger
behaviour.

## Treating PID 1 as an offender — fixed in 0.3.0

**What it did.** PID 1 topped the I/O ranking on a live incident (8.7 MB/s read)
and was promoted into the *Proven* tier as "largest disk consumer".

**Why it was wrong.** init performs writes on behalf of other services — journal
forwarding, unit state, cgroup bookkeeping. Naming it is almost always
misattribution, and it displaced the real consumer from the report.

**What replaced it.** PID 1 is excluded from the named top consumer, the first
non-init process is named instead, and the capture explains what the delegated
activity actually was, classified from its open descriptors.

## Verifying a `ps`-based parser only on the target host — avoided in 0.3.0

**What was nearly repeated.** `ring_sample` originally piped `ps -eo` straight
into an inline awk program. Git Bash on the development machine has no `ps -eo`,
so the parser could not be exercised locally at all — the same position that let
the pidstat timestamp bug reach production.

**What was done instead.** Listing and parsing were split: `ring_format` reads
`ps` output on stdin and is fed captured Linux output by the test suite, while
`ring_sample` only supplies the pipe. The parser is now covered by thirteen
assertions without needing the target host.

## Scoring a cause from process *names* — replaced in 0.2.0

**What it did.** `analysis_classify` awarded points to "Maintenance interaction"
and "Package manager" for every matching process name found in the process
table: `+12` to `+15` each, up to roughly `+24`.

**Why it was wrong.** On a cPanel box the Imunify360 daemons
(`imunify-agent-p`, `wafd_imunify_da`, `pam_imunify_dae`, and six more) are
resident 24/7. Their presence during an incident carries **zero information**
about that incident. Production `incident-20260723-071746` was reported as
`Maintenance (84%)` on this basis. After the 0.1.0 rewrite the same class of
evidence still produced `Maintenance interaction (29%)` on
`incident-20260723-192658` — lower, but still the named cause, and still wrong.

**What replaced it.** Presence now scores `+2`. It becomes real evidence
(`+35`) only when the same process also appears as the measured top consumer in
the CPU or I/O offender table. Uncorroborated presence is capped at
`SF_INCONCLUSIVE_FLOOR`, so it can never be named as the cause. The report says
explicitly: *"maintenance/package/backup processes present but NONE consumed
measurable CPU or I/O ... (presence is not evidence)"*.

## Detecting maintenance without excluding the recorder's own processes — fixed in 0.2.0

**What it did.** The detector in `scripts/panic.sh` matched a keyword list
against the full `ps` output, excluding only `awk|ps|sh|bash`.

**Why it was wrong.** It matched `timeout` — the recorder's own
`run_with_timeout` wrapper — and listed it as maintenance activity. The tool was
scoring its own processes as evidence of a cause. `gpg-agent` was also caught
and mapped to "Package manager" purely because `analysis_comm_subsystem`
matched `*gpg*`.

**What replaced it.** The exclusion list now covers `timeout`, `pidstat`,
`iostat`, `vmstat`, `lsof`, `find`, `sed`, `grep`, `head`, `sort` and anything
whose command line contains `server-forensics`. `*gpg*` was removed from the
package-manager map.

## No CPU-bound hypothesis — added in 0.2.0

**What it did.** `SF_HYPOTHESES` covered blocking, storage, memory, network and
the application tiers, but had no entry for "the box was simply busy". CPU was
only ever used as *negative* evidence (`CPU < 30%` → not compute-bound).

**Why it was wrong.** `incident-20260723-192658` was 80.6% CPU at load 12.46
with 0.6% I/O wait and zero D-state tasks. Every genuine signal correctly scored
zero because the engine had no way to express the right answer, so the verdict
fell through to the noise floor.

**What replaced it.** A "CPU saturation" hypothesis scored from measured
`cpu_busy_pct` at peak load and from the per-process CPU ranking. It is not
capped by the missing kernel signals (wchan/stack/PSI) because it does not
depend on them.

## Listing exclusions as support in the evidence ledger — fixed in 0.2.0

**What it did.** `analysis_ledger` printed one fixed checklist regardless of
which hypothesis led, so `[x] no Apache pressure (7 workers)` appeared under
**"Supported by"** for a maintenance verdict.

**Why it was wrong.** "Apache is idle" is the absence of a competing cause. It
is not a reason to believe any particular remaining hypothesis.

**What replaced it.** Support is now selected per leader, and exclusions moved
to a separate **"Alternatives ruled out (not support for X)"** section.

## Parsing pidstat by fixed column offsets — fixed twice

**Attempt 1 (0.2.0-dev).** Split the header on whitespace and subtract one for
the leading `#` token.

*Failed because* sysstat also emits the marker attached to the first column
(`#Time` rather than `# Time`). Every index shifted, `PID` resolved to the `UID`
column, the resulting `0` was dropped by the `pid == 0` guard, and the offender
table came out **empty with no error**. Caught by a pre-push probe, never
shipped.

*Replaced by* stripping `^#[ \t]*` before splitting, so header index maps 1:1
onto data field index.

**Attempt 2 (shipped in 42adcc1, broken in production).** Detected data rows
with `$1 ~ /^[0-9]+$/`, assuming `pidstat -h` emits an epoch timestamp.

*Failed because* sysstat 11.7.3 on el8 with a 12-hour locale emits
`07:27:10 PM` — **two** whitespace-separated fields. `07:27:10` does not match
`^[0-9]+$`, so **every data row was discarded**. `offenders-1.tsv` was 0 bytes
and `Top I/O Process` read `none` on a live incident. The bug was invisible
until real server output was examined, because all three test fixtures used the
epoch form.

*Replaced by* detecting the timestamp width from the data (`$2 == "AM" || $2 ==
"PM"` → two fields, else one) and anchoring every column from the left by that
offset. The offset **cannot** be derived from field-count arithmetic, because
`Command` itself contains spaces for some processes (`lfd - sleeping`). Samplers
also now run under `S_TIME_FORMAT=ISO LC_ALL=C` for determinism, and the test
suite carries verbatim production output as a fixture.

**Lesson recorded:** fixtures invented from documentation are not evidence that
a parser works. Capture real output from the target host before claiming a
format is handled.

## Waiting for background samplers with a bare `wait` — fixed pre-push

**What it did.** `capture_io_forensics` started three concurrent samplers and
called `wait` with no arguments.

**Why it was wrong.** Bare `wait` reaps *every* background job in the shell. A
probe confirmed it blocking for the full duration of an unrelated 6-second job.
Nothing in the panic path backgrounds work today, so it was latent — but any
future `&` upstream would have stalled the capture.

**What replaced it.** Sampler PIDs are tracked in `SF_IO_JOBS` and waited on
individually by `io_wait_jobs`, with a regression test.

## Running the three samplers serially — never shipped

**Considered and rejected.** `pidstat -d 1 10`, `pidstat -u 1 10` and
`iostat -x 1 10` run one after another need 30 seconds against a
`PANIC_SNAPSHOT_INTERVAL` of 10, which would have starved the snapshot loop
during the exact window under investigation.

**What replaced it.** All three run concurrently into separate files and are
merged in a fixed order. They are passive `/proc` readers, so overlapping them
costs effectively nothing and the capture takes one sampling window.

## Writing a scratch file to render the offender table — fixed pre-push

**What it did.** `cmd_offenders` wrote the aggregated TSV to a temp file, with a
fallback path inside the incident directory.

**Why it was wrong.** A read-only inspection command should not write anything,
and the fallback would fail outright for a non-root caller — killing the CLI
under `set -e`.

**What replaced it.** `io_render_stream` reads rows from stdin.

## Unbounded sampler output — fixed pre-push

**What it did.** Sampler output was captured with no line limit.

**Why it was wrong.** `pidstat` on a box with thousands of processes is
unbounded, and the recorder must not be able to fill the disk it is already
stalled on.

**What replaced it.** `PANIC_IO_MAX_LINES` (default 20000) caps each sampler,
and `PANIC_IO_MAX_TRACKED_PIDS` (default 5000) bounds the ranking arrays so a
fork storm cannot grow them without limit.
