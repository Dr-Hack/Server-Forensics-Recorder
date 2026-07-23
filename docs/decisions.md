# Decisions and Superseded Approaches

A record of approaches this project tried that turned out to be wrong, why they
failed, and what replaced them. Kept because several of these failures were
**silent** — the tool produced confident output that was simply incorrect — and
that is the failure mode most worth guarding against in a forensic recorder.

Newest first.

---

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
