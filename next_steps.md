# Server Forensics Recorder - Roadmap & Status

## Purpose

This project is **not** another monitoring system. Netdata already tells us
*when* something is wrong. This project preserves enough evidence to explain
*why* an intermittent outage happened, on cPanel / CloudLinux / Apache +
mod_lsapi / lsphp / MariaDB / WordPress / Exim stacks.

Constraints: production safe, very low overhead. The architecture
(collector → watcher → panic → rotation) is sound and stays.

---

## Done

These were on the original wishlist and are implemented:

- **Trigger reason** — incidents record the exact threshold(s) crossed, e.g.
  `load1=12.3>10,lsphp=51>40`, which is richer than a bare `Trigger=LOAD`.
- **`--version`** — name, version, install dir, active config path.
- **`--doctor`** — validates writable dirs, dependencies, and systemd state.
- **`--test-panic`** — creates and closes a safe incident with no expensive
  diagnostics; refuses to run while a real incident is active.
- **`--health` / `--health-json`** — timer/service state, last run, incidents.
- **Config validation** — `validate_config` rejects non-numeric thresholds,
  out-of-range values, and unsafe / non-absolute paths at startup.
- **Panic snapshots** — `ps auxfww`, `top -b -n1`, `vmstat`, `iostat`,
  `ss -antp`, `lsof -nP`, `mysqladmin processlist/status`, `dmesg`,
  `journalctl --since -5min`, each guarded by timeout and output caps, and
  skipped gracefully when the command is absent. Expensive commands run only in
  panic mode.
- **Plugin architecture** — `lib/plugins.sh` loads lightweight metric plugins
  from `plugins/metrics/` and `/etc/server-forensics/plugins/metrics/`.
- **GitHub scaffolding** — README, DESIGN, CHANGELOG, CONTRIBUTING, SECURITY,
  LICENSE, issue/PR templates, and CI (ShellCheck, `bash -n`, format, systemd).

## Recently fixed

- **CPU calculation** — was a single lifetime-cumulative `/proc/stat` read
  (never changed). Now a delta against a persisted previous sample in
  `.state/cpu_stat`; `NA` until a baseline exists.
- **MariaDB metrics** — now `Threads_running`, `Threads_connected`, `Questions`,
  `Uptime`, `Slow_queries` from one `extended-status` call.

## Investigation engine (implemented)

The recorder no longer just counts D-state processes — it explains them. This
was the highest-priority work after several real incidents were traced to high
D-state counts with low CPU.

- **D-state forensics** — each panic snapshot writes `dstate-N.log`: full
  `ps … wchan:40 …`, the D-state processes alone, per-PID `/proc/<pid>/stack`
  and `wchan` (capped by `PANIC_DSTATE_MAX_PIDS`), `pstree -ap`, scheduled jobs
  (`systemctl list-timers`, `crontab -l`, `/etc/cron.*`), and detected
  maintenance/package/backup processes. Package managers are **detected, never
  invoked** — running `dnf`/`yum`/`rpm` during a stall could make the recorder
  part of the outage.
- **IO wait** — `iowait_pct` added to the lightweight sample from the existing
  `/proc/stat` delta (no `vmstat`/`iostat` spawn); incidents track `peak_iowait`
  and `peak_dstate`.
- **`analysis.txt` (evidence-based reporter)** — `lib/analysis.sh` turns the
  captured evidence at incident close into a report that separates **Observed
  facts → Inference → Evidence ledger → Confidence distribution → Proven /
  Inferred / Unknown → Timeline → Recurring patterns → Next steps → Missing
  evidence**. Confidence is a per-hypothesis distribution **gated by missing
  evidence**: without a readable wait channel or kernel stack, specific-cause
  confidence is capped (and the cap and its reason are printed), so it never
  overstates and never reaches 100%. Folds a one-line verdict into `summary.txt`,
  viewable via `--last-analysis`, and covered by `tests/analysis.sh`.
- **PSI capture (shipped)** — each panic snapshot records
  `/proc/pressure/{io,cpu,memory}` and the incident tracks peak io/cpu/memory
  pressure. This is the signal that proves whether a "high load, low CPU" stall
  was storage-, CPU-, or memory-bound, and it feeds the classifier and the
  Proven tier directly. Gated by `PANIC_CAPTURE_PSI`.
- **Correlation engine (shipped)** — a compact per-incident `.facts` file lets
  the reporter fold recurring findings across all recorded incidents (e.g.
  "Apache idle in 8/8", "high D-state in 7/8") into every analysis, robust even
  after old `dstate-*.log` files are rotated away.
- **Timeline (shipped)** — reconstructed from the `current.log` samples spanning
  the incident window, annotated with the transitions (load crossing threshold,
  D-state climbing, IO-wait spikes, recovery).

Tuning note: the wchan/comm → subsystem maps and the scoring weights in
`lib/analysis.sh` are seeded from general Linux knowledge. Feed real
`dstate-*.log` output and PSI peaks from a production incident back in to sharpen
them for this server's actual wait channels.

---

## Capture timing (0.6.0, shipped 2026-07-29)

The 0.5.2 rapid D-state sampler worked and still reported
`no D-state processes caught across 6 samples` **8 times out of 8** across four
consecutive incidents (`Wait channel captured 0/34` all-time). It was arriving
too late, not failing. On `incident-20260728-143130` — triggered *by*
`dstate=8>5` — the collectors ahead of it cost 29s (`vmstat` 4s, `iostat` 2s,
`ss -antp` **17s**, `lsof -nP` 6s) and every blocked task had cleared.

- **Capture ordered by perishability** — D-state/wchan/stacks/PSI first,
  `ss`/`lsof` last. Lag 13-29s → <1s.
- **Wait channels in the ring buffer** — `wchan` rides on the `ps` the ring
  already runs (no extra process). The structural fix: no trigger can outrun a
  sub-minute stall, so the ring, which samples before the threshold trips, is now
  the primary source and the panic snapshot is context.
- **Blocked-task attribution** — `kind=php` rows carry `dstate` + `wchan`, so a
  report can say *which request* was waiting in which kernel subsystem.
- **Orphan sweep** — the watcher closes an incident left open by a dead
  `panic.sh`. Two 3h+ orphans on 2026-07-28 were each closed against an
  unrelated later event; 183224 was scored "Package manager 38%" on a `dnf` run
  three hours after its trigger.
- **Stale-capture guard**, **ERR trap**, **snapshot index reservation**,
  **capture provenance reporting**.

---

## Remaining ideas (not yet implemented)

### Provider accountability evidence (HIGHEST PRIORITY)

**Goal:** produce a timestamped, defensible record that the stalls originate
**below** the OS — the hypervisor and the storage backend — so it can be put to
Namecheap directly. Root cause was already proven on 2026-07-27 (incident
183639: `vda` 97% util at 56-125ms `w_await` while doing **under 1 MB/s**, dmesg
clean). What is missing is not the finding but the **time series** to argue with.

Three gaps. The first is now closed; two remain.

1. ~~**`steal_pct` is not captured.**~~ **DONE in 0.6.1.** Steal time is the vCPU
   being ready to run while the hypervisor gave the physical core to someone
   else — it cannot be caused by our own workload, so it is not arguable, which
   makes it the strongest single metric in a provider dispute. `/proc/stat`
   field 9 was already inside the line `read_cpu_fields` sums for `total`, so it
   costs nothing. Now reported as `Peak CPU Steal` in `summary.txt`, an observed
   fact, **per-row timeline annotations** (`<- CPU steal 44.7% (host)` — these
   are the timestamps to quote), a `CPU steal (host contention) n/N`
   recurring-patterns line, and a provider action item. Gated by
   `STEAL_NOTABLE_PCT` (default 5).
   - Carried forward as a caveat: `cpu_busy_pct` counts stolen time as busy
     (`total - idle - iowait`, and `total` includes steal). The definition was
     left unchanged for comparability with previously recorded incidents; the
     analysis discloses the overlap, and when the verdict is *CPU saturation* the
     ledger raises stolen time as a competing explanation — otherwise host
     contention gets scored as local load.
2. **Disk latency is not in the per-minute timeline.** `r_await` / `w_await` /
   `%util` exist only inside panic `iostat` output, so we can show a stall but
   cannot plot latency across an evening. Deriving await from a
   `/proc/diskstats` delta uses the same persisted-previous-sample technique as
   the CPU delta — cheap, no `iostat` spawn, and it makes latency a first-class
   time series.
3. **No report aimed at the dispute.** A `--provider-evidence [since]` command
   emitting a timestamped table — time, load, cpu, **steal**, iowait, `w_await`,
   `%util`, throughput, PSI io — with the argument stated explicitly: *high
   latency and high steal at low throughput is backend contention, not our
   load.* Correlating against `%steal` distinguishes a noisy CPU neighbour from
   a noisy storage neighbour.

The honest limit to state in that report: `%steal` proves CPU contention
directly, whereas storage contention is inferred from latency-at-low-throughput.
Both are strong; only the first is unarguable.

### Trend detection
Flag rapid changes rather than only absolute values, e.g. "load +450% in 4 min"
or "lsphp 3 → 48". This would make `summary.txt` far easier to read. Requires
retaining a short window of recent samples (the state dir is the natural home).

### PHP version breakdown
Split `lsphp_count` into `php80_lsphp=2 php81_lsphp=1 php82_lsphp=3` by parsing
the lsphp binary path from `ps`. Useful on multi-PHP cPanel servers.

### Apache mod_status
When `mod_status` is reachable, collect `BusyWorkers`, `IdleWorkers`, and
`RequestsPerSec`; skip gracefully otherwise.

### JSON output
Optional `current.json` / `incident.json` for Grafana / Prometheus / AI
summarization pipelines. (`--health-json` already exists as a starting point.)

### `summarize INCIDENT` command
Human-readable incident digest: duration, peak load / lsphp / memory /
connections, likely bottleneck, recommended next investigation. Mostly covered
now by `analysis.txt` + `--last-analysis`; what remains is a compact one-screen
digest and the ability to target an arbitrary past incident by id.

---

## Current assessment

| Area | State |
| --- | --- |
| Architecture | Excellent |
| Performance / overhead | Excellent |
| Code organization | Good |
| Metrics | Good — CPU and MariaDB now correct |
| Forensic capability | Strong — evidence-based analysis, PSI, timeline, correlation |
| Root-cause reasoning | Strong — observed/inferred/proven with evidence-gated confidence |

The project is already useful in production. With the evidence-based reporter,
PSI capture, timeline, correlation engine and perishability-ordered capture in
place, the highest-value remaining work is, in order:

1. **Provider accountability evidence** — `steal_pct` shipped in 0.6.1; what
   remains is **per-minute disk latency** from a `/proc/diskstats` delta, then
   the `--provider-evidence` report. This is what converts a proven diagnosis
   into a case Namecheap has to answer. Storage is the harder half: steal is
   already unarguable, whereas latency-at-low-throughput is an inference, so the
   value of a per-minute series is that it shows the pattern holding across
   hours rather than in a single captured moment.
2. **Tune the wchan/comm maps against real captures.** The maps in
   `lib/analysis.sh` are still seeded from general Linux knowledge, and until
   0.6.0 no incident had ever captured a wait channel to check them against. The
   ring should start producing `kind=wchan` rows now, so this is finally
   testable.
3. **Trend detection** — turn raw samples in `summary.txt` into plain language.
