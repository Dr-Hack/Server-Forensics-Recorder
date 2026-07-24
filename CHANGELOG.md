# Changelog

All notable changes to this project will be documented in this file.

## 0.4.0 — 2026-07-25

The recorder could prove "PHP saturated the box" but not *which request* did it.
On a single-account dedicated host that is the whole question — every worker is
named `lsphp` and owned by the one account, so both per-executable and per-user
views are blind. This release attributes the load to the endpoint.

### Added

- **PHP endpoint attribution.** The process ring buffer now captures each
  worker's command line (`ps ... args=`). Under Apache mod_lsapi the worker's
  argv is rewritten to `lsphp:<script path>`, which is the only place the served
  script is visible — `pidstat` and `comm` both show a bare `lsphp`. The ring
  parses that into a stable endpoint key (the last two path components, so a
  front-truncated `…ackne/site.com/wp-admin/admin-post.php` still aggregates
  cleanly as `wp-admin/admin-post.php`) and ranks workers by endpoint.

  On `incident-20260725-001537` — a sustained ~2h PHP saturation, load ~14, CPU
  99.6% — the offender detail happened to catch a few workers on
  `cryptoawaz.com/index.php`, `wp-admin/admin-post.php`, and
  `wp-admin/admin-ajax.php`, but most had already exited. The ring samples
  continuously and survives that churn, so the run-up now reports the hot
  endpoints even when the workers are gone by panic time.

  The analysis Run-up section and `--runup` gain a *Hot PHP endpoints* table;
  idle workers and non-PHP processes are excluded; query strings do not split an
  endpoint. Rows per sample are capped by `RINGBUFFER_TOP_PHP` (10).

## 0.3.0 — 2026-07-24

The recorder measured the right things but arrived after the event, and ranked
by PID when the cause was a worker pool. Both are fixed.

### Added

- **Pre-incident process ring buffer.** Panic mode is triggered by `load1`, a
  one-minute average that lags the work causing it, so a sub-minute burst is
  always sampled on its way down. On `incident-20260724-193525` the offender
  table accounted for ~49% of a machine that had been at 374%, and the largest
  process read 9%, because the fourteen `lsphp` workers had already exited. No
  trigger can outrun that: if the first per-process measurement happens after the
  trigger, the burst is over.

  The watcher now records a compact per-executable snapshot every cycle and, in
  between, polls `/proc/loadavg` every 10s — a single small read — taking a full
  sample only while load exceeds `RINGBUFFER_FAST_LOAD`. Steady-state cost on an
  idle server is one `ps` per minute; measured footprint is 2.5 KB per sample,
  37 KB of 15-minute history idle and 223 KB at maximum sampling rate.

  The ring **never declares an incident**, so enabling it cannot change when
  panic mode fires. The analysis gains a *Run-up* section showing what was
  building before the trigger; `--runup [ID]` and `--ring [N]` expose it directly.
- **Aggregation by executable and subsystem.** Ranking by PID is misleading for
  worker pools: fourteen `lsphp` at 26% each is invisible per-PID and obvious as
  one row. Reports now lead with a combined table — executable, subsystem,
  combined read/write/CPU, process count, peak single process, average per
  process — plus a subsystem rollup that collapses the nine differently-named
  Imunify daemons into one line. Per-PID tables are kept below.
- **Distributed-load notice.** When the machine exceeds
  `AGG_DISTRIBUTED_CPU_PCT` (90) but no single process reaches
  `AGG_DISTRIBUTED_TOP_PCT` (15), the report states plainly that usage is spread
  across processes and points at the aggregated totals, rather than leaving a
  9% top process to read as "nothing was using the CPU".
- **PID 1 is classified, not accused.** init writes on behalf of other services,
  so it routinely tops an I/O ranking without being a workload. It is now
  excluded from the named top consumer, and the capture explains *what* the
  delegated activity was — journal logging, service management, or undetermined —
  from its open descriptors, with the heaviest journal-writing units listed.

### Changed

- The systemd timer now uses `OnUnitActiveSec=60` rather than
  `OnUnitInactiveSec=60`. The latter counts from when the service *finishes*,
  which would have stretched the metric cadence to poll-window + 60s once the
  watcher began using the tail of each interval for ring polling.
- *Observed facts* falls back to values re-derived from the offender tables when
  incident meta is absent, so it can no longer contradict the *Inference* block
  when an older incident's analysis is regenerated.

## 0.2.0 — 2026-07-23

Named causes are now backed by per-process measurement rather than by which
service names happen to be present. See `docs/decisions.md` for the approaches
this release removed and why.

### Fixed

- **Per-process I/O attribution produced an empty table on the target server.**
  The ranking detected data rows with `$1 ~ /^[0-9]+$/`, assuming `pidstat -h`
  emits an epoch timestamp. sysstat 11.7.3 on el8 with a 12-hour locale emits
  `07:27:10 PM` — two whitespace-separated fields — so **every row was
  discarded**, `offenders-*.tsv` was empty, and `Top I/O Process` read `none`
  on a live incident with no error reported anywhere. Column indices are now
  anchored from the left by a detected timestamp width, samplers run under
  `S_TIME_FORMAT=ISO LC_ALL=C`, and the test suite carries verbatim production
  output as a fixture.
- **Resident daemons could be named as the cause.** Process-name presence scored
  up to `+24`, enough to lead a verdict on a cPanel box where the Imunify360
  daemons run permanently. Presence now scores `+2` and is capped below the
  inconclusive floor; it earns real weight only when the same process is also
  the measured top CPU or I/O consumer.
- **The recorder detected its own processes as maintenance activity.** `timeout`
  (the `run_with_timeout` wrapper) was listed as evidence. The exclusion list now
  covers the recorder's helpers, and `gpg` no longer maps to "Package manager".
- **The evidence ledger listed exclusions as support.** "No Apache pressure"
  appeared under *Supported by* for unrelated verdicts. Support is now selected
  per leading hypothesis, with exclusions in their own section.
- **Recurring-pattern counts hid their denominator.** Incidents without `.facts`
  were silently dropped; the count now states how many were skipped.

### Added

- **CPU saturation hypothesis and per-process CPU ranking.** `pidstat -u` was
  already captured but never read. It is now ranked into a second offender table
  (`cpuoffenders-*.tsv`), tracked as `peak_cpu_pid` / `peak_cpu_comm` /
  `peak_cpu_pct`, printed in `summary.txt`, and scored into a "CPU saturation"
  hypothesis. Without it the engine could not express "the box was simply busy",
  and a compute-bound spike fell through to whatever noise-floor hypothesis
  remained. `--offenders` now prints both tables, CPU first.
- `PANIC_IO_MAX_TRACKED_PIDS` bounds the ranking arrays so a fork storm cannot
  grow them without limit.
- `docs/decisions.md` — a record of superseded approaches and why they failed.

## 0.1.0

### Added

- **Per-process I/O attribution.** System metrics established *that* the server
  was storage-stalled; this establishes *which process moved the bytes*. Every
  panic snapshot now captures `pidstat -d` (per-process read/write and block-I/O
  delay), `pidstat -u` (per-process CPU over the same window), `iostat -x`
  (per-device service times), `/proc/pressure/{io,cpu,memory}`,
  `/proc/diskstats`, `mount` and `findmnt` into `io-N.log`. Processes are then
  ranked into an **offending-processes table** by actual throughput, and every
  process above `PANIC_IO_OFFENDER_PCT` of observed I/O gets a full detail block:
  PID, PPID, user, state, executable, command line, elapsed time, working
  directory, wait channel, open files (`lsof` and `/proc/PID/fd`) and cumulative
  `/proc/PID/io` counters. The incident's worst offender is retained in meta
  (`peak_io_pid`, `peak_io_comm`, `peak_io_kbs`) and printed in `summary.txt`, so
  it survives rotation of the verbose captures.

  The three sampling commands run **concurrently**, so the capture costs one
  sampling window rather than three and cannot starve the panic snapshot loop.
  `lsof` and every per-offender read is timeout-bounded, because a descriptor
  pointing at a stalled mount must never hang the recorder. Ranking parses
  `pidstat`'s own header rather than fixed column positions, so it works across
  sysstat versions that differ in the `iodelay` and `kB_ccwr/s` columns.

  New commands: `--offenders [ID]` for the ranked table, `--io [ID]` for the raw
  capture. `--doctor` now checks for `pidstat`, `findmnt`, root, and PSI. Gated
  by `ENABLE_IO_FORENSICS`; requires `sysstat`.

- **PSI (Pressure Stall Information) capture.** Each panic snapshot now records
  `/proc/pressure/{io,cpu,memory}` into `dstate-N.log`, and incidents track
  `peak_psi_io_full`, `peak_psi_cpu_some`, and `peak_psi_mem_full`. On a
  PSI-capable kernel this is the single best signal for telling a storage stall
  apart from a CPU or memory stall even when utilisation looks low. Three tiny
  `/proc` reads; skipped gracefully without `CONFIG_PSI`. Gated by
  `PANIC_CAPTURE_PSI`.
- **Evidence-based analysis report.** `analysis.txt` now separates **Observed
  facts -> Inference -> Evidence ledger -> Confidence distribution -> Proven /
  Inferred / Unknown -> Timeline -> Recurring patterns -> Next steps -> Missing
  evidence**. Confidence is a per-hypothesis distribution that is **gated by
  missing evidence**: when the decisive kernel signals (wait channel, blocked
  stack) were not captured, specific-cause confidence is capped and the cap is
  stated explicitly, so the report never overstates certainty and never reaches
  100%. A correlation engine folds recurring findings across past incidents
  (e.g. "Apache idle in 8/8 incidents") using a compact per-incident `.facts`
  file, and a timeline is reconstructed from the `current.log` samples that span
  the incident window. Covered by `tests/analysis.sh`.
- **D-state / blocking forensics.** Each panic snapshot now writes a
  `dstate-N.log` recording `ps -eo pid,user,state,wchan:40,comm,args`, the
  D-state processes alone, per-PID `/proc/<pid>/stack` and `wchan` (capped by
  `PANIC_DSTATE_MAX_PIDS`), `pstree -ap`, scheduled jobs (`systemctl
  list-timers`, `crontab -l`, `/etc/cron.*`), and any maintenance/package/backup
  processes **detected** from the process table. Package managers are never
  invoked. Gated by `ENABLE_DSTATE_FORENSICS` / `PANIC_CAPTURE_KERNEL_STACK`.
- **Investigation engine (`lib/analysis.sh`).** On incident close the recorder
  now generates `analysis.txt`: the most likely responsible subsystem
  (Filesystem / Disk / MariaDB / Apache / PHP / Backup / Package manager /
  Maintenance / Memory / Network / Kernel / Unknown), an explainable confidence
  level, the supporting evidence (most common wait channel and blocked
  executable, peak D-state, peak IO wait, low-CPU-vs-high-load), and recommended
  next investigation steps. A one-line verdict is folded into `summary.txt`.
- `iowait_pct` in the lightweight sample, derived from the same `/proc/stat`
  delta already used for CPU (no extra process spawned). Incidents now track
  `peak_dstate` and `peak_iowait`.
- `--latest`, `--tail [N]`, `--incidents`, `--last-incident`, and
  `--last-analysis` CLI commands for quickly inspecting samples, recorded
  outages, and the auto-generated root-cause analysis.
- Optional `MYSQL_DEFAULTS_FILE` config to point `mysqladmin` at a specific
  credentials file for status collection and panic diagnostics.

### Fixed (deployment)

- The systemd unit now exports `HOME=/root` so the MySQL/MariaDB client finds
  root's `~/.my.cnf` (where cPanel stores DB credentials) under systemd, which
  previously left the MariaDB metrics as `NA` even though the server was up.

### Fixed

- CPU busy percentage is now computed from the delta of `/proc/stat` between
  consecutive samples instead of a single lifetime-cumulative reading, which
  previously produced a near-constant value. The first sample after boot reports
  `NA` until a baseline exists.

### Changed

- MariaDB collection now records `Threads_running`, `Threads_connected`,
  `Questions`, `Uptime`, and `Slow_queries` from a single `extended-status`
  call, degrading to `NA` only when the server is unreachable.
- The watcher now collects samples in-process via `collect_metrics_line` rather
  than spawning `collector.sh --print`, removing a redundant subprocess and
  config reload per cycle.
- Panic snapshots run `lsof -nP` to avoid slow host and port name resolution
  under load.

## 0.1.0 - 2026-07-18

- Added lightweight forensic collector for cPanel-style Linux servers.
- Added threshold watcher and panic incident lifecycle.
- Added rich panic snapshots with graceful command skipping.
- Added incident summaries, cooldown handling, and rotation.
- Added systemd timer/service installation.
- Added GitHub-ready repository layout with docs and syntax test.
- Added ShellCheck, shfmt, Bash syntax, installer syntax, and systemd unit checks through GitHub Actions.
- Added safer uninstall markers and panic snapshot output caps for production deployment.
- Added CLI commands for version, health, doctor, and safe test panic mode.
- Added validated configuration and lightweight metric plugin support.
- Added contribution, security, issue, and pull request templates.
