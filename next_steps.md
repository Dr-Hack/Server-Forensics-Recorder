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

## Remaining ideas (not yet implemented)

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
PSI capture, timeline, and correlation engine in place, the highest-value
remaining work is **feeding real production `dstate-*.log` + PSI peaks back into
the wchan/comm maps and scoring weights**, then **trend detection** to turn raw
samples in `summary.txt` into a plain-language explanation.
