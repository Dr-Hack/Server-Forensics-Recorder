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
- **`analysis.txt`** — `lib/analysis.sh` correlates the evidence at incident
  close into a likely subsystem + confidence + evidence + next steps, folds a
  one-line verdict into `summary.txt`, and is viewable via `--last-analysis`.
  The classifier is a transparent weighted-evidence model (wchan → subsystem,
  corroborated by blocked executable, running maintenance, IO wait, and
  low-CPU-vs-high-load), so the confidence figure is explainable.

Tuning note: the wchan/comm → subsystem maps in `lib/analysis.sh` are seeded
from general Linux knowledge. Feed real `dstate-*.log` output from a production
incident back in to sharpen them for this server's actual wait channels.

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
connections, likely bottleneck, recommended next investigation.

---

## Current assessment

| Area | State |
| --- | --- |
| Architecture | Excellent |
| Performance / overhead | Excellent |
| Code organization | Good |
| Metrics | Good — CPU and MariaDB now correct |
| Forensic capability | Good |

The project is already useful in production. The highest-value remaining work is
**trend detection**, since it turns raw samples into an explanation.
