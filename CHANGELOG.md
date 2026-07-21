# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

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
