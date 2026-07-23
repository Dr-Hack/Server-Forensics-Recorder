# Server Forensics Recorder

[![CI](https://github.com/Dr-Hack/Server-Forensics-Recorder/actions/workflows/ci.yml/badge.svg)](https://github.com/Dr-Hack/Server-Forensics-Recorder/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25.svg)](scripts/)
[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)](docs/installation.md)

A lightweight Linux server forensic recorder for intermittent outages on
cPanel, CloudLinux, Apache, `mod_lsapi`, `lsphp`, MariaDB, Exim, and WordPress
servers.

Think of it as a small black box for production web servers.

Monitoring tells you **that** a problem happened.

Server Forensics Recorder preserves evidence so you can determine **why** it
happened.

> ### ⭐ New: Automatic root-cause analysis
>
> The recorder no longer just captures raw snapshots — it now performs a
> **first-pass forensic investigation for you**. Every incident closes with an
> `analysis.txt` that separates **observed facts, inference, and proof**, ranks
> the likely causes with a confidence that is **gated by missing evidence** (it
> never overstates and never reaches 100%), reconstructs a **timeline**, and
> correlates **recurring patterns** across past incidents. It was built to answer
> the hardest question this stack throws at you: *why is load very high while CPU
> is almost idle?* — by capturing which processes went into uninterruptible
> **D-state**, **what kernel wait channel they were blocked on**, and the **PSI**
> pressure that proves whether the stall was storage, CPU, or memory. See
> [Automatic Root-Cause Analysis](#automatic-root-cause-analysis).

## Why This Exists

Intermittent outages often disappear before an administrator can log in. Load
settles, workers exit, sockets close, queues drain, and the useful evidence is
gone.

This project records cheap metrics during normal operation and automatically
captures deeper diagnostics only when the server crosses a configured threshold.
It is intentionally not a monitoring dashboard. Netdata, Prometheus, Grafana,
and similar tools are still the right place for live monitoring.

## Target Stack

Built for real-world shared hosting and WordPress infrastructure:

- AlmaLinux 8
- cPanel
- Apache
- CloudLinux
- `mod_lsapi`
- `lsphp`
- MariaDB
- Exim
- Cloudflare proxy
- WordPress workloads

The collector is generic enough to run on many Linux web servers, but the panic
snapshots are tuned for cPanel-style hosting stacks.

## Highlights

- **Automatic root-cause analysis** — every incident ends with a human-readable
  `analysis.txt` separating observed / inferred / proven, with an
  evidence-gated confidence distribution, a timeline, and cross-incident patterns
- **D-state / blocking forensics** — records which processes blocked, on which
  kernel wait channel, and the **PSI** pressure behind it, the answer to
  "high load, low CPU"
- Tiny normal overhead
- One lightweight sample per minute
- Panic mode only when thresholds trip
- Incident folders with rich diagnostic snapshots
- Graceful fallback when optional commands are missing
- systemd timer installation
- Clean uninstall
- ShellCheck and `shfmt` CI checks
- Plain Bash, no heavy runtime dependencies

## Quick Start

Clone and install as root:

```bash
git clone https://github.com/Dr-Hack/Server-Forensics-Recorder.git
cd Server-Forensics-Recorder
sudo bash install.sh
```

Check the timer:

```bash
systemctl list-timers server-forensics.timer
systemctl status server-forensics.timer
```

Run one watcher cycle manually:

```bash
sudo /opt/server-forensics/scripts/watcher.sh
```

Operational checks:

```bash
server-forensics --version
server-forensics --health
server-forensics --health-json
sudo server-forensics --doctor
sudo server-forensics --test-panic
```

Logs and incidents are written to:

```text
/var/log/server-forensics/
```

## Commands

The installed CLI is `server-forensics` (symlinked into `/usr/local/sbin` and
`/usr/bin`). Commands that read or write `/var/log/server-forensics` need root,
so run them with `sudo`.

| Command | What it does |
| --- | --- |
| `server-forensics --version` | Version, install directory, and active config path. |
| `server-forensics --health` | Timer/service state, last run, active + last incident, and thresholds. |
| `server-forensics --health-json` | The same health data as JSON (pipe to `jq`). |
| `server-forensics --doctor` | Validate config, writable dirs, dependencies, and systemd state. |
| `server-forensics --latest` | Print the newest lightweight sample, one field per line. |
| `server-forensics --tail [N]` | Print the last `N` samples from `current.log` (default 10). |
| `server-forensics --incidents` | List recorded incidents, newest first, with their trigger reason. |
| `server-forensics --last-incident` | Print the summary of the most recent incident. |
| `server-forensics --last-analysis` | Print the auto-generated root-cause analysis (`analysis.txt`) of the latest incident. |
| `server-forensics --offenders [ID]` | **Which process was actually consuming I/O** — the offending-processes table ranked by disk read+write, merged across the incident's snapshots. Defaults to the latest incident. |
| `server-forensics --io [ID]` | Full I/O attribution capture: `pidstat -d`/`-u`, `iostat -x`, PSI, `/proc/diskstats`, mounts, and per-offender `cmdline`/`cwd`/open files/`/proc/PID/io`. |
| `server-forensics --test-panic` | Create and close a safe incident with no expensive diagnostics. |
| `server-forensics --collect` | Take one lightweight sample now and append it to `current.log`. |
| `server-forensics --watch` | Run one full watcher cycle (collect, evaluate thresholds, panic if tripped). |
| `server-forensics --help` | Show usage. |

Common workflows:

```bash
# Is it running and healthy right now?
sudo server-forensics --doctor && server-forensics --health

# What do the live numbers look like?
server-forensics --latest
server-forensics --tail 20

# Analyze the most recent outage
server-forensics --incidents
server-forensics --last-incident
# read the automated first-pass root-cause verdict:
server-forensics --last-analysis
# then drill into the captured diagnostics:
less /var/log/server-forensics/incidents/incident-*/snapshot-1.log
# and the D-state / blocking evidence behind the verdict:
less /var/log/server-forensics/incidents/incident-*/dstate-1.log
```

## How It Works

Normal path:

```text
systemd timer
  -> watcher
  -> collect lightweight metrics
  -> current.log
  -> exit if healthy
```

Panic path:

```text
threshold crossed
  -> create incident
  -> capture snapshot every 10 seconds
  -> keep capturing until recovery
  -> write summary
  -> rotate old incidents
```

The normal collector reads mostly from `/proc`. Expensive commands such as
`lsof`, `journalctl`, `top`, `vmstat`, `iostat`, full process listings, and
MariaDB process lists are used only in panic mode.

## Collected Lightweight Metrics

Each normal sample is appended to `current.log` as a single key-value line.

Examples of collected fields:

- Timestamp and uptime
- Load average
- CPU busy percentage (delta of `/proc/stat` between samples; `NA` on the first
  sample after boot)
- IO wait percentage (from the same `/proc/stat` delta; no extra process spawned)
- Memory and swap
- Apache worker count
- `lsphp` process count
- Average and oldest `lsphp` age
- MariaDB running state
- MariaDB `Threads_running`, `Threads_connected`, `Questions`, `Uptime`, and
  `Slow_queries` when reachable (`NA` otherwise)
- Exim queue size when available
- TCP state summary
- Processes in uninterruptible `D` state

Example:

```text
timestamp=2026-07-18T17:30:25+0500 load1=12.33 mem_available_mb=420 lsphp_count=51 tcp_established=344 dstate_processes=1
```

## Panic Snapshots

When the watcher detects an unhealthy sample, it creates an incident directory:

```text
/var/log/server-forensics/incidents/incident-20260718-173025/
```

Typical files:

```text
summary.txt      # peak metrics + one-line root-cause verdict
analysis.txt     # automated root-cause analysis (see below)
snapshot-1.log   # general diagnostics
dstate-1.log     # D-state / blocking evidence (wchan, kernel stacks, cron, ...)
snapshot-2.log
dstate-2.log
```

Snapshot diagnostics include:

- `date`
- `uptime`
- `free -m`
- `vmstat 1 5`
- `iostat -xz 1 3`
- `top -b -n1`
- `ps auxfww`
- `ss -antp`
- `lsof`
- `df -h`
- `dmesg | tail -100`
- `journalctl --since "-5 min"`
- `mysqladmin processlist`
- `mysqladmin status`
- `apachectl status`

Missing commands are skipped gracefully and recorded in the snapshot.

## Automatic Root-Cause Analysis

Several real production incidents on this stack were driven by processes piling
up in uninterruptible **D-state**, producing very high load with almost idle
CPU. Counting D-state processes told us *that* it was happening; it did not tell
us *which* processes were blocked, *what* they were waiting on, or *why*.

The recorder now answers those questions automatically. During panic mode each
snapshot also writes a `dstate-N.log` capturing:

- `ps -eo pid,user,state,wchan:40,comm,args`, and the **D-state processes alone**
- per-PID `/proc/<pid>/stack` and `/proc/<pid>/wchan` (the kernel wait channel —
  the single most valuable signal for a blocking stall)
- **PSI** from `/proc/pressure/{io,cpu,memory}` (Pressure Stall Information) —
  how long tasks were actually stalled on each resource, which distinguishes a
  storage stall from a CPU or memory stall even when utilisation looks low
- `pstree -ap` to show which service spawned the blocked process
- scheduled jobs (`systemctl list-timers`, `crontab -l`, `/etc/cron.*`)
- maintenance / package / backup processes **detected** from the process table

> Package managers (`dnf`, `yum`, `rpm`) are **detected, never invoked**. Running
> them during a stall could block on locks or the network and make the recorder
> part of the outage. Everything captured here is cheap `/proc` reads, bounded by
> a timeout and a per-snapshot PID cap.

When the incident recovers, `lib/analysis.sh` turns this evidence into an
`analysis.txt` that reasons like an incident investigator rather than asserting a
single cause. It deliberately separates what was **measured**, what is
**inferred**, and what is **proven**, and its confidence is a per-hypothesis
distribution that is **gated by missing evidence** — when the decisive kernel
signals (wait channel, blocked stack, PSI) were not captured, specific-cause
confidence is capped and the cap is stated explicitly. It never reaches 100%.
View it with:

```bash
server-forensics --last-analysis
```

The report contains, in order: **Observed facts** (measurements, no
interpretation) → **Inference** (reasoning from the facts) → **Evidence ledger**
(a ✓/✗ checklist for the leading cause, plus the confidence cap and its reason) →
**Confidence distribution** (every hypothesis, highest first) → **Proven /
Inferred / Unknown** → **Timeline** (reconstructed from the incident's samples) →
**Recurring patterns** (correlated across past incidents) → **Recommended next
investigation** → **Missing evidence** to capture next time.

Abridged example:

```text
LIKELY CAUSE: Filesystem wait (95%)
Mechanism:    blocked (uninterruptible) tasks (90%)

-- Observed facts (measured, no interpretation) --
  - Peak load: 41.2
  - CPU at peak load: 12.0% (window min 8%)
  - Peak IO wait: 27.0%
  - Peak D-state processes: 14
  - PSI io full avg10 (peak): 78.4
  - Wait channels: captured

Confidence distribution:
  Filesystem wait ...................  95%
  Blocked (uninterruptible) tasks ...  90%
  Maintenance interaction ...........  50%
  Disk / block layer ................  33%
  MariaDB bottleneck ................   3%
  Apache overload ...................   2%

Proven:
  - Uninterruptible (D-state) blocking occurred: 14 task(s) counted directly.
  - Not CPU-bound: CPU 12.0% at load 41.2 (measured).
  - Stall class was I/O: PSI io full avg10 78.4 (direct kernel measurement).
  - Blocked in kernel path: wait channel ext4_writepages (direct /proc read).
Inferred:
  - Filesystem wait is the most likely layer (95%), from the signals above.
Unknown:
  - (none)

Timeline:
  01:30:00  load=3.0  cpu=8.0%  iowait=4.0%  dstate=1   <- incident window begins
  01:30:30  load=22.0 cpu=11.0% iowait=24.0% dstate=9   <- load crosses threshold
  01:31:00  load=41.2 cpu=12.0% iowait=27.0% dstate=14  <- D-state climbing
  (recovery: load back below 10)

Recurring patterns (across recorded incidents):
  Apache idle .................. 8/8
  High D-state ................. 7/8
  IO wait > 20% ................ 6/8
  PSI io-full high ............. 6/8
```

When the decisive evidence is missing, the same report caps confidence and says
so, e.g. `=> confidence for Filesystem wait capped at 65% because wait channel,
kernel stack and PSI were not captured.`

Hypotheses it distinguishes: Filesystem wait, Disk / block layer, MariaDB
bottleneck, Apache overload, PHP overload, Memory exhaustion, Network / remote
FS, Maintenance interaction, Package manager, and Kernel lock contention — plus
the separate *mechanism* verdict "blocked (uninterruptible) tasks". When no
specific cause clears the noise floor it reports **Inconclusive** rather than
inventing one.

The classification is a **first pass** meant to point you at the right subsystem
immediately after an outage. Always confirm against the raw `snapshot-*.log` and
`dstate-*.log` before acting. The wait-channel → subsystem maps and the scoring
weights in `lib/analysis.sh` are easy to extend as you learn your server's real
channels.

## Configuration

Default config file:

```text
/etc/server-forensics/config.conf
```

Important defaults:

```bash
INTERVAL=60
LOAD_THRESHOLD=10
LSPHP_THRESHOLD=40
MEMORY_THRESHOLD_MB=500
ESTABLISHED_THRESHOLD=300
DSTATE_THRESHOLD=5
PANIC_COOLDOWN=300
KEEP_INCIDENTS=100
LOG_DIR=/var/log/server-forensics
```

Panic controls:

```bash
PANIC_SNAPSHOT_INTERVAL=10
PANIC_COMMAND_TIMEOUT=20
PANIC_OUTPUT_LINES=5000
ENABLE_DSTATE_FORENSICS=1
PANIC_CAPTURE_KERNEL_STACK=1
PANIC_DSTATE_MAX_PIDS=25
PANIC_CAPTURE_PSI=1
COLLECTOR_COMMAND_TIMEOUT=1
ENABLE_PLUGINS=1
PLUGIN_TIMEOUT=1
PLUGIN_DIRS=/opt/server-forensics/plugins/metrics:/etc/server-forensics/plugins/metrics
```

Tune thresholds from real `current.log` values on your server. Start
conservative, then adjust based on normal peak traffic.

## Metric Plugins

Optional lightweight collector plugins live in:

```text
/opt/server-forensics/plugins/metrics/
/etc/server-forensics/plugins/metrics/
```

Each plugin prints key-value pairs on one line. Plugins run in the normal
collector path, so they must be fast and must not call expensive diagnostics.

## Repository Layout

```text
server-forensics/
|-- README.md
|-- DESIGN.md
|-- CHANGELOG.md
|-- CONTRIBUTING.md
|-- SECURITY.md
|-- LICENSE
|-- config.conf
|-- install.sh
|-- uninstall.sh
|-- docs/
|   |-- architecture.md
|   |-- configuration.md
|   |-- installation.md
|   `-- troubleshooting.md
|-- tests/
|   |-- syntax.sh
|   |-- lint.sh
|   |-- format.sh
|   `-- systemd.sh
|-- scripts/
|   |-- collector.sh
|   |-- watcher.sh
|   |-- panic.sh
|   `-- rotate.sh
|-- lib/
|   |-- metrics.sh
|   |-- logging.sh
|   |-- incident.sh
|   |-- plugins.sh
|   `-- utils.sh
|-- plugins/
|   `-- metrics/
`-- systemd/
    |-- service
    `-- timer
```

## Development Checks

Run locally:

```bash
bash tests/syntax.sh
bash tests/lint.sh
bash tests/format.sh
bash tests/systemd.sh
```

GitHub Actions runs:

- ShellCheck
- `bash -n`
- `shfmt`
- systemd unit validation
- installer syntax checks

## Documentation

- [Design background](DESIGN.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Installation](docs/installation.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Uninstall

Preserve logs:

```bash
sudo bash uninstall.sh
```

Delete logs too:

```bash
sudo bash uninstall.sh --delete-logs
```

## Roadmap

Not planned for v1, but good future directions:

- Email notifications
- Slack, Discord, or webhook alerts
- Netdata integration
- Prometheus exporter
- Grafana annotations
- JSON output mode
- YAML configuration
- Plugin architecture
- Docker support
- Multi-server aggregation
- Optional Python rewrite for advanced analysis

## Author

Created and maintained by **Dr-Hack**.

Website: [https://hackology.co](https://hackology.co)

GitHub: [https://github.com/Dr-Hack](https://github.com/Dr-Hack)

## License

MIT License. See [LICENSE](LICENSE).
