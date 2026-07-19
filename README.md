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
# then drill into the captured diagnostics:
less /var/log/server-forensics/incidents/incident-*/snapshot-1.log
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
summary.txt
snapshot-1.log
snapshot-2.log
snapshot-3.log
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
