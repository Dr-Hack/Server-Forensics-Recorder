# Server Forensics Recorder

Server Forensics Recorder is a lightweight Linux flight recorder for intermittent server outages. It is designed for cPanel, CloudLinux, Apache, `mod_lsapi`, `lsphp`, MariaDB, Exim, and WordPress workloads, but the core collector stays generic enough for most production Linux web servers.

This is not a monitoring replacement. Monitoring tells you something went wrong. This tool preserves the evidence that explains why it went wrong before the evidence disappears.

## Repository Layout

```text
server-forensics/
├── README.md
├── DESIGN.md
├── CHANGELOG.md
├── LICENSE
├── config.conf
├── install.sh
├── uninstall.sh
├── docs/
│   ├── architecture.md
│   ├── installation.md
│   └── troubleshooting.md
├── tests/
│   └── syntax.sh
├── scripts/
│   ├── collector.sh
│   ├── watcher.sh
│   ├── panic.sh
│   └── rotate.sh
├── lib/
│   ├── metrics.sh
│   ├── logging.sh
│   ├── incident.sh
│   └── utils.sh
└── systemd/
    ├── service
    └── timer
```

## Architecture

Normal operation is intentionally cheap:

1. `server-forensics.timer` starts `server-forensics.service` once per minute.
2. `scripts/watcher.sh` records one lightweight metric line in `current.log`.
3. The watcher compares that line with configured thresholds.
4. If healthy, it exits.
5. If unhealthy, `scripts/panic.sh` creates or continues an incident and captures richer diagnostics every 10 seconds until recovery.
6. `scripts/rotate.sh` compresses and removes old incidents beyond the retention limit.

The normal collector reads mostly from `/proc` and uses short timeouts around optional commands. Expensive tools such as `lsof`, `journalctl`, `top`, `vmstat`, `iostat`, and full process listings are used only in panic mode.

## Requirements

Required:

- Linux
- Bash
- systemd for timer-based installation
- Standard tools such as `awk`, `sed`, `ps`, `date`, `find`, and `sort`

Optional diagnostics:

- `mysqladmin`
- `exim`
- `ss`
- `lsof`
- `vmstat`
- `iostat`
- `journalctl`
- `apachectl`
- `tar`

Missing optional commands are skipped gracefully.

## Installation

Run from the project directory as root:

```bash
sudo bash install.sh
```

The installer:

- Copies scripts to `/opt/server-forensics`
- Installs configuration at `/etc/server-forensics/config.conf`
- Creates `/var/log/server-forensics`
- Installs and enables the systemd timer
- Starts the timer
- Verifies the installed files

Check the timer:

```bash
systemctl list-timers server-forensics.timer
systemctl status server-forensics.timer
```

Run manually:

```bash
sudo /opt/server-forensics/scripts/watcher.sh
```

## Uninstall

Preserve logs:

```bash
sudo bash uninstall.sh
```

Delete logs too:

```bash
sudo bash uninstall.sh --delete-logs
```

## Configuration

Edit:

```bash
/etc/server-forensics/config.conf
```

Default values:

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

Additional panic controls:

```bash
PANIC_SNAPSHOT_INTERVAL=10
PANIC_COMMAND_TIMEOUT=20
```

## Lightweight Metrics

Each normal sample is appended to:

```bash
/var/log/server-forensics/current.log
```

Example line:

```text
timestamp=2026-07-18T17:30:25+0500 epoch=1784381425 uptime_seconds=90125 load1=12.33 load5=8.44 load15=6.10 cpu_busy_pct=22.8 mem_total_mb=32000 mem_available_mb=420 swap_total_mb=4095 swap_free_mb=3800 apache_workers=87 lsphp_count=51 lsphp_avg_age=42 lsphp_oldest_age=300 mariadb_running=1 threads_running=3 threads_connected=44 exim_queue=12 tcp_established=344 tcp_time_wait=91 tcp_close_wait=3 tcp_syn_recv=0 dstate_processes=1
```

Collected metrics include:

- Timestamp and uptime
- Load average
- CPU busy percentage since boot
- Memory and swap
- Apache worker count
- `lsphp` process count and age
- MariaDB process presence
- MariaDB thread counts when `mysqladmin` is available
- Exim queue size when `exim` is available
- TCP state summary from `/proc/net/tcp*`
- Processes in uninterruptible `D` state

## Incident Lifecycle

An incident starts when any threshold is crossed:

- Load average above `LOAD_THRESHOLD`
- `lsphp` count above `LSPHP_THRESHOLD`
- Available memory below `MEMORY_THRESHOLD_MB`
- Established TCP connections above `ESTABLISHED_THRESHOLD`
- D-state process count above `DSTATE_THRESHOLD`

Example flow:

```text
Load rises
  -> watcher detects unhealthy sample
  -> incident directory is created
  -> panic snapshots are captured every 10 seconds
  -> lightweight metrics continue to be appended
  -> server becomes healthy
  -> incident summary is finalized
```

Panic mode never creates duplicate incidents while one is active. After recovery, `PANIC_COOLDOWN` prevents immediate re-entry during short flapping periods.

## Example Incident

Incident directory:

```text
/var/log/server-forensics/incidents/incident-20260718-173025/
```

Files:

```text
summary.txt
snapshot-1.log
snapshot-2.log
snapshot-3.log
```

Summary example:

```text
Incident ID: incident-20260718-173025
Started: 2026-07-18T17:30:25+0500
Ended: 2026-07-18T17:33:05+0500
Duration: 160 seconds
Peak Load: 18.42
Peak lsphp: 76
Lowest Available Memory: 214 MB
Peak Connections: 512 established
Reason Triggered: load1=12.33>10,lsphp=51>40
Snapshots Taken: 16
```

Each snapshot includes:

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

## Example Screenshots

This project is terminal-first, so screenshots are usually captures of incident folders and summaries:

```text
$ ls -lah /var/log/server-forensics/incidents/incident-20260718-173025/
summary.txt
snapshot-1.log
snapshot-2.log
snapshot-3.log
```

```text
$ sed -n '1,20p' /var/log/server-forensics/incidents/incident-20260718-173025/summary.txt
Incident ID: incident-20260718-173025
Started: 2026-07-18T17:30:25+0500
Ended: 2026-07-18T17:33:05+0500
Duration: 160 seconds
...
```

## Tuning Thresholds

Start conservative and adjust from real `current.log` data:

- `LOAD_THRESHOLD`: Set above normal peak load. On busy shared hosting servers, this may be higher than CPU core count because short queue spikes are common.
- `LSPHP_THRESHOLD`: Tune from normal `lsphp_count` during traffic peaks. WordPress floods often show up here first.
- `MEMORY_THRESHOLD_MB`: Set to the point where the server is close to swap pressure or OOM behavior.
- `ESTABLISHED_THRESHOLD`: Tune from normal Cloudflare-proxied traffic. Use this to catch connection pileups.
- `DSTATE_THRESHOLD`: Keep low. D-state processes often indicate storage or kernel-level stalls.
- `PANIC_COMMAND_TIMEOUT`: Lower this if snapshots are too heavy during outages.

## Troubleshooting

No logs are appearing:

```bash
systemctl status server-forensics.timer
systemctl status server-forensics.service
journalctl -u server-forensics.service --no-pager
```

Permission errors:

- Run the installer as root.
- Panic diagnostics such as `lsof`, `dmesg`, and `journalctl` may require root.

MariaDB fields show `NA`:

- `mysqladmin` may not be installed.
- The root account may require a defaults file or socket authentication.
- This does not stop the recorder.

No `iostat` output:

- Install `sysstat` if you want disk device diagnostics in panic snapshots.

`apachectl status` fails:

- Apache status depends on local server-status configuration.
- Failure is recorded but ignored.

## Coding Standards

The project is written as small Bash modules:

- `lib/utils.sh`
- `lib/logging.sh`
- `lib/metrics.sh`
- `lib/incident.sh`

Scripts use:

- `set -Eeuo pipefail`
- Defensive command checks
- Short timeouts around optional commands
- Simple key-value log output
- Graceful degradation when commands are missing
- Functions instead of monolithic script bodies

Run checks:

```bash
bash tests/syntax.sh
bash tests/lint.sh
bash tests/format.sh
bash tests/systemd.sh
```

GitHub Actions runs these checks automatically on pushes and pull requests:

- ShellCheck linting
- `bash -n` syntax checks
- `shfmt` formatting verification
- systemd unit validation
- explicit installer syntax checks

## Roadmap

Not planned for v1:

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

## License

MIT License. See `LICENSE`.
