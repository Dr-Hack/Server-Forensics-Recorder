# Configuration

Installed configuration:

```text
/etc/server-forensics/config.conf
```

The file uses simple shell syntax. Keep values unquoted unless a path contains
spaces.

## Core Runtime

```bash
INTERVAL=60
LOG_DIR=/var/log/server-forensics
KEEP_INCIDENTS=100
```

- `INTERVAL`: Expected timer cadence in seconds. Must be at least `10`.
- `LOG_DIR`: Absolute path for logs, incidents, archives, and state.
- `KEEP_INCIDENTS`: Number of uncompressed incidents to keep before rotation.

## Thresholds

```bash
LOAD_THRESHOLD=10
LSPHP_THRESHOLD=40
MEMORY_THRESHOLD_MB=500
ESTABLISHED_THRESHOLD=300
DSTATE_THRESHOLD=5
```

Panic mode starts when any threshold is crossed.

## Panic Controls

```bash
PANIC_COOLDOWN=300
PANIC_SNAPSHOT_INTERVAL=10
PANIC_COMMAND_TIMEOUT=20
PANIC_OUTPUT_LINES=5000
```

- `PANIC_COOLDOWN`: Minimum seconds after recovery before a new incident starts.
- `PANIC_SNAPSHOT_INTERVAL`: Delay between panic snapshots.
- `PANIC_COMMAND_TIMEOUT`: Timeout for each panic diagnostic command.
- `PANIC_OUTPUT_LINES`: Maximum lines captured from each diagnostic command.

## D-state / Blocking Forensics

```bash
ENABLE_DSTATE_FORENSICS=1
PANIC_CAPTURE_KERNEL_STACK=1
PANIC_DSTATE_MAX_PIDS=25
```

Most incidents on the target server were driven by uninterruptible (D-state)
processes producing very high load with low CPU. During each panic snapshot the
recorder writes a `dstate-N.log` with the full `ps` wait-channel table, the
D-state processes alone, per-PID kernel stacks, the process tree, scheduled
jobs, and any detected maintenance/package/backup activity. All of it is cheap
`/proc` reads; package managers are detected from the process table, never run.

- `ENABLE_DSTATE_FORENSICS`: Master switch for the D-state capture and the
  `analysis.txt` investigation engine.
- `PANIC_CAPTURE_KERNEL_STACK`: Read `/proc/<pid>/stack` and `wchan` for blocked
  processes. Needs root; some hardened kernels restrict it, in which case the
  capture notes the value as unavailable and continues.
- `PANIC_DSTATE_MAX_PIDS`: Cap on how many D-state PIDs get a kernel-stack read
  per snapshot, so a storm of blocked tasks cannot make the recorder fan out.

On incident close, `lib/analysis.sh` correlates this evidence into
`analysis.txt` — most likely subsystem, confidence, evidence, and next steps —
viewable with `server-forensics --last-analysis`.

## Collector Controls

```bash
COLLECTOR_COMMAND_TIMEOUT=1
MYSQL_DEFAULTS_FILE=
```

- `COLLECTOR_COMMAND_TIMEOUT`: Caps optional collector commands such as
  `mysqladmin` and `exim`. Keep this low so normal collection stays lightweight.
- `MYSQL_DEFAULTS_FILE`: Optional absolute path to a MySQL/MariaDB credentials
  file, passed to `mysqladmin` as `--defaults-extra-file`. Leave empty to rely on
  the client's normal lookup. On cPanel, root's credentials live in
  `/root/.my.cnf`; the systemd unit exports `HOME=/root` so that file is found
  automatically, so this is only needed for non-standard credential locations
  (for example, a dedicated read-only monitoring account).

## Plugins

```bash
ENABLE_PLUGINS=1
PLUGIN_TIMEOUT=1
PLUGIN_DIRS=/opt/server-forensics/plugins/metrics:/etc/server-forensics/plugins/metrics
```

Plugins are optional lightweight metric collectors. Each plugin must print
key-value pairs on one line and finish within `PLUGIN_TIMEOUT`.

Do not put expensive diagnostics in plugins.

## Validation

Configuration is validated on startup. Invalid numeric values, unsafe paths, and
relative plugin directories are rejected before runtime actions occur.
