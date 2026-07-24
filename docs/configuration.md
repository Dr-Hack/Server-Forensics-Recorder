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
PANIC_CAPTURE_PSI=1
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
- `PANIC_CAPTURE_PSI`: Capture PSI (Pressure Stall Information) from
  `/proc/pressure/{io,cpu,memory}` during each panic snapshot, and track the peak
  io/cpu/memory pressure for the incident. On a PSI-capable kernel this is the
  single best signal for distinguishing a storage stall from a CPU or memory
  stall even when utilisation looks low. Three tiny `/proc` reads; skipped
  gracefully when the kernel lacks `CONFIG_PSI`.

On incident close, `lib/analysis.sh` correlates this evidence into
`analysis.txt` — observed facts, inference, an evidence ledger, a confidence
distribution gated by missing evidence, a proven/inferred/unknown split, a
reconstructed timeline, and recurring patterns across past incidents — viewable
with `server-forensics --last-analysis`.

## Per-Process I/O Attribution

```bash
ENABLE_IO_FORENSICS=1
PANIC_IO_SAMPLES=10
PANIC_IO_INTERVAL=1
PANIC_IO_OFFENDER_PCT=5
PANIC_IO_MIN_OFFENDERS=3
PANIC_IO_MAX_OFFENDERS=10
PANIC_IO_TABLE_ROWS=20
PANIC_IO_MAX_LINES=20000
PANIC_IO_MAX_TRACKED_PIDS=5000
PANIC_IO_LSOF_LINES=60
PANIC_IO_DETAIL_TIMEOUT=5
```

The metrics above establish *that* the server is under pressure. This
establishes **which process caused it** — the only question that follows, and
the one a list of installed services cannot answer.

Two rankings are produced per snapshot: `offenders-N.tsv` by disk read+write and
`cpuoffenders-N.tsv` by CPU. A spike is either compute-bound or blocked, so both
dimensions are needed for the culprit to be nameable in either case. Presence of
a process in the table is a measurement; presence of a process in `ps` is not,
and the analysis engine treats them very differently — see `docs/decisions.md`.

- `ENABLE_IO_FORENSICS`: Capture per-process I/O attribution during each panic
  snapshot into `io-N.log`, plus a machine-readable `offenders-N.tsv`. Requires
  `sysstat` for `pidstat` and `iostat`; run `--doctor` to confirm.
- `PANIC_IO_SAMPLES`, `PANIC_IO_INTERVAL`: The sampling window, as
  samples x seconds. `pidstat -d`, `pidstat -u` and `iostat -x` all sample over
  this window **concurrently**, so the wall-clock cost is one window, not three.
  Note that the panic loop period becomes
  `max(PANIC_SNAPSHOT_INTERVAL, PANIC_IO_SAMPLES * PANIC_IO_INTERVAL)`.
- `PANIC_IO_OFFENDER_PCT`: A process is treated as an offender, and gets a full
  detail block, when it accounts for more than this percentage of all observed
  disk I/O in the window.
- `PANIC_IO_MIN_OFFENDERS`, `PANIC_IO_MAX_OFFENDERS`: Always detail at least the
  top N processes so a diffuse incident still yields something, and never more
  than the maximum so a storm of writers cannot make the recorder fan out.
- `PANIC_IO_MAX_LINES`: Hard cap on lines retained from each sampler. On a box
  with thousands of processes the raw sampler output is unbounded, and the
  recorder must not be able to fill the disk it is already stalled on.
- `PANIC_IO_MAX_TRACKED_PIDS`: Upper bound on distinct PIDs the ranking keeps in
  memory, so a fork storm cannot grow the ranking arrays without limit.
- `PANIC_IO_LSOF_LINES`, `PANIC_IO_DETAIL_TIMEOUT`: Bounds on the per-offender
  reads. `lsof` is run with `-b -w` and under `timeout`, because a descriptor
  pointing at a stalled mount must never hang the recorder during the outage it
  is recording.

Each offender's block records PID, PPID, user, state, executable, command line,
elapsed time, working directory, wait channel, open files (both `lsof` and
`/proc/PID/fd`) and the cumulative `/proc/PID/io` byte counters — `read_bytes`
and `write_bytes` are the ones that actually reached the block layer, while
`rchar`/`wchar` include cache hits.

The incident's worst offender is retained as `peak_io_pid`, `peak_io_comm` and
`peak_io_kbs`, printed in `summary.txt`, and viewable with
`server-forensics --offenders`. The raw capture is `server-forensics --io`.

## Pre-Incident Process Ring Buffer

```bash
ENABLE_PROC_RING=1
RINGBUFFER_RETAIN_SECONDS=900
RINGBUFFER_LOOKBACK_SECONDS=300
RINGBUFFER_TOP_EXECS=15
RINGBUFFER_TOP_PIDS=10
RINGBUFFER_POLL=1
RINGBUFFER_POLL_INTERVAL=10
RINGBUFFER_FAST_INTERVAL=10
RINGBUFFER_FAST_LOAD=3
RINGBUFFER_POLL_WINDOW=45
```

Panic mode is triggered by `load1`, a one-minute average that **lags** the work
causing it. A burst shorter than the collector interval is therefore always
sampled on its way down, and the per-process tables describe the recovery rather
than the event. No trigger fixes this: if the first per-process measurement
happens after the trigger, the burst is already over. The ring samples
continuously so the analysis can look **backwards**.

- `ENABLE_PROC_RING`: Record a compact per-executable snapshot each cycle. The
  ring **never declares an incident** — enabling it cannot change when panic mode
  fires.
- `RINGBUFFER_RETAIN_SECONDS`, `RINGBUFFER_LOOKBACK_SECONDS`: History kept, and
  how far before an incident's start the analysis reads back. Measured footprint
  is ~2.5 KB per sample: about 37 KB of 15-minute history on an idle server and
  223 KB at the maximum sampling rate.
- `RINGBUFFER_POLL`, `RINGBUFFER_POLL_INTERVAL`, `RINGBUFFER_FAST_LOAD`: Between
  timer ticks the watcher polls `/proc/loadavg` — a single small read — every
  `POLL_INTERVAL` seconds, and takes a full `ps` sample only while load1 exceeds
  `FAST_LOAD`. Steady-state cost on an idle server is one `ps` per minute.
  `FAST_LOAD` is deliberately far below `LOAD_THRESHOLD`: the point is to already
  be sampling quickly by the time the panic threshold is crossed.
- `RINGBUFFER_POLL_WINDOW`: How long the watcher keeps polling after a healthy
  cycle. Validated to be less than `INTERVAL` so the next timer tick is never
  delayed.

The systemd timer uses `OnUnitActiveSec=60` rather than `OnUnitInactiveSec=60`,
because the latter counts from when the service *finishes* and would stretch the
metric cadence to poll-window + 60s.

View it with `server-forensics --runup [ID]` for an incident, or
`server-forensics --ring [N]` for the live buffer.

## Distributed-Load Notice

```bash
AGG_DISTRIBUTED_CPU_PCT=90
AGG_DISTRIBUTED_TOP_PCT=15
```

When the machine is busier than `AGG_DISTRIBUTED_CPU_PCT` but no single process
reaches `AGG_DISTRIBUTED_TOP_PCT`, the report states that usage is spread across
processes and points at the aggregated executable totals. Without it, a
worker-pool spike — 93% CPU with a 9% top process — reads as though nothing was
using the CPU.

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
