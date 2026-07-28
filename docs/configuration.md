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
KEEP_INCIDENTS=50
```

- `INTERVAL`: Expected timer cadence in seconds. Must be at least `10`.
- `LOG_DIR`: Absolute path for logs, incidents, archives, and state.
- `KEEP_INCIDENTS`: Number of uncompressed incidents to keep before rotation.
  This is the *shipped default for a fresh install only* — `install.sh` never
  overwrites an existing `/etc/server-forensics/config.conf`, so changing it here
  does not alter an already-installed host; edit that host's config directly.

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
PANIC_DSTATE_SAMPLES=6
PANIC_DSTATE_INTERVAL=0.5
PANIC_DSTATE_READ_TIMEOUT=2
PANIC_CAPTURE_PSI=1
```

Most incidents on the target server were driven by uninterruptible (D-state)
processes producing very high load with low CPU. During each panic snapshot the
recorder writes a `dstate-N.log` with the full `ps` wait-channel table, the
D-state processes alone, per-PID kernel stacks + current syscall, the process
tree, scheduled jobs, and any detected maintenance/package/backup activity. All
of it is cheap `/proc` reads; package managers are detected from the process
table, never run.

Blocked tasks are **transient** — they block and unblock every few milliseconds
during a stall, so a single `ps` usually catches none, which is why reports could
read *"Wait channels: unavailable"* even mid-stall. The capture therefore samples
the D-state set repeatedly and unions the PIDs, and the analysis renders a
**kernel wait-channel histogram** (what the tasks were blocked in, mapped to a
subsystem). On a uniformly slow disk there is no single stuck file; the wait
*path* is the actionable answer — `jbd2_log_wait_commit` → journal/fsync stall,
`wait_on_page_writeback` → dirty-page flushing, read/folio paths → reads.

- `ENABLE_DSTATE_FORENSICS`: Master switch for the D-state capture and the
  `analysis.txt` investigation engine.
- `PANIC_CAPTURE_KERNEL_STACK`: Read `/proc/<pid>/stack`, `wchan`, and `syscall`
  for blocked processes. Needs root; some hardened kernels restrict it, in which
  case the capture notes the value as unavailable and continues.
- `PANIC_DSTATE_MAX_PIDS`: Cap on how many D-state PIDs get a kernel-stack read
  per snapshot, so a storm of blocked tasks cannot make the recorder fan out.
- `PANIC_DSTATE_SAMPLES`, `PANIC_DSTATE_INTERVAL`: How many times, and how far
  apart, the D-state set is sampled to catch the transient blockers. Since 0.6.0
  this capture runs **first** in a panic snapshot, ahead of every collector with
  a sampling window or a full-`/proc` walk: it previously ran after ~29s of other
  diagnostics and caught nothing in 8 consecutive attempts, because blocked tasks
  clear in seconds. Note that even a zero-lag panic capture cannot outrun a
  sub-minute stall — the ring buffer's `kind=wchan` rows are the reliable source.
- `STALE_CAPTURE_SECONDS`: How long after the trigger a per-process capture may
  land and still be treated as evidence *of* that incident. Beyond this the
  offender tables are still printed, but specific-cause confidence is held at the
  inconclusive floor and the ledger states why. Guards against scoring an
  incident on something that happened long after the event that opened it.
- `PANIC_DSTATE_READ_TIMEOUT`: Per-PID timeout for each `/proc/<pid>/{syscall,stack}`
  read, so a deeply-blocked task can never stall the recorder.
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
RINGBUFFER_TOP_PHP=10
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

- `RINGBUFFER_TOP_PHP`: PHP endpoint rows kept per sample. Under Apache
  `mod_lsapi` a worker's argv is rewritten to `lsphp:<script path>` — the only
  place the served script is visible, since `pidstat` and `comm` both report a
  bare `lsphp`. The ring parses that into a stable endpoint key (the last two
  path components, so a front-truncated `…site.com/wp-admin/admin-post.php` still
  aggregates as `wp-admin/admin-post.php`) and ranks workers by endpoint. On a
  single-account host this is the actionable unit: "`lsphp` at 68000% CPU" tells
  you nothing, "`wp-admin/admin-ajax.php`, 15 workers" tells you the request.
- `RINGBUFFER_TOP_WCHAN`: Kernel wait-channel rows kept per sample. `wchan` is
  read as part of the `ps` the ring already runs, so continuous wait-channel
  capture costs **no additional process**. This matters because the panic-time
  sampler cannot win the race: load1 lags, the watcher runs every 60s, and panic
  mode starts after that, whereas the ring is already sampling on the way up.
  Rows are emitted only when something is actually blocked, so an idle server
  writes none. `kind=php` rows additionally carry `dstate` and `wchan`, which is
  what lets a report say which *request* was waiting in which kernel subsystem.

View it with `server-forensics --runup [ID]` for an incident, or
`server-forensics --ring [N]` for the live buffer. The busiest endpoint also
appears in the analysis Run-up section and Proven tier.

## Web Request Attribution

```bash
WEBLOG_DIRS=
WEBLOG_MAX_LINES=200000
WEBLOG_TOP_ROWS=20
WEBLOG_READ_TIMEOUT=5
WEBLOG_ABUSE_ENDPOINTS="xmlrpc.php wp-login.php admin-ajax.php admin-post.php wp-cron.php"
```

The endpoint names the script; the access log names the URL and the client IP.
At incident close the recorder reads a bounded tail of the domain access logs,
filters to the incident window, and writes `web.txt`: a per-vhost hit tally, a
**host + URI** table, top client IPs, abuse-endpoint tallies, and top user
agents. View it with `server-forensics --requests [ID]`, which regenerates on
demand so it also works mid-incident.

The **host + URI** table is the granular view: WordPress pretty permalinks route
every front-end request through `index.php`, so the per-endpoint view collapses
`/checkout`, `/product/…`, and search into one row — but the access log still
carries the real URI, so this table shows the actual pages per vhost, ranked by
request count. Per-URI CPU is not shown (mod_lsapi does not expose the request
URI to the process table, so it cannot be attributed); instead the table adds an
average-response-time column when the domlog `LogFormat` appends `%D` (request
microseconds), and otherwise prints a one-line hint on enabling it. To enable
timing, add `%D` to the end of the cPanel Apache `LogFormat` (a custom
`Include`), e.g. `... \"%{User-Agent}i\" %D`.

For `admin-ajax.php` / `admin-post.php` the report keeps the `action` parameter
(e.g. `admin-ajax.php?action=edd_download`) so the responsible plugin/feature is
named; ids and nonces are dropped to keep the table bounded. Only **GET** actions
reach the log — a POST action (WordPress `heartbeat`, most plugin AJAX) is in the
request body, which Apache does not record.

The `--io` capture also records the kernel ring buffer (`dmesg`, last
`PANIC_DMESG_LINES` lines, default 200) — OOM-killer kills, ext4/jbd2 journal
errors, and block/virtio timeouts during a stall — alongside `/proc/diskstats`,
`/proc/mounts`, `mount`, and `findmnt`.

The client-IP table labels the **server's own addresses** — discovered at
runtime from `hostname -I` / `ip addr`, never hardcoded — as loopback /
self-requests (`wp-cron`, cPanel health pings), so a self-request row is not read
as a client. The **per-vhost tally** attributes hits per domain, so on a
multi-site account the targeted site is explicit.

- `WEBLOG_DIRS`: Space-separated search path; empty uses the cPanel defaults
  (`/etc/apache2/logs/domlogs`, `/usr/local/apache/domlogs`,
  `/var/log/apache2/domlogs`, `/usr/local/lsws/logs`). Only the first existing
  directory is read.
- `WEBLOG_MAX_LINES`: Per-file tail cap. The incident has just closed, so the
  relevant lines are at the end of each active log; nothing is read in full.
- `WEBLOG_READ_TIMEOUT`: Seconds any single log read may take before it is
  abandoned — a log on a stalled mount must never hang the recorder.
- `WEBLOG_ABUSE_ENDPOINTS`: WordPress endpoints bots hammer, tallied separately
  so a flood stands out.

**Cloudflare-aware.** Behind Cloudflare every TCP peer — and the log's own
client-IP column, absent `mod_remoteip` — is a Cloudflare edge, not the attacker.
When the busiest client IPs are a known Cloudflare range the report says so and
points at the `CF-Connecting-IP` header and Cloudflare's own controls, rather
than fingering the CDN or suggesting a CSF ban that would only block Cloudflare's
edges. Restore the real client IP with `mod_remoteip` for per-IP attribution to
work directly.

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
