# Architecture

Server Forensics Recorder is designed as a low-overhead forensic black box.
Normal operation records only cheap metrics. Expensive diagnostics are captured
only after a threshold trips.

## Normal Path

The systemd timer runs once per minute and starts the watcher:

```text
systemd/timer
  -> systemd/service
  -> scripts/watcher.sh
  -> lib/metrics.sh
  -> current.log
```

`scripts/watcher.sh` collects one lightweight line, appends it to
`current.log`, evaluates thresholds, and exits if the server is healthy. The
watcher delegates the actual sample creation to `scripts/collector.sh --print`
so collection remains a separate component.

## Panic Path

When the watcher detects an unhealthy sample:

```text
scripts/watcher.sh
  -> scripts/panic.sh
  -> incident directory
  -> snapshot-N.log every PANIC_SNAPSHOT_INTERVAL seconds
```

Panic mode continues until a fresh lightweight sample is healthy again. It then
writes the final `summary.txt`, clears active incident state, and applies
rotation.

## Module Boundaries

- `scripts/collector.sh`: collect and append one lightweight sample.
- `scripts/watcher.sh`: collect, evaluate thresholds, and trigger panic mode.
- `scripts/panic.sh`: own incident snapshot loop and expensive diagnostics.
- `scripts/rotate.sh`: compress and prune old incidents.
- `lib/metrics.sh`: all metric collection and threshold evaluation.
- `lib/incident.sh`: incident state, summaries, peaks, and lifecycle.
- `lib/logging.sh`: console and file logging.
- `lib/plugins.sh`: optional lightweight collector plugin loader.
- `lib/utils.sh`: config loading and shared helpers.

## Metric Plugins

Metric plugins are optional shell scripts in `plugins/metrics/` or
`/etc/server-forensics/plugins/metrics/`. They run during the lightweight
collector path with `PLUGIN_TIMEOUT`, so they must emit quickly and avoid
expensive diagnostics.

Plugin output is appended to the normal key-value metric line:

```text
custom_metric=123 another_metric=ok
```

## Runtime State

Default runtime location:

```text
/var/log/server-forensics/
├── current.log
├── server-forensics.log
├── incidents/
├── archive/
└── .state/
```

Runtime logs are intentionally not part of the source repository.
