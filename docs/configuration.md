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

## Collector Controls

```bash
COLLECTOR_COMMAND_TIMEOUT=1
```

This caps optional collector commands such as `mysqladmin` and `exim`. Keep this
low so normal collection stays lightweight.

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
