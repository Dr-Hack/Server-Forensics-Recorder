# Metric Plugins

Place lightweight metric plugins in this directory.

Each plugin must be a small shell script that prints one or more key-value
pairs on a single line:

```text
custom_metric=123 another_metric=ok
```

Plugins run during the lightweight collector path, so they must finish quickly
and must not call expensive commands such as `lsof`, `journalctl`, `iostat`, or
looping `vmstat`.
