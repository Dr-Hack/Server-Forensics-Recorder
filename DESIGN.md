# Background

This project exists because a production cPanel server experienced
intermittent outages that were difficult to diagnose.

Previous investigations showed:

- CPU was usually not saturated.
- MariaDB appeared healthy.
- Apache remained responsive.
- Multiple lsphp workers accumulated.
- Evidence disappeared before administrators could investigate.

Netdata has already been deployed successfully.

This project DOES NOT replace Netdata.

Its purpose is forensic evidence collection.

The design philosophy is:

Monitoring tells us THAT a problem happened.

Server Forensics tells us WHY it happened.

Target stack:

- AlmaLinux 8
- cPanel
- Apache
- CloudLinux
- mod_lsapi
- lsphp
- MariaDB
- Exim
- Cloudflare

Primary goals:

- Tiny overhead
- Production safe
- Modular
- Easy installation
- GitHub quality

# Architecture

The timer starts `server-forensics.service` once per minute. The service invokes
`scripts/watcher.sh`. The watcher delegates the lightweight sample to
`scripts/collector.sh --print`, evaluates configured thresholds, appends the
sample, and exits when the server is healthy.

If a threshold is exceeded, the watcher invokes `scripts/panic.sh`. Panic mode
creates one incident directory for the outage and keeps adding snapshots to that
same directory until lightweight metrics recover.

# Incident Lifecycle

```text
healthy sample
  -> no action

unhealthy sample
  -> create incident
  -> capture panic snapshots
  -> keep capturing while unhealthy
  -> close incident after recovery
  -> cooldown before allowing a new incident
```

# Plugin Model

Optional metric plugins live under `plugins/metrics/` or
`/etc/server-forensics/plugins/metrics/`. They are for lightweight metrics only.
Expensive diagnostics belong exclusively in panic mode.
