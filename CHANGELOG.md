# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Fixed

- CPU busy percentage is now computed from the delta of `/proc/stat` between
  consecutive samples instead of a single lifetime-cumulative reading, which
  previously produced a near-constant value. The first sample after boot reports
  `NA` until a baseline exists.

### Changed

- MariaDB collection now records `Threads_running`, `Threads_connected`,
  `Questions`, `Uptime`, and `Slow_queries` from a single `extended-status`
  call, degrading to `NA` only when the server is unreachable.
- The watcher now collects samples in-process via `collect_metrics_line` rather
  than spawning `collector.sh --print`, removing a redundant subprocess and
  config reload per cycle.
- Panic snapshots run `lsof -nP` to avoid slow host and port name resolution
  under load.

## 0.1.0 - 2026-07-18

- Added lightweight forensic collector for cPanel-style Linux servers.
- Added threshold watcher and panic incident lifecycle.
- Added rich panic snapshots with graceful command skipping.
- Added incident summaries, cooldown handling, and rotation.
- Added systemd timer/service installation.
- Added GitHub-ready repository layout with docs and syntax test.
- Added ShellCheck, shfmt, Bash syntax, installer syntax, and systemd unit checks through GitHub Actions.
- Added safer uninstall markers and panic snapshot output caps for production deployment.
- Added CLI commands for version, health, doctor, and safe test panic mode.
- Added validated configuration and lightweight metric plugin support.
- Added contribution, security, issue, and pull request templates.
