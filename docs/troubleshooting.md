# Troubleshooting

## No Logs Are Appearing

Check the timer and service:

```bash
systemctl status server-forensics.timer
systemctl status server-forensics.service
journalctl -u server-forensics.service --no-pager
```

Run the watcher manually:

```bash
sudo /opt/server-forensics/scripts/watcher.sh
```

## MariaDB Values Show NA

`mysqladmin` is optional. `NA` usually means one of these is true:

- `mysqladmin` is not installed.
- The MariaDB user requires credentials.
- Socket authentication is not available to the running user.

The recorder continues without MariaDB thread details.

## Missing Panic Diagnostics

Panic mode skips missing commands gracefully. Install optional packages only when
you want that diagnostic source.

Common examples:

- `sysstat` for `iostat`
- `lsof` for open file diagnostics
- `iproute` for `ss`

## Apache Status Fails

`apachectl status` depends on the local Apache status configuration. Failure is
recorded in the snapshot and does not stop the incident.

## Too Many Incidents

Increase thresholds or cooldown in:

```bash
/etc/server-forensics/config.conf
```

Useful settings:

```bash
LOAD_THRESHOLD=10
LSPHP_THRESHOLD=40
MEMORY_THRESHOLD_MB=500
ESTABLISHED_THRESHOLD=300
DSTATE_THRESHOLD=5
PANIC_COOLDOWN=300
```
