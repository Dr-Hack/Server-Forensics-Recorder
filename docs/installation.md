# Installation

Install as root from the repository root:

```bash
sudo bash install.sh
```

The installer copies source files to:

```text
/opt/server-forensics
```

Configuration is installed to:

```text
/etc/server-forensics/config.conf
```

Logs are written to:

```text
/var/log/server-forensics
```

## systemd

Installed units:

```text
/etc/systemd/system/server-forensics.service
/etc/systemd/system/server-forensics.timer
```

The timer runs the watcher once per minute:

```bash
systemctl status server-forensics.timer
systemctl list-timers server-forensics.timer
```

Manual watcher run:

```bash
sudo /opt/server-forensics/scripts/watcher.sh
```

Installed CLI:

```bash
server-forensics --version
server-forensics --health
server-forensics --health-json
sudo server-forensics --doctor
sudo server-forensics --test-panic
```

## Development Checks

Before opening a pull request, run:

```bash
bash tests/syntax.sh
bash tests/lint.sh
bash tests/format.sh
bash tests/systemd.sh
```

The GitHub Actions workflow runs the same checks automatically.

## Configuration

Edit:

```bash
sudo vi /etc/server-forensics/config.conf
```

Then either wait for the next timer run or run the watcher manually.

## Uninstall

Preserve logs:

```bash
sudo bash uninstall.sh
```

Delete logs:

```bash
sudo bash uninstall.sh --delete-logs
```

The uninstaller removes only directories created and marked by the installer:

- `/opt/server-forensics`
- `/etc/server-forensics`
- `/var/log/server-forensics` when `--delete-logs` is used

If a directory is missing, uninstall skips it. If a directory exists but does
not contain the expected project marker file, uninstall refuses to delete it.
