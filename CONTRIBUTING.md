# Contributing

Thanks for helping improve Server Forensics Recorder.

## Development Rules

- Keep normal collection lightweight.
- Do not add expensive commands to the collector path.
- Put shared logic in `lib/`.
- Put optional lightweight metric extensions in `plugins/metrics/`.
- Panic-only diagnostics belong in `scripts/panic.sh`.
- Keep scripts ShellCheck clean and formatted with `shfmt`.

## Checks

Run before opening a pull request:

```bash
bash tests/syntax.sh
bash tests/lint.sh
bash tests/format.sh
bash tests/systemd.sh
```

## Production Safety

Changes that affect deletion, installation paths, panic diagnostics, or
threshold evaluation should include a short safety note in the pull request.
