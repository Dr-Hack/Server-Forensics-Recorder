# Security Policy

## Supported Versions

Security fixes target the latest `main` branch until formal releases begin.

## Reporting a Vulnerability

Please report security issues privately through:

- Website: https://hackology.co
- GitHub: https://github.com/Dr-Hack

Do not open a public issue for vulnerabilities involving unsafe deletion,
privilege escalation, sensitive log exposure, or command injection.

## Security Expectations

- The collector must not run expensive or risky commands.
- Panic diagnostics must gracefully skip missing commands.
- Uninstall must not delete unmarked directories.
- Configuration must be validated before runtime actions.
- Shell scripts must avoid untrusted command construction.
