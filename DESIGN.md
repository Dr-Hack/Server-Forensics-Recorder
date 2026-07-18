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
