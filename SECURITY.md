# Security policy

## Reporting a vulnerability in OpenScore

Please **do not** open a public issue for security problems in OpenScore itself (for example,
a report-template injection, or a way to make a scan touch out-of-scope hosts).
Use GitHub's **private vulnerability reporting** (Security tab → "Report a vulnerability").
We aim to acknowledge reports within 5 business days.

## Responsible use

OpenScore is an assessment tool for defenders, vulnerability management and authorized
penetration tests. It identifies and documents issues; it never exploits them. Passive and
light checks only use public data and normal browser-like requests. **Active checks must only be run against systems you own or have
written authorization to test.** The tool enforces an `--authorization` reference and an
interactive scope confirmation, and records every active action in an audit log — keep those
logs with the client's authorization.

Never commit scan output (`reports/`) or client suppression files; they contain client data.
