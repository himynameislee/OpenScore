# OpenScore documentation

OpenScore looks at an organization from the outside, the way an attacker would, grades it A–F
across eight factors, and explains every finding: the evidence that triggered it, a command to
verify it by hand, and how to fix it.

The [project README](../README.md) is the short version. These pages are the long one.

## Using OpenScore

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | Installing on Linux and Windows, the standalone binaries, your first scan, where the output goes |
| [Modes, scope and authorization](modes-and-scope.md) | Passive, light and active: what each one touches, what counts as in scope, the authorization gate and the audit log |
| [Reading the report](reading-the-report.md) | Every section of the HTML report, evidence exhibits, Coverage gap boxes, Module notes, the scan-to-scan diff |
| [Scoring methodology](scoring.md) | How the score and grade are calculated, with worked examples |
| [Handling false positives](FALSE_POSITIVES.md) | How OpenScore avoids them, the triage workflow and the suppressions file |
| [Hosting classification](hosting-classification.md) | How hosts are classified as owned, cloud, CDN or SaaS, and why that decides both scoring and scope |
| [Data sources and network use](data-sources.md) | Every outside service OpenScore contacts, and the optional API keys |
| [Troubleshooting](troubleshooting.md) | Common problems and what to do about them |
| [Practice targets](practice-targets.md) | Where to try OpenScore safely without scanning someone who hasn't agreed to it |

## Coming before 1.0

- **Command reference:** every option, generated from the program itself so it can't drift.
- **Check catalog:** every check with its factor, severity, trigger, verify command and fix,
  generated from the knowledge base.
- **Performance tuning:** nuclei and testssl.sh speed, timeouts and what to expect on large estates.
- **Tracking findings with Claude:** building a shared tracker from the JSON report.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the development setup and how to add a check, and
[SECURITY.md](../SECURITY.md) for reporting a vulnerability in OpenScore itself.
