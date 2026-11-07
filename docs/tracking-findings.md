# Tracking findings with Claude

The HTML report is a snapshot. To follow fixes over weeks (who owns what, what's done, what came
back), you can turn the JSON report into a shared tracker with Claude, and keep it up to date
after each rescan. OpenScore doesn't need a plugin or server for this: the JSON file is the
interface.

## Before you upload anything

**A report describes someone's attack surface.** It names hosts and IPs, and the evidence shows
what was exposed. Only upload it to an AI service your organization, or your client, allows for
this kind of data, under the account and data settings they expect. If in doubt, ask first.

You can leave the most sensitive parts out. The `evidence`, `proof` and `audit` fields are the
raw material; a tracker doesn't need them. With [jq](https://jqlang.org/):

```bash
jq '{domain, started, overall: .overall.grade, findings: [.findings[]
     | select(.severity != "pass" and .severity != "info" and (.suppression | not))
     | {key, severity, confidence, factor, title, asset, hosts, third_party, description, remediation, verify}]}' \
   reports/example.com-20261107-1728.json > tracker-input.json
```

Drop `asset`, `hosts` and `verify` too if hostnames mustn't leave your network; the `key` still
identifies each finding.

## What each finding carries

| Field | Meaning |
|---|---|
| `key` | Stable ID: the same check, asset and title give the same key in every scan. Use it to match findings between scans and to link tickets. |
| `check_id` | The check, as listed in the [check catalog](check-catalog.md). |
| `severity`, `confidence` | `critical` … `info`; `tentative` means it needs verifying (for example, a version-based CVE match). |
| `factor` | Which of the eight factors it scores under. |
| `title`, `asset`, `hosts` | What was found, where, and (for findings on an IP) the sites on that IP. |
| `description`, `remediation`, `verify` | Why it matters, how to fix it, and the command to confirm it by hand, with the host and URL filled in. |
| `third_party` | On a SaaS-hosted name: reported, not scored; usually the vendor's to fix. |
| `suppression` | Set when your suppressions file marks it as a false positive, accepted risk or compensating control. |

## Build the tracker

Attach `tracker-input.json` to a conversation with Claude and ask for what you need. For
example:

> Build a findings tracker from this OpenScore report as an interactive page I can share with my
> team. One row per finding, keyed on `key`. Columns: severity, title, asset, owner, status
> (Open / In progress / Fixed / Won't fix), due date, notes. Sort by severity, let me filter by
> factor and status, and show how to fix and verify each finding when I open a row.

Claude can build this as a page that you keep, edit and share like any other artifact. Ask for
the extra columns or views your process uses (for example, an SLA by severity, or a view per
owner).

## After each rescan

Run OpenScore again (the report's change summary already lists what's new and resolved), then
give Claude the new JSON:

> Here's the new scan. Update the tracker by `key`: add findings that are new, mark findings that
> no longer appear as "Fixed (not seen on <date>)", and keep owners, statuses and notes on
> everything else.

A finding that disappears from one scan isn't always fixed: the host may have been down or out
of scope that time. Check the report's Coverage gap boxes and the "Not a like-for-like
comparison" note before closing anything.

## Tickets

If your ticketing system (Jira, ServiceNow, GitHub Issues and so on) is connected to Claude, you
can ask it to open tickets from the tracker. Put the `key` in each ticket, so later scans update
the same ticket instead of opening a duplicate.

## Triage stays in OpenScore

The tracker is for people. OpenScore itself never reads it. When you decide a finding is a false
positive, an accepted risk or covered by a compensating control, also record it in the
suppressions file (see [Handling false positives](FALSE_POSITIVES.md)), so the score and the
next report reflect the decision.
