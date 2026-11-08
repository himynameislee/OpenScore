# Scoring methodology

Every point in an OpenScore grade can be traced to a finding. This page explains the arithmetic.
The source is `openscore/scoring.py`, and the report's Methodology section repeats the rules.

## The eight factors

| Factor | Weight | What it covers |
|---|---|---|
| Network Security | 1.0 | Risky services reachable from the internet (RDP, SMB, databases, remote admin) |
| Patching Cadence | 1.0 | End-of-life or outdated software and known-vulnerable versions (CISA KEV, EPSS) |
| Information Exposure | 1.0 | Leaked files, debug pages, version banners, breached accounts |
| IP & Domain Reputation | 0.9 | Blocklist listings, abuse reports, signs of compromised hosts |
| Application Security | 0.8 | HTTP security headers, cookie flags, HTTPS redirects, CORS |
| TLS / Certificates | 0.8 | Certificate validity, protocol versions, key strength |
| Email Security | 0.8 | SPF, DKIM, DMARC, MTA-STS |
| DNS Health | 0.6 | DNSSEC, CAA, nameserver resilience, zone transfers, subdomain takeover |

The weights favor what attackers use most to get in: exposed services, unpatched software and
leaked data.

## Factor scores

Each factor starts at **100**. Each finding deducts points by severity:

| Severity | Deduction |
|---|---|
| Critical | 35 |
| High | 18 |
| Medium | 8 |
| Low | 3 |
| Info, passed | 0 |

Three rules adjust the deductions:

1. **Repeats are dampened.** When the same issue (same check and title) appears on several hosts,
   the worst one counts in full, the next counts half, the next a quarter, and so on. One
   misconfiguration copied across 40 subdomains doesn't zero a factor, but breadth still costs
   something.
2. **Tentative findings count half.** Findings marked *needs verification* (version-based CVE
   matches, ports seen only by Shodan, unknown DKIM selectors) deduct half their usual points.
3. **Suppressed findings don't count:** findings you've triaged as a false positive, accepted risk
   or compensating control. Findings on vendor-hosted hosts (SaaS, CDN) do count, labeled with the
   vendor's name.

A factor can't go below 0.

**Example.** Missing HSTS (medium, 8 points) on five hosts deducts 8 + 4 + 2 + 1 + 0.5 = 15.5 points
from Application Security. If those findings were tentative, it would be 7.75.

## Overall score

The overall score is the **weighted average of the assessed factors**. A factor that couldn't be
assessed is shown as "not assessed" and left out of the average instead of counting as 100 or 0.
For example, without `--active` and without Shodan InternetDB data, Network Security has no data
and isn't assessed.

### The critical cap

**Any open, confirmed critical finding caps the overall score at 79 (grade C)**, however good the
rest is. One exposed database outweighs a lot of good headers.

A critical that still needs verification, typically a CVE matched only from a version number,
**doesn't cap the grade**. It still deducts its (halved) points, and the report summary says the
grade would be capped at C if the finding is confirmed. OpenScore never exploits a vulnerability to
confirm it, so version-based CVE findings stay tentative unless something else observes the same
issue directly.

### Grades

| Grade | Score |
|---|---|
| A | 90 and above |
| B | 80 to 89.9 |
| C | 70 to 79.9 |
| D | 60 to 69.9 |
| F | below 60 |

## Priority fixes

The report's **Priority fixes** table answers "what should we fix first?". For each issue (check
and title, the same grouping the score uses), OpenScore recalculates the overall score as if that
issue were fixed on every host where it appears, and ranks the issues by how many points that
gains. The top 12 are shown.

## testssl.sh results

In active mode testssl.sh adds a `TLS: <id>` finding per issue it reports, with a few adjustments
so one problem counts once:

- Rows the built-in TLS checks already cover (certificate expiry, trust, hostname, key size and
  signature, and the CAA record) are skipped. The module note counts them.
- OCSP stapling and wildcard-certificate notes are shown as info and don't affect the score.
- Rows testssl.sh itself calls "potentially vulnerable" (BREACH, LUCKY13 and the like) are marked
  tentative and count half.

A certificate that expires within 7 days is high severity, within 14 days medium, and within 30
days low.

## Versions that distributions patch in place

Enterprise Linux distributions often keep an old version number and backport security fixes. RHEL
8, for example, ships Apache 2.4.37 for its whole life. When OpenScore sees one of these frozen
versions, the evidence for end-of-life, outdated and CVE findings says so and shows the package
check to run (`rpm -q` or `dpkg -l`). This is context only: the severity and score don't change,
because an unpatched or end-of-life machine shows exactly the same version string. If a server
banner includes a distribution marker (`(Ubuntu)`, `el8`, `+deb11u3`…), version-based findings
are marked tentative.

## Comparing scores

- **Between scans of the same organization:** the report's *Change since last scan* section shows
  the score change and which findings are new or resolved. Compare scans run in the same mode;
  an active scan finds things a passive one can't.
- **Between organizations:** scores are comparable when the scans used the same mode and the same
  factors were assessed. A missing factor changes what the average is made of.
