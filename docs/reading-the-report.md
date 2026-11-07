# Reading the report

The HTML report is a single file with everything embedded: no outside fonts, scripts or images,
so it opens offline and can be emailed as-is. **Print → Save as PDF** produces a clean PDF, and the
toggle in the header switches between light and dark.

The sections appear in this order.

## Header and summary

- **Grade and score**, the client name, the domain, when the scan ran (UTC), the mode and, for an
  active scan, the authorization reference.
- **A one-sentence summary** with the number of issues by severity. If a tentative critical is
  holding back the critical cap, the summary says the grade would be capped at C if it's confirmed
  (see [Scoring](scoring.md#the-critical-cap)).
- **Coverage gap boxes**, when part of the scan couldn't do its job. Read these first. A report
  built on missing data can look cleaner than the organization really is, so these are called out
  here, not only in the Module notes at the bottom:
  - a data source failed (most often certificate transparency, crt.sh, which means discovery found
    fewer hosts than it should have),
  - a data source hit its rate limit (GreyNoise, AbuseIPDB), so later IPs have no data from it,
  - testssl.sh didn't complete on any host, so TLS results come from the built-in checks only,
  - nuclei failed or was stopped before finishing (time limit or Ctrl+C).
- **Severity counts** and the number of passed checks.

## Change since last scan

When there's an earlier scan of the same domain in the output folder (or you pass `--baseline`),
this shows the previous date, score and grade, the change in points, and lists of **new** and
**resolved** findings. A finding is matched across scans by its check, host and title. Suppressed,
informational and third-party (SaaS) findings are left out of the comparison, since none of them
affects the score. A line under the heading names the previous report file, when it ran, its mode
and how many assets it covered. If the mode differs or the asset count differs by more than a
quarter, a note says the comparison isn't like-for-like.

Compare like with like: an active scan finds things a passive scan can't, so a passive scan
following an active one shows "resolved" findings that simply weren't looked for. Use
`--no-baseline` to skip the comparison. When no earlier scan is found, the section is missing and
the module notes at the end of the report say which folder was searched.

## Factor scores

One card per factor: the grade and score, the number of issues and a one-line description.
"Not assessed" means OpenScore had no data for that factor in this scan (for example, Network
Security without `--active` or Shodan data). Unassessed factors are left out of the overall score.

## Priority fixes

The checks whose fix would gain the most points, with the affected hosts. This is the list to
hand someone who asks "where do we start?". See [Scoring](scoring.md#priority-fixes) for how the
gain is calculated.

## Findings and remediation

Findings are grouped by factor, then by issue. Critical and high issues are expanded by default.
Each issue shows:

- **Severity**, the title, how many hosts are affected, and a **needs verification** tag when the
  finding is tentative.
- **Why it matters:** what an attacker could do with it.
- **For each affected host:** the host, where the finding came from (`http`, `nmap`, `shodan`,
  `nuclei`…), the **triage buttons**, and the **evidence exhibit**. Findings from IP-based sources
  (Shodan, nmap, CVE matches) name an IP; the report lists the organization's sites on that IP next
  to it, and the JSON carries them as `hosts` on the finding.
- **How to verify:** a command you can run yourself, already filled in with the host or URL.
- **How to fix:** remediation steps, with Microsoft 365, Exchange Online and Entra specifics where
  they apply, plus reference links.

### Evidence exhibits

Every finding carries the raw data that triggered it, laid out like an exhibit in a penetration
test report, with the offending line highlighted and annotated:

| Finding type | The exhibit shows |
|---|---|
| Headers, cookies, CORS, redirects | The HTTP response headers. Missing headers appear as red `(not present)` lines. |
| TLS | Certificate and handshake details (subject, SANs, issuer, validity, key, signature, protocols, ciphers) with the failing field highlighted |
| SPF, DMARC, DKIM, DNS | The DNS answer with the problem marked. SPF lookup-limit findings show the full lookup tree. |
| Open ports | nmap or TCP connect output, or the Shodan data plus the live re-test result |
| Exposed files | The control request to a random path (proving the site doesn't answer every URL the same way), then the real response with the matching line. Secret values are masked. |
| End-of-life software, CVEs | The version banner next to the vendor lifecycle data, and CVEs with their KEV and EPSS status |
| Reputation | The blocklist or API answer |

Exhibits are also exported as PNG files in `<report>-evidence/`, stamped with severity, finding,
host, time and OpenScore version, ready to paste into a ticket. The number of PNGs per scan is
capped by `--max-proof-images` (default 250); the HTML report always has every exhibit.

**Page screenshots** appear where seeing the page is the proof: VPN and appliance portals, admin
panels, status and debug pages, directory listings, management interfaces, and each host's
homepage in the asset inventory. They're capped by `--max-screenshots` (default 60) and are taken
only of in-scope pages.

### Triage buttons

**False positive**, **Accept risk** and **Compensating control** copy a ready-made suppressions
entry for that finding to your clipboard. See [Handling false positives](FALSE_POSITIVES.md) for the
workflow.

## Third-party hosted

Findings on hosts served by a SaaS provider: Microsoft 365 autodiscover, a marketing platform's
landing pages, an identity provider's login page on your domain. The provider controls those
settings, so these findings are listed for information and **excluded from the score**. See
[Hosting classification](hosting-classification.md).

## Suppressed findings

Findings matched by your suppressions file, with their status, reason, approver, compensating
control and expiry date. Two lists may follow:

- **Expired suppressions:** entries past their review date. Those findings are counted again.
- **Suppressions that matched nothing:** probably fixed. Remove them to keep the file clean.

## Passed checks

What OpenScore checked and found in order. This is useful evidence too: it shows a control was
tested, not just that nothing was reported.

## Asset inventory

Every host and IP that was assessed: CNAME chain, IP addresses, hosting provider (ASN), hosting
class, what the web server returned, and a homepage thumbnail.

**Check this list.** Attributing infrastructure to an organization from the outside is
error-prone: old IPs, shared hosting and vendor systems all show up under a company's domain. Anything
that isn't the organization's should be excluded (`--exclude`) or triaged. Before an active scan,
this list is also how you confirm the scope (see [Modes and scope](modes-and-scope.md#check-the-scope-before-an-active-scan)).

## Methodology

The mode and what it means, which factors were assessed, the scoring rules, and two things worth
reading when something looks off:

- **Module notes:** for each module, how long it took and anything that limited it: tools not
  installed, data sources that failed, nuclei or testssl.sh stopped early (by time limit or
  Ctrl+C) and which hosts were skipped, IPs skipped from the port scan because they belong to a
  CDN or SaaS provider, Shodan ports that couldn't be confirmed live, whether TLS inspection was
  detected on your network.
- **Audit log:** the same entries as the `.audit.log` file.

## The JSON file

`<domain>-<time>.json` holds everything in the report as data: overall and factor scores,
priority fixes, every finding (check, factor, severity, host, title, evidence, source,
confidence, suppression), the asset inventory, software versions seen, CVEs per host, module notes
and the audit log. It's the baseline for the next scan's comparison, and the input for anything
you want to build on top of OpenScore.
