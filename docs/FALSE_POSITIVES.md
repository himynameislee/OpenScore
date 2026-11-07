# Handling false positives

External scanners all see your client from the outside, so some
findings will be wrong or irrelevant. OpenScore is built to make those easy to spot, prove, and
record.

## 1. How OpenScore reduces false positives automatically

| Source of false positives | What OpenScore does |
|---|---|
| DNS resolver timeouts reported as "missing SPF/DMARC" | Distinguishes NXDOMAIN/NOANSWER from network errors; errors never become findings. A circuit breaker stops the DNS module if the resolver is unreachable. |
| Soft-404 pages ("200 OK" for every URL) | Requests a random path first; exposure findings require a **content signature** (e.g. `ref: refs/` for `.git/HEAD`), not just HTTP 200. |
| Stale internet-scan data (Shodan) | Ports seen only by Shodan are **tentative**. In active mode each one is re-tested live: confirmed → firm, unreachable → kept tentative with a "likely stale" note. |
| Distro backports (Ubuntu/RHEL patch old version numbers) | Banners with a distro marker (`(Ubuntu)`, `el8`, `+deb11u3`…) mark EOL/outdated findings **tentative** with a backport warning. |
| Version-based CVE matching | Always **tentative**, counted at half weight; KEV/EPSS used to prioritize. |
| Third-party SaaS (M365 autodiscover, HubSpot, Shopify…) | Detected by CNAME/ASN, excluded from score, listed separately for dispute. |
| CDN/shared IPs (Cloudflare, Akamai) | Never port-scanned or reputation-scored as the client's own. |
| Unknown DKIM selectors | DKIM-not-found is **tentative** and low severity; add `--dkim-selectors`. |

Tentative findings show a **needs verification** badge in the report and count half towards the score.

## 2. Triage workflow

1. Open the report and start with critical/high findings.
2. Expand a finding — each has a **How to verify** box with the exact manual command
   (`curl`, `dig`, `nmap`, `openssl`) pre-filled with the affected host/URL.
   Findings with a URL also carry a **screenshot** stamped with URL, status and time —
   often enough on its own to confirm a finding (or show it's a WAF block page / soft-404).
3. Run it. Decide: **real**, **false positive**, **accepted risk**, or **compensating control**.
4. For anything not real (or not being fixed), click the matching **Triage** button on the
   finding: **False positive**, **Accept risk** or **Compensating control**. Each copies a
   suppressions entry with that status to your clipboard.
5. Paste into `suppressions/<domain>.toml`, fill in `reason` and `approved_by` (for a
   compensating control, also `control`: what mitigates it), check the pre-filled `expires`
   review date (6 months for accepted risks, 12 for compensating controls), and re-run the scan.

Suppressed findings:

- drop out of the score,
- stay visible in a **Suppressed findings** section with the reason, approver and expiry,
- **come back automatically when they expire**, and
- suppressions that no longer match anything are flagged so the file stays clean.

## 3. Measuring accuracy

- **Lab ground truth:** `tests/fake_target.py` plants known issues. CI scans it on Linux and
  Windows and fails if expected findings disappear (regression = missed true positive).
- **Against other scanners:** for each client, list findings other tools
  report that OpenScore missed (false negatives), and OpenScore findings you suppressed as
  false positives. Open an issue with the *False positive / missed finding* template — every
  report improves a check for everyone.
- **Precision per check:** the suppressions files across your clients are a dataset. A check
  that's frequently marked `false_positive` needs tightening.

## 4. Common false positives and what to do

| Finding | Typical cause | Action |
|---|---|---|
| End-of-life Apache/PHP/OpenSSL on Linux | Distro backports | Verify with distro security tracker → `false_positive` |
| TLS certificate untrusted | Your own network's TLS-inspection proxy | Re-scan from another network |
| SMB/RDP/port open (Shodan only) | IP reassigned / port since closed | Run with `--active` to live-confirm |
| Cookie without HttpOnly | CSRF token cookie that JS must read | `false_positive` with reason |
| AbuseIPDB reports | Recently acquired cloud IP with previous tenant's history | Check report dates → `false_positive` |
| DKIM not found | Custom selector | `--dkim-selectors <name>` |
| CORS wildcard | Public API with no user data | `accepted_risk` |
