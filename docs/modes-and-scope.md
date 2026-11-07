# Modes, scope and authorization

OpenScore has three kinds of checks. Passive and light checks always run. Active checks run only
when you ask for them and confirm you're authorized.

| Mode | What it does | Who it contacts | Needs |
|---|---|---|---|
| **Passive** | Discovery, DNS and email records, reputation, software lifecycle and CVE data | Public data sources and DNS. No requests to the target's web servers. | Nothing |
| **Light** | Web and TLS checks, page screenshots | The target's web servers, with the requests a normal visitor's browser makes | Nothing |
| **Active** | Port scan, exposure probes, CORS probe, nuclei, testssl.sh | The target's servers, with more and deeper requests than a visitor makes | `--active`, `--authorization` and a typed scope confirmation |

> **Only run active checks against systems you own or have written permission to test.** Passive
> and light checks are safe on any domain.

There's currently no switch to turn off light checks. A scan without `--active` is "passive +
light".

## What each part does

The scan runs these modules in order:

| Module | Mode | What it does |
|---|---|---|
| discovery | passive | Finds hostnames from certificate transparency logs (crt.sh), subfinder if installed, and a list of common names (`www`, `mail`, `vpn`, `portal`…), then resolves them and looks up who hosts each IP (Team Cymru). Flags dangling CNAMEs (possible subdomain takeover). |
| dns_email | passive | SPF, DMARC, DKIM, MTA-STS, TLS-RPT, DNSSEC, CAA, nameservers. Also asks each authoritative nameserver for a zone transfer (AXFR), which is a single standard DNS request and is written to the audit log. |
| web | light | Fetches the homepage of each host over HTTP and HTTPS, checks the redirect, security headers and cookies, and inspects the TLS certificate and handshake. Looks for `security.txt`. In active mode, also sends one CORS probe per site (never to a SaaS host or a redirect target outside the scope). |
| reputation | passive | DNS blocklists, AbuseIPDB, GreyNoise and Shodan tags for each IP; domain blocklists. |
| ports | **active** | nmap (or a built-in TCP connect scanner) on in-scope IPs, then a live re-test of any port that only Shodan reported. |
| exposures | **active** | Single GET requests for well-known sensitive paths (`/.git/HEAD`, `/.env`, backups, debug pages, admin panels), matched on content, after a control request to a random path. |
| external_tools | **active** | nuclei (safe templates only) and testssl.sh. |
| software | passive | Matches the software versions seen so far against end-of-life data, CISA KEV and FIRST EPSS. |
| screenshots | light | Page screenshots of portals, panels and each host's homepage, for the evidence. |

## Scope

Active checks only ever touch:

- **the domain you scan and its subdomains** (minus anything in `--exclude`),
- **hosts and URLs you name** with `--hosts` and `--url`, and
- **IP addresses inside ranges you name** with `--ips` (up to 256 addresses per range).

**Active checks test the host they actually contact.** When a homepage redirects somewhere else,
OpenScore records where it went (you'll see it in the Asset inventory), but if the destination is
another organization's domain or a SaaS sign-in page, no active check is sent there. Only the
original, in-scope address is tested. Exposure probes follow redirects only within the scope.

Two kinds of hosts are skipped by the port scan even when they're in scope, because the IPs are
shared with other customers:

- **CDN** hosts (Cloudflare, Akamai, Azure Front Door…), unless you pass `--scan-cdn`.
- **SaaS** hosts (Microsoft 365, Salesforce, Okta…). These are also skipped by exposure probes,
  nuclei, testssl.sh and screenshots, and their findings don't count toward the score.

See [Hosting classification](hosting-classification.md) for how hosts are classified.

### Check the scope before an active scan

Every subdomain OpenScore discovers is in scope for active checks. That's usually what you want,
but it isn't always what you're authorized for:

- **A subdomain may point at a vendor's system** that OpenScore doesn't recognize as SaaS, for
  example a hosted application on its own IP range. If your authorization doesn't cover it, add it
  to `--exclude`.
- **A subdomain may belong to a different legal entity** (a subsidiary, a franchisee). Same answer.

The simplest way to check is to run a passive + light scan first, read the **Asset inventory** at
the bottom of the report, and then run the active scan with `--exclude` for anything that isn't
covered. To test only specific hosts, use `--no-discovery` with `--hosts` or `--url`; OpenScore then
checks only the domain, its `www` host and what you named.

`--max-hosts` (default 60) caps how many discovered hosts are kept. When there are more, OpenScore
keeps the apex, `www`, mail and remote-access names first, then the shortest names, and logs a
warning.

## The authorization gate

An active scan won't start unless:

1. **`--authorization` is given.** Use a reference to the written permission: a statement of work
   number, the signer and the date. It appears in the report header and the audit log, so don't put
   anything there you wouldn't want in a client deliverable.
2. **You confirm the scope.** OpenScore prints the domain, IP ranges, extra hosts and the
   authorization reference, then asks you to type the domain. Anything else aborts the scan.

`-y` skips the typed confirmation, for scheduled scans where you've already confirmed the scope.

## The audit log

`<domain>-<time>.audit.log` records, with UTC timestamps:

- the scan start: domain, mode, authorization reference and the operator's username,
- every active action: the nmap command and the IPs it scanned, exposure probes per site, CORS
  probes, nuclei's tags, rate and stop reason, each testssl.sh host and how it ended,
- zone-transfer attempts and screenshots (URLs without query strings),
- the scan end.

Keep it with the report. It's your record of exactly what was sent to the client's systems.

## What OpenScore never does

OpenScore finds and documents issues; it doesn't exploit them.

- No exploitation, no credential guessing or default-login checks, no payload injection, no form
  submission.
- Exposure probes are single GET requests. Responses are capped at 512 KB, secret values are
  masked before they're stored, and secret-bearing files are never screenshotted.
- nuclei runs only the `exposure, misconfig, ssl, takeover, config, exposed-panels, panel, cve, kev`
  tags and excludes `intrusive, dos, fuzz, bruteforce, default-login, sqli, xss, rce, lfi, ssrf,
  oast, headless`, with out-of-band interaction (interactsh) turned off.
- The User-Agent identifies OpenScore and links to the project, so a site owner who sees the traffic
  can tell what it is.
