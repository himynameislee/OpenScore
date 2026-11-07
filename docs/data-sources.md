# Data sources and network use

Besides the target itself, OpenScore talks to these services. None of them receives anything but
the domain, hostnames or IP addresses being assessed, and the API keys you supply. OpenScore has
no telemetry and doesn't check for updates on its own (`--update` runs only when you ask).

| Service | Used for | Key | Notes |
|---|---|---|---|
| **crt.sh** | Subdomain discovery from certificate transparency logs | None | Often overloaded. OpenScore retries up to three times; a final failure shows as a Coverage gap. |
| **subfinder** (if installed) | More subdomain discovery from its own passive sources | Its own config | Optional tool, runs locally |
| **DNS** (your resolver or `--resolver`) | Resolving hosts, email and DNS records, blocklist lookups | None | See the Spamhaus note below |
| **Team Cymru** IP-to-ASN (over DNS) | Who owns each IP, for [hosting classification](hosting-classification.md) | None | |
| **Shodan InternetDB** | Open ports, known CVEs and tags for each IP, without scanning | None | Free, limited data; ports seen only here are tentative until confirmed live |
| **Spamhaus ZEN / DBL, SpamCop, Barracuda, PSBL, SURBL** | IP and domain blocklists | None | DNS lookups |
| **AbuseIPDB** | Abuse reports per IP | `ABUSEIPDB_KEY` (free) | Skipped without a key; 1,000 checks per day on the free tier |
| **GreyNoise Community** | Whether an IP is seen scanning or attacking the internet | `GREYNOISE_KEY` (optional) | Works without a key but is rate-limited |
| **Have I Been Pwned** | Breached accounts on the domain | `HIBP_KEY` (paid) | Skipped without a key; the domain must be verified in your HIBP dashboard |
| **endoflife.date** | Software end-of-life dates | None | |
| **CISA KEV** | Which CVEs are known to be exploited | None | |
| **FIRST EPSS** | How likely each CVE is to be exploited | None | |

All requests to these services use an HTTP User-Agent that names OpenScore and its version and
links to the project.

## Requests to the target

What reaches the target's own systems depends on the mode; see
[Modes, scope and authorization](modes-and-scope.md). In short: passive checks send nothing to the
target's web servers (DNS queries go to its nameservers, including one zone-transfer request each),
light checks make normal-visitor requests, and active checks scan and probe only what's in scope.

## Notes on specific sources

**Spamhaus and public resolvers.** Spamhaus refuses queries that arrive through large public
resolvers such as 1.1.1.1 and 8.8.8.8. If your system uses one, the Spamhaus checks don't work and
the Module notes say so. Use your ISP's resolver or your own with `--resolver`.

**Rate limits.** GreyNoise's community API and AbuseIPDB's free tier have daily limits. Once a
limit is hit, IPs checked after that get no result from that source, and the report says so in a
Coverage gap box.

**Corporate networks that inspect TLS.** If your network re-signs HTTPS traffic (a TLS-inspection
proxy), OpenScore still reaches these services: it trusts your operating system's certificate store
as well as its own. The target's TLS results would describe the proxy rather than the target,
though, so those are skipped and the report says why. See
[Troubleshooting](troubleshooting.md#tls-inspection-detected).

**Failures are reported, not hidden.** When requests to a data source fail during a scan, the
report says so in a Coverage gap box at the top and in the Module notes, rather than looking
clean. Rate limits get a Coverage gap box too; other problems, such as an unreachable source, are
listed in the Module notes.

## Using API keys

Set keys as environment variables: `ABUSEIPDB_KEY`, `GREYNOISE_KEY`, `HIBP_KEY`. The
`--abuseipdb-key`, `--greynoise-key` and `--hibp-key` flags exist, but command-line arguments end
up in shell history and process lists. See [Getting started](getting-started.md#api-keys-optional).
Keys are never written to reports, exhibits or the audit log.
