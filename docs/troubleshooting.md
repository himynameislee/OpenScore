# Troubleshooting

Start with the report itself: the **Coverage gap** boxes under the summary and the **Module notes**
at the bottom say what didn't run and why. Most of the problems below show up there first.

## The scan found far fewer hosts than expected

**Coverage gap: crt.sh.** Certificate transparency is OpenScore's main discovery source, and
crt.sh is often overloaded. OpenScore retries three times, then carries on with subfinder (if
installed) and common hostnames, and says so at the top of the report. Rerun later, or install
subfinder.

**You're running a standalone binary.** The binaries only find subfinder and nuclei on your PATH
or in a `tools` folder next to the binary. Run from Downloads, they have neither, so discovery is
limited. Put the binary in its own folder with `tools\subfinder.exe` next to it, or install from
source. See [Getting started](getting-started.md#standalone-binaries).

**`--max-hosts` was reached.** The console logs `Discovered N live hosts; keeping first 60`. Raise
`--max-hosts`, or narrow the scope with `--exclude`.

## The active scan takes hours

nuclei and testssl.sh are the slow steps.

- **nuclei** prints progress every minute. It stops after `--nuclei-timeout` minutes (default 60)
  and keeps what it found; Ctrl+C stops it early, also keeping its findings. `--nuclei-rate` sets the
  target requests per second shared by all sites (default 100). nuclei can briefly run a little above
  it, so treat it as a target rather than a hard ceiling. A run of about 30 sites typically takes
  25–40 minutes at the default.
- **testssl.sh** tests one HTTPS host at a time, about 1–2 minutes each, and stops a host after
  `--testssl-timeout` minutes (default 5). Ctrl+C skips the remaining hosts.
- `--no-nuclei` and `--no-testssl` skip them completely.

In every case, what was skipped or stopped is listed in the Module notes and the audit log.

## testssl.sh "can't use an openssl binary"

testssl.sh couldn't start `openssl` on this machine. OpenScore stops trying after the first host
when testssl.sh can't run at all, puts a Coverage gap at the top of the report, and keeps its
built-in TLS checks. Check that `testssl --version` works in a terminal.

## TLS inspection detected

The console warns `TLS inspection detected (HTTPS re-signed by '…')` when your network decrypts
and re-signs HTTPS traffic, which is common on corporate networks. Data sources keep working, but
certificate, protocol and cipher results for the target would describe your proxy, so OpenScore
skips them; when every TLS result was intercepted, the TLS factor isn't graded. Scan from a network
without inspection (a home connection, a cloud VM) for complete TLS results.

## "Spamhaus refused the query"

Spamhaus doesn't answer queries from big public resolvers (1.1.1.1, 8.8.8.8 and similar). Point
OpenScore at your ISP's resolver or your own with `--resolver <IP>`.

## Have I Been Pwned returns 401

The key is wrong, or the domain isn't verified in your HIBP dashboard. HIBP only returns breach
data for domains you've verified you control.

## Rate-limit notes for GreyNoise or AbuseIPDB

The free tiers have daily limits. Large estates can use them up in one scan; IPs checked after the
limit get no result from that source, and the report shows a Coverage gap for it. Add a GreyNoise
key, or spread scans out.

## Lots of "needs verification" findings on Linux servers

Usually version-based findings on a distribution that backports security fixes, such as Apache
2.4.37 on RHEL 8. The evidence says when a version is one a distribution freezes and shows the
`rpm -q` or `dpkg -l` command to check the real patch level. See
[Handling false positives](FALSE_POSITIVES.md).

## Two reports overwrote each other

Report file names include the time to the minute. Scans of the same domain started within the same
minute write to the same files. Wait a minute, or use a different `-o` folder.

## nmap on Windows finds nothing, or OpenScore says it fell back to its own scanner

nmap on Windows needs [Npcap](https://npcap.com). Without it, OpenScore uses a built-in TCP
connect scan of common ports.

## No page screenshots

Screenshots need Playwright and its Chromium browser, which the installers set up. The standalone
binaries don't include them. On a source install:

```bash
pip install playwright && python3 -m playwright install chromium
```

`--no-screenshots` turns them off on purpose.

## Error loading suppressions

OpenScore stops rather than scan with a broken suppressions file. The message names the entry.
Each entry needs at least `check` and `reason`, `status` must be `false_positive`,
`accepted_risk` or `compensating_control`, and accepted risks and compensating controls need an
`expires` date. See [Handling false positives](FALSE_POSITIVES.md).

## `--update` refuses to run

It only fast-forwards. If you've edited OpenScore's own files, or your copy was cloned from a
different repository, it stops instead of overwriting anything. Commit or discard your changes, or
clone a fresh copy.

## Still stuck?

Run with `-v` for debug logging, and [open an issue](https://github.com/himynameislee/OpenScore/issues)
with the console output and the Module notes. **Remove client hostnames, IPs and findings before
posting.**
