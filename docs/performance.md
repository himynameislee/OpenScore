# Performance tuning

A passive + light scan of a typical organization finishes in a few minutes. An active scan takes
longer, and almost all of that time goes to two external tools: **nuclei** and **testssl.sh**.
This page explains where the time goes, what to expect, and which options trade speed for
coverage.

## What to expect

Measured on a real active scan of an organization with about 60 assets and 30 web roots
(Linux, home broadband):

| Scan | Time |
|---|---|
| Full active scan, `--nuclei-rate 150` | about 49 minutes |
| nuclei alone (30 web roots at 150 requests/s) | about 22 minutes |
| testssl.sh alone (29 HTTPS hosts) | about 14 minutes |
| Active scan with `--no-nuclei` | about 27 minutes |
| Passive + light (no `--active`) | a few minutes |

Your numbers will differ with the number of hosts, how fast they answer, and your connection.
The console prints progress for nuclei and testssl.sh every minute, and the Module notes in the
report give the time each one took.

## nuclei

nuclei runs only the safe template tags (see [Modes, scope and authorization](modes-and-scope.md))
against each web root (one per origin, so a host reached through several URLs is tested once).
The `cve` tag makes up most of the requests: about **7,400 requests per web root**.

nuclei's time is set by its rate limit, so a quick estimate is:

    minutes ≈ web roots × 7,400 ÷ rate ÷ 60

That's about **1.2 minutes per web root at the default 100 requests/s**, and 0.8 minutes at 150.

| Option | Default | Effect |
|---|---|---|
| `--nuclei-rate N` | 100 | Requests per second, shared by all sites. Concurrency follows it (rate ÷ 4, between 10 and 50). Raise it for large estates if the targets and your link can take it; lower it for fragile or rate-limited sites. |
| `--nuclei-timeout MIN` | 60 | Stops nuclei after MIN minutes and keeps what it found. At 100 requests/s, 60 minutes covers about 48 web roots; with more roots than that, raise the limit or the rate. A stopped run shows as a Coverage gap at the top of the report. |
| `--no-nuclei` | off | Skips nuclei completely. OpenScore's own exposure probes, port checks and TLS checks still run. |

Ctrl+C during nuclei stops only nuclei; the rest of the scan carries on with what it found.

## testssl.sh

testssl.sh tests one HTTPS host at a time, usually 30 seconds to 2 minutes each. Hosts that
can't be reached time out after 10 seconds per connection.

| Option | Default | Effect |
|---|---|---|
| `--testssl-timeout MIN` | 5 | Stops testssl.sh on one host after MIN minutes and keeps the results it had. |
| `--no-testssl` | off | Skips testssl.sh. OpenScore's built-in TLS checks (certificate, protocols, key, signature) still run on every host. |

Ctrl+C during testssl.sh skips the remaining hosts.

## Discovery and scope

| Option | Default | Effect |
|---|---|---|
| `--max-hosts N` | 60 | Cap on discovered live hosts. Everything after N is skipped (the console says so). Raise it for large organizations; every extra web host adds roughly 1–2 minutes to an active scan. |
| `--no-discovery` | off | Tests only the apex, `www` and what you pass with `--hosts` / `--url`. The fastest way to re-check a few systems after a fix. |
| `--exclude HOST ...` | none | Skips named hosts (for example, a fragile legacy system). |
| `--full-ports` | off | Scans all 65,535 TCP ports instead of the high-risk list. Much slower; use it on small IP ranges. |

## Everything else

| Option | Default | Effect |
|---|---|---|
| `--threads N` | 8 | Parallel workers for DNS, discovery and probes (the port check uses up to 8× this, capped at 64). |
| `--timeout SEC` | 12 | Network timeout per request. Lower it if many hosts don't answer at all. |
| `--delay SEC` | 0.25 | Pause between probe requests to the same host. Keep it for production systems; `0` is fine for a lab. |
| `--no-screenshots` | off | Skips page screenshots (Playwright). Saves a few seconds per host. |
| `--max-screenshots N` | 60 | Cap on page screenshots per scan. |
| `--max-proof-images N` | 250 | Cap on PNG evidence exhibits. Large estates can reach it; the HTML report still shows every exhibit. |

## Recipes

Quick re-check of a few hosts after a fix:

    openscore example.com --no-discovery --hosts app.example.com vpn.example.com \
        --active --authorization "..." --no-nuclei

First look at a large estate (fast, then go deeper where it matters):

    openscore example.com --max-hosts 200 --active --authorization "..." --no-nuclei --no-testssl

Full scan of a large estate, given more time:

    openscore example.com --max-hosts 200 --active --authorization "..." \
        --nuclei-rate 150 --nuclei-timeout 180

Run active scans from a machine with a stable connection (a cloud VM works well), and agree the
scan window and rate with the owner of the systems, as your authorization should say.
