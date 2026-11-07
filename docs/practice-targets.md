# Practice targets

Passive and light scans are safe on any domain. **Active scans need permission**, and "it's a
training site" isn't permission: many training sites run on production infrastructure that only
invites you to solve its challenges in a browser. These are the options that are actually set up
for scanning.

## The built-in lab

The repository ships a deliberately misconfigured local target, `tests/fake_target.py`. It's what
CI scans on every change, it needs no internet access, and you can't hurt anyone with it:

```bash
python3 tests/fake_target.py &
python3 -m openscore lab.invalid --no-discovery \
    --url https://127.0.0.1:8443/ http://127.0.0.1:8080/ \
    --ips 127.0.0.1/32 --active --authorization "local lab" -y --delay 0 --open
```

Expect a poor grade: that's the point. `lab.invalid` isn't a real domain, so the DNS, email and
reputation results don't mean anything here; the lab is for the web, TLS, exposure and port checks.

## Public sites that invite scanning

These operators publish their sites specifically for testing scanners. Rules can change, so read
each site's own terms before an active scan, keep `--nuclei-rate` modest, and expect them to be slow
or down sometimes: they're shared by everyone practicing.

| Site | Good for | How to scan it |
|---|---|---|
| `scanme.nmap.org` | Port scanning | The Nmap project lets people scan this one host for testing; keep it occasional, not repeated. Active scan of that host only. |
| `testphp.vulnweb.com`, `testhtml5.vulnweb.com`, `testasp.vulnweb.com`, `testaspnet.vulnweb.com`, `rest.vulnweb.com` | Web checks, exposures, outdated software, nuclei | Deliberately vulnerable demo sites published for testing web vulnerability scanners. An active scan also port-scans the host, which goes beyond web scanning; check the operator's terms first. |
| The `*.testinvicti.com` demo sites | Same, with newer stacks | Published by the same company, on the same terms. |
| `badssl.com` subdomains (`expired.`, `self-signed.`, `wrong.host.`, `tls-v1-0.`…) | TLS checks | Built to test how clients handle bad TLS. **Light mode only**: no port scans. |

### Scanning a single host

OpenScore rates domains: it discovers subdomains and checks the domain's email and DNS setup. For a
public test host, scan exactly that host so nothing else is pulled in:

```bash
python3 -m openscore testphp.vulnweb.com --no-discovery --active \
    --authorization "public scanner test site" --nuclei-rate 10
```

With `--no-discovery`, OpenScore checks only the name you gave and its `www` host. Expect email
and DNS findings that don't mean much (a test web server doesn't send mail), and a grade that says
more about the test site than about OpenScore.

## Your own targets

The most useful practice target is one you own completely:

- **A lab VM or container** running deliberately vulnerable software (OWASP Juice Shop, DVWA, an old
  web server version). Scan it by IP with `--ips` and `--hosts`.
- **A throwaway domain** with a small cloud server behind it. This is the only way to exercise the
  email, DNS, certificate and takeover checks on real data. Misconfigure it on purpose: a weak SPF
  record, no DMARC, an expired certificate on one subdomain, missing security headers.

  **Don't leave a claimable dangling CNAME live** (for example, a CNAME to a deleted Azure Web App
  name). Anyone could claim that name and serve content on your domain while it exists. Point it at
  a provider-assigned name instead, or claim the target yourself.

## Not suitable

- **Production sites of training platforms.** Their challenges are meant to be solved in a browser,
  and their servers also run accounts and forums. Scanning the infrastructure isn't covered.
- **Capture-the-flag and lab platforms' machines**, unless the platform's rules allow automated
  scanning. They're also a poor fit: lab machines usually sit on private IPs behind a VPN with no
  real domain, so most of OpenScore's factors have nothing to assess.
- **Anything you found by searching for "vulnerable sites".** If the owner hasn't said you can scan
  it, you can't.
