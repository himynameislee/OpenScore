"""IP & domain reputation + passive internet-scan intel (no packets to the target).

Sources (all free):
  * DNS blocklists: Spamhaus ZEN/DBL, SpamCop, Barracuda, PSBL, SURBL
  * AbuseIPDB        (free API key, 1,000 checks/day)
  * GreyNoise Community (no key needed; optional key raises limits)
  * Shodan InternetDB  (no key) — open ports, CPEs, CVEs, tags seen by Shodan
  * Have I Been Pwned domain search (optional paid key; domain must be verified in HIBP)
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from . import ports
from .. import proof, util

log = logging.getLogger("openscore")
MODE = "passive"

IP_DNSBLS = {
    "zen.spamhaus.org": "Spamhaus ZEN",
    "bl.spamcop.net": "SpamCop",
    "b.barracudacentral.org": "Barracuda",
    "psbl.surriel.com": "PSBL",
}
DOMAIN_BLS = {"dbl.spamhaus.org": "Spamhaus DBL", "multi.surbl.org": "SURBL"}
BAD_SHODAN_TAGS = {"compromised", "malware", "c2", "doublepulsar", "botnet", "cryptomining", "tor"}


def _rev(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _dnsbl(ctx, ip: str) -> None:
    for zone, name in IP_DNSBLS.items():
        r = ctx.dns.query(f"{_rev(ip)}.{zone}", "A")
        if not r.ok:
            continue
        codes = r.records
        if any(c.startswith("127.255.255.") for c in codes):
            ctx.module_status.setdefault("reputation", {})["spamhaus"] = (
                "Spamhaus refused the query (public/open resolver or rate limit). Use --resolver "
                "with your own recursive resolver or a free Spamhaus DQS key for accurate results.")
            continue
        if zone == "zen.spamhaus.org" and all(c in ("127.0.0.10", "127.0.0.11") for c in codes):
            # PBL only = "dynamic/end-user IP range", not an abuse listing
            continue
        ctx.add("rep_dnsbl_listed", ip, f"{name} ({zone}) → {', '.join(codes)}",
                title=f"IP listed on {name}", source="dnsbl",
                proof=proof.make("DNS blocklist query", f"dig +short A {_rev(ip)}.{zone}",
                                 [[c, "bad", "listed (any 127.0.0.x answer = listed)"] for c in codes],
                                 verdict=f"{ip} is listed on {name}"))


def _domain_bl(ctx) -> None:
    for zone, name in DOMAIN_BLS.items():
        r = ctx.dns.query(f"{ctx.domain}.{zone}", "A")
        if r.ok and r.records:
            if any(c.endswith(".255") or c.startswith("127.255.") or c == "127.0.0.1" for c in r.records):
                continue  # error / query refused codes
            ctx.add("rep_domain_blocklisted", ctx.domain, f"{name} → {', '.join(r.records)}",
                    title=f"Domain listed on {name}", source="dnsbl",
                    proof=proof.make("Domain blocklist query", f"dig +short A {ctx.domain}.{zone}",
                                     [[c, "bad", "listed"] for c in r.records],
                                     verdict=f"{ctx.domain} is listed on {name}"))


def _abuseipdb(ctx, ip: str) -> None:
    key = ctx.cfg.abuseipdb_key
    if not key:
        return
    try:
        r = ctx.session.get("https://api.abuseipdb.com/api/v2/check",
                            params={"ipAddress": ip, "maxAgeInDays": 90},
                            headers={"Key": key, "Accept": "application/json"}, timeout=20)
        if r.status_code == 429:
            ctx.module_status.setdefault("reputation", {})["abuseipdb"] = "rate limited (free tier 1000/day)"
            return
        r.raise_for_status()
        d = r.json().get("data", {})
    except Exception as e:
        ctx.module_status.setdefault("reputation", {})["abuseipdb"] = f"error: {e}"
        return
    score = d.get("abuseConfidenceScore", 0) or 0
    reports = d.get("totalReports", 0) or 0
    if score == 0 and reports == 0:
        return
    sev = "high" if score >= 75 else "medium" if score >= 25 else "low"
    ev = (f"Confidence {score}%, {reports} reports from {d.get('numDistinctUsers', '?')} users, "
          f"last {d.get('lastReportedAt', '?')}; ISP {d.get('isp', '?')}, usage {d.get('usageType', '?')}")
    ctx.add("rep_abuseipdb", ip, ev, severity=sev, title=f"IP reported for abuse on AbuseIPDB ({score}%)",
            source="abuseipdb", proof=proof.make(
                "AbuseIPDB API", f"curl -s -H 'Key: …' 'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'",
                [[f'"abuseConfidenceScore": {score}', "bad" if score >= 25 else "warn", None],
                 [f'"totalReports": {reports}', "bad" if reports else None, None],
                 [f'"numDistinctUsers": {d.get("numDistinctUsers", "?")}', None, None],
                 [f'"lastReportedAt": "{d.get("lastReportedAt", "?")}"', None, "check this is recent"],
                 [f'"isp": "{d.get("isp", "?")}"  "usageType": "{d.get("usageType", "?")}"', None,
                  "shared/cloud IP? reports may belong to a previous tenant"]],
                verdict=f"{reports} abuse reports in the last 90 days"))


def _greynoise(ctx, ip: str) -> None:
    headers = {"Accept": "application/json"}
    if ctx.cfg.greynoise_key:
        headers["key"] = ctx.cfg.greynoise_key
    try:
        r = ctx.session.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers, timeout=15)
        if r.status_code == 404:
            return
        if r.status_code == 429:
            ctx.module_status.setdefault("reputation", {})["greynoise"] = "rate limited (community API)"
            return
        if r.status_code != 200:
            return
        d = r.json()
    except Exception:
        return
    if d.get("classification") == "malicious":
        ctx.add("rep_greynoise_malicious", ip, f"GreyNoise: {d.get('name', '')} last seen {d.get('last_seen', '?')} "
                f"— {d.get('link', '')}", source="greynoise",
                proof=proof.make("GreyNoise Community API", f"curl -s https://api.greynoise.io/v3/community/{ip}",
                                 [[f'"classification": "{d.get("classification")}"', "bad", None],
                                  [f'"noise": {str(d.get("noise")).lower()}', None, "seen scanning the internet"],
                                  [f'"name": "{d.get("name", "")}"', None, None],
                                  [f'"last_seen": "{d.get("last_seen", "?")}"', None, None]],
                                 verdict=f"{ip} observed performing malicious internet-wide activity"))


def _internetdb(ctx, ip: str) -> None:
    try:
        r = ctx.session.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
        if r.status_code in (200, 404):
            ctx.flags["internetdb_ok"] = True
        if r.status_code != 200:
            return
        d = r.json()
    except Exception as e:
        # Without InternetDB a passive scan can't assess Network Security; say why in the report.
        util.note_source_failure(ctx, "reputation", "shodan_internetdb", e)
        return
    for p in d.get("ports", []):
        ports.report_port(ctx, ip, int(p), "(seen by Shodan — not live-verified)", "shodan-internetdb",
                          confidence="tentative", shodan_ports=d.get("ports", []))
    for cpe in d.get("cpes", []):
        ports._cpe_software(ctx, ip, cpe, "shodan cpe")
    for cve in d.get("vulns", []):
        ctx.record_cve(cve, ip)
    bad = BAD_SHODAN_TAGS & set(d.get("tags", []))
    if bad:
        ctx.add("rep_shodan_tag", ip, f"Shodan tags: {', '.join(sorted(bad))}", source="shodan-internetdb",
                proof=proof.make("Shodan InternetDB", f"curl -s https://internetdb.shodan.io/{ip}",
                                 [[f'"tags": {sorted(d.get("tags", []))}', "bad", f"{', '.join(sorted(bad))}"]],
                                 verdict=f"Shodan flags {ip} as {', '.join(sorted(bad))}"))


def _hibp(ctx) -> None:
    if not ctx.cfg.hibp_key:
        return
    try:
        r = ctx.session.get(f"https://haveibeenpwned.com/api/v3/breacheddomain/{ctx.domain}",
                            headers={"hibp-api-key": ctx.cfg.hibp_key}, timeout=30)
        if r.status_code in (401, 403):
            ctx.module_status.setdefault("reputation", {})["hibp"] = (
                f"HTTP {r.status_code}: key invalid or domain not verified in your HIBP dashboard")
            return
        if r.status_code == 404:
            return
        r.raise_for_status()
        data = r.json() or {}
    except Exception as e:
        ctx.module_status.setdefault("reputation", {})["hibp"] = f"error: {e}"
        return
    if not data:
        return
    breaches = {}
    for alias, bl in data.items():
        for b in bl:
            breaches.setdefault(b, []).append(alias)
    n = len(data)
    sev = "high" if n >= 25 else "medium" if n >= 5 else "low"
    ev = f"{n} addresses in {len(breaches)} breaches. Top: " + "; ".join(
        f"{b} ({len(a)})" for b, a in sorted(breaches.items(), key=lambda x: -len(x[1]))[:8])
    ctx.add("leak_breached_accounts", ctx.domain, ev, severity=sev, source="hibp")


def run(ctx) -> None:
    _domain_bl(ctx)
    _hibp(ctx)
    ips = set()
    skipped = set()
    for a in ctx.assets.values():
        for ip in a.ips:
            if a.hosting_class in ("saas", "cdn") and not a.explicit:
                skipped.add(ip)
            else:
                ips.add(ip)
    ips = sorted(ips - skipped, key=lambda x: (":" in x, x))
    v4 = [i for i in ips if ":" not in i]
    log.info("Reputation / InternetDB lookups for %d IPs (%d shared SaaS/CDN IPs skipped)", len(ips), len(skipped))

    def one(ip):
        if ":" not in ip:
            _dnsbl(ctx, ip)
        _abuseipdb(ctx, ip)
        _greynoise(ctx, ip)
        _internetdb(ctx, ip)

    with ThreadPoolExecutor(max_workers=min(4, ctx.cfg.threads)) as ex:
        list(ex.map(one, ips))

    if not any(f.factor == "reputation" and f.severity != "pass" for f in ctx.findings) and v4:
        ctx.passed("rep_clean", ctx.domain, f"{len(ips)} IPs checked", source="reputation")
