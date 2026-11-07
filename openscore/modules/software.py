"""Patching cadence analysis (passive — uses only data already collected plus free public APIs):

  * endoflife.date  — is the detected version end-of-life / behind the latest patch?
  * CISA KEV        — are any detected CVEs actively exploited?
  * FIRST EPSS      — probability a CVE is exploited in the next 30 days
"""
from __future__ import annotations

import datetime as dt
import logging
import re

from .. import proof, util

log = logging.getLogger("openscore")
MODE = "passive"

ALIASES = {
    "apache": "apache-http-server", "apache httpd": "apache-http-server", "http_server": "apache-http-server",
    "httpd": "apache-http-server", "apache http server": "apache-http-server",
    "nginx": "nginx", "php": "php", "openssl": "openssl", "tomcat": "tomcat",
    "apache tomcat": "tomcat", "apache-coyote": None, "wordpress": "wordpress", "drupal": "drupal",
    "joomla": "joomla", "joomla!": "joomla", "mysql": "mysql", "mariadb": "mariadb",
    "postgresql": "postgresql", "redis": "redis", "elasticsearch": "elasticsearch",
    "mongodb": "mongodb", "node.js": "nodejs", "nodejs": "nodejs", "jquery": "jquery",
    "haproxy": "haproxy", "jetty": "eclipse-jetty", "squid": "squid", "exchange": "msexchange",
    "sharepoint": "sharepoint",
}

DISTRO_RE = re.compile(r"ubuntu|debian|centos|red ?hat|rhel|\bel[5-9]\b|fedora|suse|amazon|almalinux|rocky|"
                       r"oracle linux|raspbian|deb\d+u\d+|\+deb", re.I)
BACKPORT_NOTE = ("NOTE: the banner indicates a distro package ({distro}). Distros backport security fixes "
                 "without changing the upstream version number, so this may be a FALSE POSITIVE. "
                 "Verify against the distro's security tracker.")

# Versions that enterprise distros freeze for a whole release and patch by backporting fixes. A banner
# showing one of these exact versions often means "distro package", even with no distro marker in it.
# Only adds context to the evidence; severity and score are unchanged (an unpatched or end-of-life
# box, e.g. CentOS 8, shows the same string).
FROZEN = {
    "apache-http-server": {"2.2.15": "RHEL/CentOS 6", "2.4.6": "RHEL/CentOS 7", "2.4.37": "RHEL 8",
                           "2.4.51": "RHEL 9", "2.4.53": "RHEL 9", "2.4.57": "RHEL 9", "2.4.62": "RHEL 9",
                           "2.4.29": "Ubuntu 18.04", "2.4.41": "Ubuntu 20.04", "2.4.52": "Ubuntu 22.04",
                           "2.4.58": "Ubuntu 24.04", "2.4.38": "Debian 10"},
    "nginx": {"1.14.1": "RHEL 8", "1.20.1": "RHEL 9", "1.18.0": "Ubuntu 20.04", "1.24.0": "Ubuntu 24.04",
              "1.22.1": "Debian 12"},
    "openssl": {"1.0.1e": "RHEL/CentOS 6", "1.0.2k": "RHEL/CentOS 7", "1.1.1k": "RHEL 8",
                "1.1.1f": "Ubuntu 20.04"},
    "openssh": {"7.4": "RHEL/CentOS 7", "8.0": "RHEL 8", "8.7": "RHEL 9", "7.6": "Ubuntu 18.04",
                "8.2": "Ubuntu 20.04", "8.9": "Ubuntu 22.04", "9.6": "Ubuntu 24.04"},
    "php": {"5.4.16": "RHEL/CentOS 7", "7.2.24": "RHEL 8", "8.0.30": "RHEL 9"},
}
PKG = {"apache-http-server": ("httpd", "apache2"), "nginx": ("nginx", "nginx"), "openssl": ("openssl", "openssl"),
       "openssh": ("openssh-server", "openssh-server"), "php": ("php", "php")}


def frozen_note(product: str, version: str) -> str | None:
    """'2.4.37 is the version RHEL 8 ships …' when the exact version is a distro-frozen one."""
    key = "openssh" if "openssh" in product.lower() else _norm(product)
    m = re.match(r"(\d+(?:\.\d+)*)([a-z]?)", (version or "").strip().lower())
    if not m:
        return None
    table = FROZEN.get(key or "", {})
    ver = m.group(0) if m.group(0) in table else m.group(1)     # 1.1.1k (OpenSSL) vs 8.9p1 (OpenSSH)
    distro = table.get(ver)
    if not distro:
        return None
    rpm, deb = PKG[key]
    cmd = f"rpm -q {rpm}" if distro.startswith(("RHEL", "CentOS")) else f"dpkg -l {deb}"
    return (f"{product} {ver} is the version {distro} ships; the distro backports security fixes "
            f"without changing it. If this host runs {distro}, check the package build on the host "
            f"(`{cmd}`) against the distro's security tracker before acting.")


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def vtuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


class EOL:
    def __init__(self, ctx):
        self.ctx = ctx
        self.cache: dict[str, list | None] = {}

    def cycles(self, product: str):
        if product not in self.cache:
            try:
                r = self.ctx.session.get(f"https://endoflife.date/api/{product}.json", timeout=20)
                self.cache[product] = r.json() if r.status_code == 200 else None
            except Exception as e:
                self.ctx.module_status.setdefault("software", {})["endoflife.date"] = f"unreachable: {e}"
                self.cache[product] = None
        return self.cache[product]

    def evaluate(self, product: str, version: str):
        """Return (status, detail) where status in eol|outdated|supported|unknown."""
        cycles = self.cycles(product)
        if not cycles:
            return _fallback(product, version)
        best = None
        for c in cycles:
            cyc = str(c.get("cycle", ""))
            if version == cyc or version.startswith(cyc + "."):
                if best is None or len(cyc) > len(str(best["cycle"])):
                    best = c
        if best is None:
            # version older than every tracked cycle -> almost certainly EOL
            oldest = min(cycles, key=lambda c: vtuple(str(c.get("cycle", "0"))) or (0,))
            if vtuple(version) and vtuple(version) < vtuple(str(oldest.get("cycle", "0"))):
                return "eol", f"older than oldest tracked release ({oldest.get('cycle')})"
            return "unknown", ""
        eol = best.get("eol")
        today = dt.date.today().isoformat()
        if eol is True or (isinstance(eol, str) and eol <= today):
            return "eol", f"{product} {best['cycle']} end-of-life {eol if isinstance(eol, str) else ''}".strip()
        latest = str(best.get("latest", ""))
        if latest and vtuple(version) and vtuple(version) < vtuple(latest):
            return "outdated", f"running {version}, latest {best['cycle']}.x is {latest}"
        return "supported", f"{product} {best['cycle']} supported until {eol}"


def _fallback(product, version):
    v = vtuple(version)
    if not v:
        return "unknown", ""
    if product == "php" and v < (8, 2):
        return "eol", "PHP < 8.2 is end-of-life"
    if product == "apache-http-server" and v < (2, 4):
        return "eol", "Apache 2.2 and older are end-of-life"
    if product == "openssl" and v < (3, 0):
        return "eol", "OpenSSL 1.x is end-of-life"
    return "unknown", ""


def _iis(version):
    v = vtuple(version)
    if v and v < (10,):
        os_ = {(7, 0): "2008", (7, 5): "2008 R2", (8, 0): "2012", (8, 5): "2012 R2"}.get(v[:2], "≤2012 R2")
        return "eol", f"IIS {version} ships with Windows Server {os_}, which is out of support"
    return "supported", f"IIS {version} (Windows Server 2016+) — patch status depends on Windows Update"


def _exchange(version):
    v = vtuple(version)
    if not v:
        return "unknown", ""
    if v[:2] in ((15, 0), (15, 1), (14, 3), (14, 0)) or (v[:2] == (15, 2) and v < (15, 2, 2562)):
        return "eol", (f"Exchange build {version}: Exchange 2013/2016/2019 are out of support "
                       "(2016/2019 ended 2025-10-14). Migrate to Exchange SE or Exchange Online.")
    return "supported", f"Exchange SE build {version}"


def _norm(product: str):
    p = product.lower().strip()
    p = re.sub(r"^(microsoft[- ])", "", p)
    if p in ("httpapi", "http.sys"):
        # Microsoft-HTTPAPI/2.0 is HTTP.sys; every Windows from Server 2008 to 2025 sends "2.0",
        # so it says nothing about the OS or IIS version (it stays a banner-disclosure finding).
        return None
    if p in ("iis", "microsoft-iis", "internet_information_services", "internet information services"):
        return "iis"
    return ALIASES.get(p, p if p in ALIASES.values() else None)


def check_versions(ctx) -> None:
    eol = EOL(ctx)
    seen = set()
    for sw in ctx.software:
        prod = _norm(sw["product"])
        if not prod or (prod, sw["version"], sw["asset"]) in seen:
            continue
        seen.add((prod, sw["version"], sw["asset"]))
        if prod == "iis":
            status, detail = _iis(sw["version"])
        elif prod == "msexchange":
            status, detail = _exchange(sw["version"])
        else:
            status, detail = eol.evaluate(prod, sw["version"])
        ev = f"{sw['product']} {sw['version']} (from {sw['source']}: {sw.get('raw') or '-'})\n{detail}"
        distro = DISTRO_RE.search(sw.get("raw", "") or "")
        src_hdr = sw["source"].replace("http ", "")
        lines = [[f"{src_hdr}: {sw.get('raw') or sw['version']}", "bad" if status in ("eol", "outdated") else None,
                  f"{prod} {sw['version']} detected"],
                 ["", None, None],
                 [f"lifecycle ({'endoflife.date/' + prod if prod not in ('iis', 'msexchange') else 'Microsoft lifecycle'}):",
                  None, None],
                 [detail or "(no lifecycle data)", "bad" if status == "eol" else "warn" if status == "outdated" else None,
                  None]]
        if distro:
            lines.append([f"distro marker '{distro.group(0)}' in banner — fixes may be backported", "warn",
                          "verify before acting"])
        elif (fz := frozen_note(sw["product"], sw["version"])):
            lines.append([fz, "warn", "verify before acting"])
            ev += "\n" + fz
        a = ctx.assets.get(sw["asset"])
        seen_url = next(iter(a.web), f"https://{sw['asset']}/") if a and a.web else f"https://{sw['asset']}/"
        pr = proof.make("Version fingerprint vs vendor lifecycle", f"curl -sI {seen_url}"
                        if sw["source"].startswith("http") else sw["source"], lines,
                        verdict=detail)
        conf = "firm"
        if distro and prod not in ("iis", "msexchange"):
            ev += "\n" + BACKPORT_NOTE.format(distro=distro.group(0))
            conf = "tentative"
        if status == "eol":
            ctx.add("sw_eol", sw["asset"], ev, title=f"End-of-life software: {sw['product']} {sw['version']}",
                    source="endoflife.date", confidence=conf, proof=pr)
        elif status == "outdated":
            ctx.add("sw_outdated", sw["asset"], ev, title=f"Outdated: {sw['product']} {sw['version']}",
                    source="endoflife.date", confidence=conf, severity="low" if distro else None, proof=pr)
        elif status == "supported":
            ctx.passed("sw_supported", sw["asset"], ev, source="endoflife.date")


def check_cves(ctx) -> None:
    if not ctx.cves:
        return
    kev = {}
    try:
        r = ctx.session.get(KEV_URL, timeout=60)
        for v in r.json().get("vulnerabilities", []):
            kev[v["cveID"].upper()] = v
    except Exception as e:
        ctx.module_status.setdefault("software", {})["cisa_kev"] = f"unreachable: {e}"
    cves = sorted(ctx.cves)
    epss = {}
    for i in range(0, len(cves), 80):
        try:
            r = ctx.session.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(cves[i:i + 80])},
                                timeout=30)
            for row in r.json().get("data", []):
                epss[row["cve"].upper()] = float(row.get("epss", 0))
        except Exception as e:
            ctx.module_status.setdefault("software", {})["epss"] = f"unreachable: {e}"
            break

    by_asset: dict[str, list[str]] = {}
    for cve, assets in ctx.cves.items():
        for a in assets:
            by_asset.setdefault(a, []).append(cve)
    frozen: dict[str, list[str]] = {}
    for sw in ctx.software:
        note = frozen_note(sw["product"], sw["version"])
        if note and note not in frozen.setdefault(sw["asset"], []):
            frozen[sw["asset"]].append(note)
    for asset, lst in by_asset.items():
        notes = frozen.get(asset, [])
        k = sorted(c for c in lst if c in kev)
        hi = sorted((c for c in lst if c not in kev and epss.get(c, 0) >= 0.3), key=lambda c: -epss[c])
        rest = sorted(c for c in lst if c not in kev and c not in hi)
        hosts = ctx.hosts_on_ip(asset) if util.is_ip(asset) else []
        host_lines = ([["", None, None]]
                      + [[f"Site on this IP: {h['url'] or h['host']}", None, None] for h in hosts[:8]]
                      + ([[f"… and {len(hosts) - 8} more", None, None]] if len(hosts) > 8 else [])
                      if hosts else [])

        def cve_proof(items, verdict):
            return proof.make("CVE enrichment (CISA KEV + FIRST EPSS)",
                              f"curl -s https://internetdb.shodan.io/{asset}  # + KEV catalog + EPSS API",
                              [[f"{c}  KEV={'YES' if c in kev else 'no'}  EPSS={epss.get(c, 0):.1%}",
                                "bad" if c in kev or epss.get(c, 0) >= 0.3 else None,
                                (kev[c].get("vulnerabilityName", "")[:80] if c in kev else None)]
                               for c in items]
                              + host_lines
                              + ([["", None, None]] + [[n, "warn", "verify before acting"] for n in notes]
                                 if notes else []), verdict=verdict)
        if k:
            ctx.add("vuln_kev", asset, "\n".join(
                f"{c} — {kev[c].get('vendorProject', '')} {kev[c].get('product', '')}: "
                f"{kev[c].get('vulnerabilityName', '')}" + (f" (EPSS {epss[c]:.0%})" if c in epss else "")
                for c in k) + "".join("\n" + n for n in notes),
                title=f"{len(k)} actively exploited CVE(s) (CISA KEV) match detected versions",
                source="cisa-kev", confidence="tentative",
                proof=cve_proof(k, "Version fingerprint matches actively exploited CVEs"))
        if hi:
            ctx.add("vuln_high_epss", asset, "\n".join(f"{c} (EPSS {epss[c]:.0%})" for c in hi[:20])
                    + "".join("\n" + n for n in notes),
                    title=f"{len(hi)} CVE(s) with high exploit probability", source="epss", confidence="tentative",
                    proof=cve_proof(hi[:20], "High probability of exploitation within 30 days"))
        if rest:
            ctx.add("vuln_cve", asset, ", ".join(rest[:40]) + (" …" if len(rest) > 40 else ""),
                    title=f"{len(rest)} potential CVE(s) from version fingerprint", source="shodan/nuclei",
                    confidence="tentative", proof=cve_proof(rest[:25], "Version-based matches — verify installed version"))


def run(ctx) -> None:
    log.info("Evaluating %d software fingerprints and %d CVEs", len(ctx.software), len(ctx.cves))
    check_versions(ctx)
    check_cves(ctx)
