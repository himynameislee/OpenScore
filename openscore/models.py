"""Core data model: findings, assets and the shared scan context."""
from __future__ import annotations

import datetime as _dt
import ipaddress
import logging
import threading
from dataclasses import asdict, dataclass, field
from typing import Optional

from . import kb

SEVERITIES = ["critical", "high", "medium", "low", "info", "pass"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

log = logging.getLogger("openscore")


@dataclass
class Finding:
    check_id: str
    factor: str
    severity: str
    asset: str
    title: str
    evidence: str = ""
    source: str = ""
    confidence: str = "firm"          # firm | tentative
    third_party: bool = False          # asset hosted by a SaaS provider -> excluded from score
    suppression: Optional[dict] = None # set when matched by a suppressions file entry
    screenshot: Optional[str] = None   # path (relative to output dir) of evidence image
    proof: Optional[dict] = None       # raw evidence exhibit (see proof.py)
    proof_image: Optional[str] = None  # PNG render of the proof (relative to output dir)

    def key(self) -> str:
        return f"{self.check_id}|{self.asset}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Asset:
    host: str
    ips: list = field(default_factory=list)
    cnames: list = field(default_factory=list)
    sources: set = field(default_factory=set)
    hosting: dict = field(default_factory=dict)   # ip -> {asn, org, cc, prefix, class}
    hosting_class: str = "unknown"                # owned | cloud | cdn | saas | unknown
    web: dict = field(default_factory=dict)       # url -> {status, final_url, server, title}
    explicit: bool = False                        # supplied by the operator
    screenshot: Optional[str] = None              # homepage thumbnail (relative to output dir)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sources"] = sorted(self.sources)
        return d


class ScanContext:
    """Shared state passed to every module."""

    def __init__(self, domain: str, cfg):
        self.domain = domain.lower().strip(".")
        self.cfg = cfg
        self.started = _dt.datetime.now(_dt.timezone.utc)
        self.findings: list[Finding] = []
        self.assets: dict[str, Asset] = {}
        self.module_status: dict[str, dict] = {}
        self.audit: list[str] = []
        self.software: list[dict] = []     # {asset, product, version, source}
        self.cves: dict[str, set] = {}     # cve -> set(assets)
        self.flags: dict[str, bool] = {}   # e.g. dns_failed, internetdb_ok, web_reached
        self._lock = threading.Lock()
        self._seen: dict[str, Finding] = {}

    # ---------------------------------------------------------------- findings
    def add(self, check_id: str, asset: str, evidence: str = "", *, severity: Optional[str] = None,
            title: Optional[str] = None, factor: Optional[str] = None, source: str = "",
            confidence: str = "firm", proof: Optional[dict] = None) -> None:
        meta = kb.get(check_id)
        f = Finding(
            check_id=check_id,
            factor=factor or meta["factor"],
            severity=severity or meta["severity"],
            asset=asset,
            title=title or meta["title"],
            evidence=(evidence or "")[:2000],
            source=source,
            confidence=confidence,
            third_party=self._is_third_party(asset),
            proof=proof,
        )
        with self._lock:
            k = f.key() + "|" + f.title
            if k in self._seen:
                old = self._seen[k]
                # A firm observation (e.g. live nmap) confirms an earlier tentative one (e.g. Shodan data)
                if old.confidence == "tentative" and confidence == "firm":
                    old.confidence = "firm"
                    old.source = f"{source}, {old.source}" if old.source else source
                    old.evidence = f.evidence or old.evidence
                    old.proof = f.proof or old.proof
                elif f.proof and not old.proof:
                    old.proof = f.proof
                return
            self._seen[k] = f
            self.findings.append(f)
        if f.severity != "pass":
            log.info("  [%s] %s — %s", f.severity.upper(), f.title, asset)

    def passed(self, check_id: str, asset: str, evidence: str = "", source: str = "") -> None:
        self.add(check_id, asset, evidence, severity="pass", source=source)

    def _is_third_party(self, asset: str) -> bool:
        a = self.assets.get(asset)
        return bool(a and a.hosting_class == "saas" and not a.explicit)

    def active_ok(self, host_or_ip: str) -> bool:
        """May an active check be sent to this host? In scope AND not a third-party SaaS host
        (unless the operator named it). Use it on the host actually contacted, e.g. after a redirect."""
        h = (host_or_ip or "").lower().strip(".")
        return bool(h) and self.in_scope(h) and not self._is_third_party(h)

    def active_urls(self, a) -> list[str]:
        """The asset's web URLs that active checks may contact. a.web also records where a homepage
        redirected to, which can be another organization's site or a SaaS sign-in page: those are
        dropped here, so every active module tests only hosts that are in scope."""
        from urllib.parse import urlparse
        if not self.active_ok(a.host):
            return []
        return [u for u in a.web if self.active_ok(urlparse(u).hostname or "")]

    def hosts_on_ip(self, ip: str) -> list[dict]:
        """The organization's hostnames that resolve to this IP, each with the site it serves
        (origin only, no path or query). Findings from IP-based sources (Shodan, nmap, CVE matches)
        use this to show which URLs are affected."""
        from urllib.parse import urlparse
        out = []
        for a in sorted(self.assets.values(), key=lambda a: a.host):
            if ip not in a.ips or a.host == ip or self._is_third_party(a.host):
                continue
            own = [urlparse(u) for u in a.web if (urlparse(u).hostname or "") == a.host]
            p = next((p for p in own if p.scheme == "https"), None) or (own[0] if own else None)
            out.append({"host": a.host, "url": f"{p.scheme}://{p.netloc}/" if p else None})
        return out

    @staticmethod
    def one_per_target(pairs) -> list[tuple[str, str]]:
        """(asset, target) pairs -> one pair per target, sorted. Two assets can lead to the same origin
        (one redirects to the other); it's tested once, under the asset whose host it is.
        A target is an origin (https://host:port) or host:port."""
        from urllib.parse import urlparse
        best: dict[str, str] = {}
        for asset, target in pairs:
            host = urlparse(target if "://" in target else "//" + target).hostname
            cur = best.get(target)
            if cur is None or (asset == host and cur != host):
                best[target] = asset
        return sorted((a, t) for t, a in best.items())

    # ------------------------------------------------------------------ assets
    def asset(self, host: str) -> Asset:
        host = host.lower().strip(".")
        with self._lock:
            if host not in self.assets:
                self.assets[host] = Asset(host=host)
            return self.assets[host]

    def all_ips(self) -> list[str]:
        ips = set()
        for a in self.assets.values():
            ips.update(a.ips)
        return sorted(ips, key=lambda x: (":" in x, x))

    def in_scope(self, host_or_ip: str) -> bool:
        """Active checks may only touch the target domain, its subdomains, operator-supplied
        hosts/URLs, or IPs inside operator-supplied ranges."""
        h = host_or_ip.lower().strip(".")
        if h == self.domain or h.endswith("." + self.domain):
            return h not in self.cfg.exclude
        a = self.assets.get(h)
        if a and a.explicit:
            return True
        try:
            ip = ipaddress.ip_address(h)
            return any(ip in net for net in self.cfg.ip_ranges)
        except ValueError:
            return False

    def audit_log(self, msg: str) -> None:
        line = f"{_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')} {msg}"
        with self._lock:
            self.audit.append(line)
        log.debug("AUDIT %s", msg)

    def remove(self, finding: Finding) -> None:
        with self._lock:
            self.findings = [f for f in self.findings if f is not finding]
            self._seen = {k: v for k, v in self._seen.items() if v is not finding}

    def record_software(self, asset: str, product: str, version: str, source: str, raw: str = "") -> None:
        with self._lock:
            entry = {"asset": asset, "product": product.lower(), "version": version, "source": source,
                     "raw": raw}
            if entry not in self.software:
                self.software.append(entry)

    def record_cve(self, cve: str, asset: str) -> None:
        with self._lock:
            self.cves.setdefault(cve.upper(), set()).add(asset)
