"""Sensitive file / debug endpoint exposure (ACTIVE).

Each probe is a single GET of a well-known path, matched on *content signatures* (not just
HTTP 200) so soft-404 pages don't produce false positives. Nothing is submitted, no logins
are attempted, no payloads are sent.
"""
from __future__ import annotations

import logging
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urljoin, urlparse

from .. import proof, util

log = logging.getLogger("openscore")
SECRET_CHECKS = {"exp_env", "exp_aws_creds", "exp_config_backup", "exp_actuator"}
MODE = "active"

# (path, check_id, regex on body (or bytes prefix if startswith 'BYTES:'), max bytes)
PROBES = [
    ("/.git/HEAD", "exp_git", r"^ref: refs/|^[0-9a-f]{40}\s*$"),
    ("/.git/config", "exp_git", r"\[core\]"),
    ("/.svn/entries", "exp_svn", r"^\d+\s*$|dir\s*\n"),
    ("/.env", "exp_env", r"(?m)^(APP_KEY|DB_PASSWORD|DB_HOST|SECRET_KEY|AWS_SECRET|DATABASE_URL|MAIL_PASSWORD|API_KEY)\s*="),
    ("/.env.production", "exp_env", r"(?m)^(APP_KEY|DB_PASSWORD|SECRET_KEY|DATABASE_URL)\s*="),
    ("/.aws/credentials", "exp_aws_creds", r"aws_access_key_id"),
    ("/wp-config.php.bak", "exp_config_backup", r"DB_PASSWORD"),
    ("/wp-config.php~", "exp_config_backup", r"DB_PASSWORD"),
    ("/wp-config.php.save", "exp_config_backup", r"DB_PASSWORD"),
    ("/web.config.bak", "exp_config_backup", r"<configuration"),
    ("/config.php.bak", "exp_config_backup", r"<\?php"),
    ("/backup.sql", "exp_backup_archive", r"(INSERT INTO|CREATE TABLE)"),
    ("/dump.sql", "exp_backup_archive", r"(INSERT INTO|CREATE TABLE)"),
    ("/database.sql", "exp_backup_archive", r"(INSERT INTO|CREATE TABLE)"),
    ("/backup.zip", "exp_backup_archive", "BYTES:PK\x03\x04"),
    ("/site.zip", "exp_backup_archive", "BYTES:PK\x03\x04"),
    ("/www.zip", "exp_backup_archive", "BYTES:PK\x03\x04"),
    ("/backup.tar.gz", "exp_backup_archive", "BYTES:\x1f\x8b"),
    ("/.DS_Store", "exp_ds_store", "BYTES:\x00\x00\x00\x01Bud1"),
    ("/server-status", "exp_server_status", r"Apache Server Status"),
    ("/phpinfo.php", "exp_phpinfo", r"phpinfo\(\)|PHP Version </td>|<title>PHP \d"),
    ("/info.php", "exp_phpinfo", r"phpinfo\(\)|PHP Version </td>|<title>PHP \d"),
    ("/elmah.axd", "exp_debug_handler", r"Error Log for"),
    ("/trace.axd", "exp_debug_handler", r"Application Trace"),
    ("/actuator/env", "exp_actuator", r"propertySources|activeProfiles"),
    ("/actuator/heapdump", "exp_actuator", "BYTES:JAVA PROFILE"),
    ("/phpmyadmin/", "exp_admin_panel", r"phpMyAdmin"),
    ("/pma/", "exp_admin_panel", r"phpMyAdmin"),
    ("/adminer.php", "exp_admin_panel", r"Adminer"),
    ("/wp-json/wp/v2/users", "exp_wp_user_enum", r'"slug"\s*:'),
    ("/xmlrpc.php", "exp_xmlrpc", r"XML-RPC server accepts POST requests only"),
    ("/crossdomain.xml", "exp_crossdomain", r'domain="\*"'),
    ("/swagger.json", "exp_api_docs", r'"swagger"\s*:|"openapi"\s*:'),
    ("/openapi.json", "exp_api_docs", r'"openapi"\s*:'),
    ("/v2/api-docs", "exp_api_docs", r'"swagger"\s*:'),
    ("/owa/auth/logon.aspx", "exchange_onprem_exposed", r"Outlook|OwaPage|owa"),
]

EDGE_PATHS = [
    ("/remote/login", r"fortinet|fgt_lang|ftnt", "Fortinet FortiGate SSL-VPN"),
    ("/dana-na/auth/url_default/welcome.cgi", r"/dana-na/|pulse (connect )?secure|ivanti", "Ivanti/Pulse Connect Secure"),
    ("/vpn/index.html", r"citrix|netscaler", "Citrix NetScaler Gateway"),
    ("/global-protect/login.esp", r"globalprotect|global-protect", "Palo Alto GlobalProtect"),
    ("/+CSCOE+/logon.html", r"cisco|webvpn", "Cisco ASA/AnyConnect"),
    ("/RDWeb/", r"RD Web|Remote Desktop", "Microsoft RD Web Access"),
]


def strip_reflections(text: str, path: str) -> str:
    """Remove echoes of the requested path from a response body. Many apps put the requested URL
    back into the page (login redirects like os_destination=..., "destination":"/dana-na/...",
    error pages), and a signature must never match OpenScore's own probe path."""
    if not path or path == "/":
        return text
    variants = {path, quote(path, safe=""), quote(path, safe="/"), path.replace("/", "\\/"),
                path.replace("/", "&#x2F;"), path.replace("/", "&#47;"), path.replace("/", "\\u002f")}
    variants |= {v.rstrip("/") for v in variants if len(v.rstrip("/")) > 1}
    for v in sorted(variants, key=len, reverse=True):
        text = re.sub(re.escape(v), "", text, flags=re.I)
    return text


def _match(sig: str, resp, path: str = "") -> bool:
    if sig.startswith("BYTES:"):
        return resp.content[: len(sig) - 6] == sig[6:].encode("latin-1")
    ctype = resp.headers.get("Content-Type", "")
    if "image" in ctype:
        return False
    return re.search(sig, strip_reflections(resp.text[:200000], path), re.I | re.M) is not None


def _stripped_len(resp, path: str) -> int:
    try:
        return len(strip_reflections(resp.text, path).encode("utf-8", "replace"))
    except Exception:
        return len(resp.content)


def _get_in_scope(ctx, url: str, max_redirects: int = 3):
    """GET that follows redirects only to hosts active checks may touch; stops at the last
    in-scope response otherwise."""
    r = None
    for _ in range(max_redirects + 1):
        r = util.get_tolerant(ctx.session, url, timeout=ctx.cfg.timeout, verify=False, allow_redirects=False)
        loc = r.headers.get("Location") if r.is_redirect else None
        if not loc:
            return r
        nxt = urljoin(url, loc)
        if not ctx.active_ok(urlparse(nxt).hostname or ""):
            return r
        url = nxt
    return r


def _probe_base(ctx, asset: str, base: str) -> None:
    s = ctx.session
    # soft-404 baseline
    try:
        rnd_url = f"{base}/openscore-{uuid.uuid4().hex[:12]}"
        rnd = util.get_tolerant(s, rnd_url, timeout=ctx.cfg.timeout, verify=False, allow_redirects=False)
        rnd_path = urlparse(rnd_url).path
        soft404_len = _stripped_len(rnd, rnd_path) if rnd.status_code == 200 else None
        control = f"control: GET {rnd_url} → HTTP {rnd.status_code} ({len(rnd.content)} bytes)"
    except Exception:
        return
    for path, check_id, sig in PROBES:
        url = base + path
        ctx.limiter.wait(url)
        try:
            r = util.get_tolerant(s, url, max_bytes=512 * 1024,       # cap download
                                  timeout=ctx.cfg.timeout, verify=False, allow_redirects=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        if soft404_len is not None and abs(_stripped_len(r, path) - soft404_len) < 32 and not sig.startswith("BYTES:"):
            continue
        if _match(sig, r, path):
            ev = f"GET {url} → 200 ({len(r.content)} bytes)"
            secret = check_id in SECRET_CHECKS
            if secret:
                ev += "  [values masked in report]"
            pr = proof.body_excerpt(r, url, sig, secret, control)
            pr["verdict"] = f"{path} is publicly downloadable"
            ctx.add(check_id, asset, ev, source="exposures", proof=pr)
    for path, sig, name in EDGE_PATHS:
        url = base + path
        ctx.limiter.wait(url)
        try:
            r = _get_in_scope(ctx, url)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        final_path = urlparse(r.url or url).path
        body = strip_reflections(strip_reflections(r.text[:100000], path), final_path)
        if re.search(sig, body, re.I) and \
                (soft404_len is None or abs(_stripped_len(r, path) - soft404_len) >= 32):
            ctx.add("edge_appliance_exposed", asset, f"{name} at {url}", title=f"{name} exposed",
                    source="exposures", proof=proof.http(r, url=url, body_marks=[(sig, "bad", f"{name} fingerprint")],
                                                         verdict=f"{name} login portal reachable at {path}"))


def run(ctx) -> None:
    bases = []
    for a in ctx.assets.values():
        seen = set()
        for url in ctx.active_urls(a):
            p = urlparse(a.web[url].get("final_url") or url)
            if not ctx.active_ok(p.hostname or ""):
                p = urlparse(url)    # redirected off-scope or to a SaaS host: probe the original
            base = f"{p.scheme}://{p.netloc}"
            if base not in seen:
                seen.add(base)
                bases.append((a.host, base))
    bases = ctx.one_per_target(bases)
    log.info("Exposure probes on %d web roots (%d paths each)", len(bases), len(PROBES) + len(EDGE_PATHS))
    for asset, base in bases:
        ctx.audit_log(f"exposure probes {base} ({len(PROBES) + len(EDGE_PATHS)} GETs)")
    with ThreadPoolExecutor(max_workers=ctx.cfg.threads) as ex:
        list(ex.map(lambda ab: _probe_base(ctx, *ab), bases))
