"""TLS + HTTP checks ("light" — equivalent to a normal browser visit: TLS handshakes and
GET of the homepage / security.txt). CORS probing only runs in active mode."""
from __future__ import annotations

import datetime as dt
import logging
import re
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from .. import proof, util

log = logging.getLogger("openscore")
MODE = "light"

VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.\- ]*?)/(\d+(?:\.\d+){0,3}[a-z]?)")
EDGE_SIGS = [
    (r"/remote/login|fortinet|fortigate|fgt_lang", "Fortinet FortiGate SSL-VPN"),
    (r"/dana-na/|pulse secure|ivanti connect secure", "Ivanti/Pulse Connect Secure"),
    (r"citrix gateway|netscaler|/vpn/index\.html|/logon/logonpoint", "Citrix NetScaler Gateway"),
    (r"global-protect|globalprotect", "Palo Alto GlobalProtect"),
    (r"sonicwall|/sslvpnlogin|sonicui", "SonicWall"),
    (r"cisco asa|/\+cscoe\+/|anyconnect", "Cisco ASA/AnyConnect"),
    (r"sophos.*(user portal|webadmin)|/userportal/", "Sophos Firewall"),
    (r"watchguard|/auth/login\?from_page", "WatchGuard"),
    (r"/rdweb/|remote desktop web", "Microsoft RD Web Access"),
]


# ------------------------------------------------------------------------- TLS
def expiry_severity(days: int) -> str:
    """A certificate about to expire is an outage in waiting: high within a week, medium within
    two weeks, low within 30 days."""
    return "high" if days <= 7 else "medium" if days < 14 else "low"


def _handshake(host, port, sni, ctx_ssl, timeout=8):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx_ssl.wrap_socket(sock, server_hostname=sni) as s:
            return s.version(), s.cipher(), s.getpeercert(binary_form=True)



def _cert_time(cert, which: str):
    """Certificate validity as an aware UTC datetime. cryptography >= 42 has *_utc; older
    releases (Debian/Ubuntu LTS ship 41) only have the naive-UTC attribute."""
    v = getattr(cert, f"not_valid_{which}_utc", None)
    return v if v is not None else getattr(cert, f"not_valid_{which}").replace(tzinfo=dt.timezone.utc)

def _proto_supported(host, port, sni, version) -> "bool|None":
    try:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        c.minimum_version = version
        c.maximum_version = version
        try:
            c.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        _handshake(host, port, sni, c, timeout=6)
        return True
    except (ssl.SSLError, ConnectionResetError) as e:
        msg = str(e).lower()
        if "no protocols available" in msg or "unsupported protocol" in msg and "alert" not in msg:
            return None  # our local OpenSSL can't test it
        return False
    except (OSError, ValueError):
        return None


def _weak_ciphers(host, port, sni) -> "list|None":
    accepted = []
    for spec in ["3DES", "RC4", "NULL", "EXPORT", "aNULL", "DES", "kRSA"]:
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.maximum_version = ssl.TLSVersion.TLSv1_2
            c.set_ciphers(f"{spec}:@SECLEVEL=0")
        except (ssl.SSLError, ValueError):
            continue  # not compiled into local OpenSSL
        try:
            _, cipher, _ = _handshake(host, port, sni, c, timeout=6)
            accepted.append(f"{spec}: {cipher[0]}")
        except Exception:
            pass
    return accepted


def tls_check(ctx, host: str, port: int, asset: str) -> bool:
    sni = None if util.is_ip(host) else host
    target = f"{host}:{port}"
    nc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    nc.check_hostname = False
    nc.verify_mode = ssl.CERT_NONE
    try:
        version, cipher, der = _handshake(host, port, sni, nc)
    except (OSError, ssl.SSLError) as e:
        log.debug("TLS connect %s failed: %s", target, e)
        return False

    icpt = ctx.flags.get("tls_interceptor_org")
    if icpt and util.issuer_org(der) == icpt:
        # Corporate TLS inspection re-signed this connection: the certificate, protocols and ciphers
        # we'd see are the proxy's. HTTP checks still run (the proxy passes the site's headers).
        ctx.module_status.setdefault("web", {}).setdefault("tls_intercepted", []).append(target)
        return True
    ctx.flags["tls_real"] = True
    issues = False
    cert = x509.load_der_x509_certificate(der)
    now = dt.datetime.now(dt.timezone.utc)
    exp = _cert_time(cert, "after")
    days = (exp - now).days
    subj = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    info = f"{target}  subject={subj}  issuer={issuer}  expires={exp:%Y-%m-%d} ({days}d)  {version} {cipher[0]}"
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName)
    except Exception:
        sans = []
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        key_desc, weak_key = f"RSA {pk.key_size} bits", pk.key_size < 2048
    else:
        key_desc, weak_key = f"{pk.__class__.__name__.replace('_', '').replace('PublicKey', '')} " \
                             f"{getattr(pk, 'key_size', '')} bits".strip(), False
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    except Exception:
        sig = "unknown"

    # Trust / hostname validation with the system trust store
    verify_result, verify_kind = "OK — chains to a trusted root, hostname matches", None
    vc = ssl.create_default_context()
    if not sni:
        vc.check_hostname = False
    try:
        _handshake(host, port, sni, vc)
    except ssl.SSLCertVerificationError as e:
        code = getattr(e, "verify_code", None)
        msg = getattr(e, "verify_message", str(e))
        verify_result = f"FAILED — {msg} (code {code})"
        if code == 10 or "expired" in msg:
            verify_kind = "expired"
        elif code == 62 or "hostname mismatch" in msg.lower() or "doesn't match" in msg.lower():
            verify_kind = "mismatch"
        else:
            verify_kind = "untrusted"
    except (OSError, ssl.SSLError):
        verify_result = "not tested (connection error)"

    protos = {}
    for name, v in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
                    ("TLS 1.2", ssl.TLSVersion.TLSv1_2), ("TLS 1.3", ssl.TLSVersion.TLSv1_3)):
        protos[name] = _proto_supported(host, port, sni, v)
    weak = _weak_ciphers(host, port, sni)

    def exhibit(marks: dict, verdict: str) -> dict:
        """marks: {line-key: (mark, note)}"""
        rows = [
            ("proto", f"Negotiated : {version}  {cipher[0]}"),
            ("subject", f"Subject    : {subj}"),
            ("sans", f"SANs       : {', '.join(sans[:8]) or '(none)'}" + (" …" if len(sans) > 8 else "")),
            ("issuer", f"Issuer     : {issuer}"),
            ("from", f"Valid from : {_cert_time(cert, 'before'):%Y-%m-%d %H:%M} UTC"),
            ("to", f"Valid to   : {exp:%Y-%m-%d %H:%M} UTC  ({days} days {'ago' if days < 0 else 'left'})"),
            ("key", f"Public key : {key_desc}"),
            ("sig", f"Signature  : {sig}"),
            ("verify", f"Verify     : {verify_result}"),
            ("", ""),
        ]
        for pname, ok in protos.items():
            state = {True: "ACCEPTED", False: "rejected", None: "not testable from this client"}[ok]
            rows.append((pname, f"{pname:<10} : {state}"))
        for w in weak:
            rows.append(("weak", f"Weak cipher: {w}  ACCEPTED"))
        lines = [[text, *marks.get(key, (None, None))] for key, text in rows]
        return proof.make("TLS handshake & certificate", f"openssl s_client -connect {target}"
                          + (f" -servername {sni}" if sni else ""), lines, verdict)

    def add(check, ev, marks, verdict, **kw):
        nonlocal issues
        ctx.add(check, asset, ev, source="tls", proof=exhibit(marks, verdict), **kw)
        if check != "tls_no_tls13":
            issues = True

    if verify_kind == "mismatch":
        add("tls_cert_hostname_mismatch", f"{info}\n{verify_result}",
            {"sans": ("bad", f"{host} is not in this list"), "verify": ("bad", None)},
            f"Certificate is not valid for {host}")
    elif verify_kind == "untrusted":
        add("tls_cert_untrusted", f"{info}\n{verify_result}",
            {"verify": ("bad", None), "issuer": ("bad", "self-signed" if subj == issuer else "chain incomplete?")},
            "Browsers will show a certificate warning")
    if days < 0:
        add("tls_cert_expired", info, {"to": ("bad", "expired")}, f"Certificate expired {-days} days ago")
    elif days < 30:
        add("tls_cert_expiring", info, {"to": ("bad" if days < 14 else "warn", f"{days} days left")},
            f"Certificate expires in {days} days", severity=expiry_severity(days))
    if weak_key:
        add("tls_weak_key", f"{key_desc} — {target}", {"key": ("bad", "minimum is RSA 2048")},
            f"{key_desc} is below the 2048-bit minimum")
    if sig in ("sha1", "md5"):
        add("tls_sha1_sig", f"{sig} — {target}", {"sig": ("bad", "deprecated")}, f"Certificate signed with {sig}")
    old = [p for p in ("TLS 1.0", "TLS 1.1") if protos[p]]
    if old:
        add("tls_old_protocol", f"{target} accepts {', '.join(old)}",
            {p: ("bad", "deprecated (RFC 8996)") for p in old}, f"Server still accepts {' and '.join(old)}")
    if protos["TLS 1.3"] is False:
        add("tls_no_tls13", target, {"TLS 1.3": ("warn", None)}, "TLS 1.3 not offered")
    if weak:
        add("tls_weak_cipher", f"{target}\n" + "\n".join(weak), {"weak": ("bad", None)},
            f"{len(weak)} obsolete cipher suite(s) accepted")

    if not issues:
        ctx.passed("tls_ok", asset, info, source="tls")
    return True


# ------------------------------------------------------------------------ HTTP
def _cookies(resp) -> list[str]:
    out = []
    for r in list(resp.history) + [resp]:
        try:
            out += r.raw.headers.getlist("Set-Cookie")
        except Exception:
            v = r.headers.get("Set-Cookie")
            if v:
                out.append(v)
    return out


def _record_software(ctx, asset, headers, body):
    found = []
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator",
              "X-OWA-Version", "MicrosoftSharePointTeamServices"):
        v = headers.get(h)
        if not v:
            continue
        if h == "X-AspNet-Version":
            found.append(("asp.net", v, h, v))
        elif h == "X-OWA-Version":
            found.append(("exchange", v, h, v))
        elif h == "MicrosoftSharePointTeamServices":
            found.append(("sharepoint", v, h, v))
        else:
            for prod, ver in VERSION_RE.findall(v):
                found.append((prod.strip(), ver, h, v))
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body or "", re.I)
    if m:
        gm = re.match(r"([A-Za-z][A-Za-z .]+?)\s+v?(\d+(?:\.\d+)+)", m.group(1))
        if gm:
            found.append((gm.group(1).strip(), gm.group(2), "meta generator", m.group(1)))
    for prod, ver, src, raw in found:
        ctx.record_software(asset, prod, ver, f"http {src}", raw=raw)
    return found


def http_check(ctx, asset_name: str, https_url: str, http_url: str, tls_ok: bool,
               https_elsewhere: bool = False) -> None:
    s = ctx.session
    a = ctx.assets[asset_name]
    resp = None
    if tls_ok:
        try:
            resp = util.get_tolerant(s, https_url, timeout=ctx.cfg.timeout, verify=False, allow_redirects=True)
        except Exception as e:
            # TLS works but the page couldn't be fetched: every HTTP header check (HSTS, CSP, cookies,
            # CORS ...) is skipped for this URL. Say so in the report instead of looking "clean".
            why = f"{type(e).__name__}: {e}"[:300]
            log.warning("HTTPS fetch of %s failed - header checks skipped (%s)", https_url, why)
            ctx.module_status.setdefault("web", {}).setdefault("https_fetch_failed", []).append(
                f"{https_url} - {why} - HTTP header checks skipped")

    # HTTP → HTTPS redirect
    plain = None
    if http_url:
        try:
            plain = s.get(http_url, timeout=ctx.cfg.timeout, allow_redirects=False)
        except Exception:
            plain = None
    if plain is not None:
        loc = plain.headers.get("Location", "")
        if 300 <= plain.status_code < 400 and loc.lower().startswith("https://"):
            pass
        elif 300 <= plain.status_code < 400 and loc.startswith("/"):
            # relative redirect — follow once to see if it lands on https
            try:
                fin = s.get(http_url, timeout=ctx.cfg.timeout, allow_redirects=True, verify=False)
                if not fin.url.startswith("https://"):
                    ctx.add("http_no_redirect", asset_name, f"{http_url} → {fin.url}", source="http",
                            proof=proof.http(plain, url=http_url, mark={"location": ("bad", "redirects, but not to https")},
                                             verdict=f"Redirect chain ends on {fin.url}"))
            except Exception:
                pass
        elif resp is None and not https_elsewhere:
            ctx.add("tls_no_https", asset_name, f"{http_url} answered HTTP {plain.status_code}; HTTPS unavailable",
                    source="http", proof=proof.http(
                        plain, url=http_url, verdict=f"https://{asset_name}/ refused the TLS connection; "
                                                     "only plain HTTP is served"))
        else:
            ctx.add("http_no_redirect", asset_name, f"{http_url} → HTTP {plain.status_code} "
                    f"{('Location: ' + loc) if loc else '(no redirect)'}", source="http",
                    proof=proof.http(plain, url=http_url,
                                     mark={"location": ("bad", "not an https:// target")},
                                     missing=[] if loc else [("Location", "no redirect to https://")],
                                     verdict=f"Plain-HTTP request answered with {plain.status_code} instead of a "
                                             "301/308 redirect to HTTPS"))

    target = resp if resp is not None else plain
    if target is None:
        return
    ctx.flags["web_reached"] = True
    body = target.text[:300000] if "text" in target.headers.get("Content-Type", "") else ""
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    a.web[target.url] = {"status": target.status_code, "final_url": target.url,
                         "server": target.headers.get("Server", ""),
                         "title": (title.group(1).strip()[:120] if title else "")}

    # Fingerprint edge appliances / on-prem Exchange (high-value patching targets)
    blob = (target.url + " " + body[:50000]).lower()
    for pat, name in EDGE_SIGS:
        if re.search(pat, blob):
            ctx.add("edge_appliance_exposed", asset_name, f"{name} login page at {target.url}",
                    title=f"{name} exposed", source="http",
                    proof=proof.http(target, body_marks=[(pat, "bad", f"{name} fingerprint")],
                                     verdict=f"Page matches the {name} login portal fingerprint"))
            break
    if target.headers.get("X-OWA-Version") or "/owa/" in target.url.lower():
        ctx.add("exchange_onprem_exposed", asset_name,
                f"{target.url}  X-OWA-Version: {target.headers.get('X-OWA-Version', 'n/a')}", source="http",
                proof=proof.http(target, mark={"x-owa-version": ("bad", "on-prem Exchange build number")},
                                 verdict="Outlook Web App served from an on-premises Exchange server"))

    sw = _record_software(ctx, asset_name, target.headers, body)
    if sw:
        hdrs = {src.split()[-1].lower(): ("bad", "exact version disclosed") for _, _, src, _ in sw
                if src != "meta generator"}
        ctx.add("exp_version_disclosure", asset_name,
                "\n".join(f"{src}: {raw}" for p, v, src, raw in sw), source="http",
                proof=proof.http(target, mark=hdrs,
                                 body_marks=[(r'<meta[^>]+name=["\']generator', "bad", "version in page source")]
                                 if any(src == "meta generator" for _, _, src, _ in sw) else None,
                                 verdict="Version numbers: " + ", ".join(f"{p} {v}" for p, v, _, _ in sw)))

    if "<title>index of /" in body.lower():
        ctx.add("http_dir_listing", asset_name, target.url, source="http",
                proof=proof.http(target, body_marks=[(r"<title>Index of", "bad", "auto-generated listing"),
                                                     (r'<a href=', None, None)],
                                 verdict="Server returns an auto-generated directory index"))

    # Header checks only make sense on our own HTTPS responses
    final_host = (urlparse(target.url).hostname or "").lower()
    own = final_host == asset_name or final_host.endswith("." + ctx.domain) or final_host == ctx.domain
    if resp is None or not own or not target.url.startswith("https://"):
        if resp is not None and not own:
            a.web[target.url]["note"] = f"redirects off-site to {final_host}"
        return
    # Headers and cookies belong to the server that sent them. When the homepage redirects to another
    # of the organization's hosts (apex -> www, dashboard -> www), file the findings under that host,
    # so its hosting class (e.g. a SaaS site builder) decides scoring, and check each origin once.
    final = urlparse(resp.url)
    if final_host != asset_name and final_host in ctx.assets:
        asset_name = final_host
    if not _first_header_check(ctx, f"{final.scheme}://{final.netloc}"):
        return
    h = {k.lower(): v for k, v in resp.headers.items()}
    issues = False
    hsts = h.get("strict-transport-security")
    def hp(missing=None, mark=None, verdict=""):
        return proof.http(resp, missing=missing, mark=mark, verdict=verdict)
    if not hsts:
        ctx.add("http_hsts_missing", asset_name, resp.url, source="http",
                proof=hp([("Strict-Transport-Security", "required on HTTPS responses")],
                         verdict="No HSTS — browsers can be downgraded to HTTP")); issues = True
    else:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        if m and int(m.group(1)) < 15552000:
            ctx.add("http_hsts_short", asset_name, f"{resp.url}: {hsts}", source="http",
                    proof=hp(mark={"strict-transport-security": ("bad", f"max-age {m.group(1)}s < 180 days")},
                             verdict="HSTS lifetime too short")); issues = True
    csp = h.get("content-security-policy", "")
    if not csp:
        ctx.add("http_csp_missing", asset_name, resp.url, source="http",
                proof=hp([("Content-Security-Policy", "no XSS / injection policy")],
                         verdict="No Content-Security-Policy header")); issues = True
    if not h.get("x-frame-options") and "frame-ancestors" not in csp:
        ctx.add("http_xfo_missing", asset_name, resp.url, source="http",
                proof=hp([("X-Frame-Options", "page can be framed"),
                          ("Content-Security-Policy: frame-ancestors", "not set either")],
                         verdict="Page can be embedded in an attacker's iframe (clickjacking)")); issues = True
    if h.get("x-content-type-options", "").lower() != "nosniff":
        ctx.add("http_xcto_missing", asset_name, resp.url, source="http",
                proof=hp([("X-Content-Type-Options", "should be 'nosniff'")]
                         if "x-content-type-options" not in h else None,
                         mark={"x-content-type-options": ("bad", "should be 'nosniff'")},
                         verdict="MIME sniffing not disabled")); issues = True
    if not h.get("referrer-policy"):
        ctx.add("http_referrer_missing", asset_name, resp.url, source="http",
                proof=hp([("Referrer-Policy", "browser default applies")], verdict="No Referrer-Policy"))

    def cookie_proof(cname, note, verdict):
        def mk(v):
            return ("bad", note) if v.split("=", 1)[0].strip() == cname else None
        return proof.http(resp, mark={"set-cookie": mk}, verdict=verdict)

    for c in _cookies(resp):
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        sessiony = re.search(r"sess|auth|token|login|sid|jwt|asp\.net|phpsessid|jsessionid|\.aspxauth", name, re.I)
        if "secure" not in [p.strip() for p in low.split(";")]:
            ctx.add("http_cookie_insecure", asset_name, f"{name} on {resp.url}", source="http",
                    proof=cookie_proof(name, "no Secure flag", f"Cookie {name} can be sent over plain HTTP"))
            issues = True
        if sessiony and "httponly" not in low:
            ctx.add("http_cookie_httponly", asset_name, f"{name} on {resp.url}", source="http",
                    proof=cookie_proof(name, "no HttpOnly flag", f"JavaScript can read cookie {name}"))
            issues = True
        if "samesite" not in low:
            ctx.add("http_cookie_samesite", asset_name, f"{name} on {resp.url}", source="http",
                    proof=cookie_proof(name, "no SameSite attribute", f"Cookie {name} has no SameSite"))

    mixed = re.findall(r"<(?:script|link|iframe)[^>]+(?:src|href)=[\"'](http://[^\"']+)", body, re.I)
    if mixed:
        ctx.add("http_mixed_content", asset_name, f"{resp.url} loads insecure resources:\n" +
                "\n".join(sorted(set(mixed))[:10]), source="http",
                proof=proof.http(resp, body_marks=[(r"(src|href)=[\"']http://", "bad", "loaded over plain HTTP")],
                                 verdict=f"HTTPS page loads {len(set(mixed))} resource(s) over HTTP")); issues = True

    # The probe goes to the URL the homepage ended on, so both the asset and that final host must
    # be fair game: in scope and not a third-party SaaS host (e.g. a sign-in redirect to the IdP).
    if ctx.cfg.active and ctx.active_ok(asset_name) and ctx.active_ok(final.hostname or "") \
            and _first_cors_probe(ctx, f"{final.scheme}://{final.netloc}"):
        probe = "https://openscore-cors-probe.example"
        try:
            ctx.audit_log(f"CORS probe {util.loggable_url(resp.url)}")
            c = util.get_tolerant(s, resp.url, headers={"Origin": probe}, timeout=ctx.cfg.timeout, verify=False)
            acao = c.headers.get("Access-Control-Allow-Origin", "")
            acac = c.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            cors_marks = {"access-control-allow-origin": ("bad", "echoes the attacker's Origin")
                          if acao == probe else ("warn", "any origin"),
                          "access-control-allow-credentials": ("bad", "cookies included")}
            if acao == probe and acac:
                ctx.add("http_cors_reflect", asset_name, f"{resp.url} reflected Origin with credentials",
                        source="http", proof=proof.http(
                            c, req_headers={"Origin": probe}, mark=cors_marks,
                            verdict="An unrelated website can read authenticated responses"))
                issues = True
            elif acao == "*":
                ctx.add("http_cors_wildcard", asset_name, resp.url, source="http",
                        proof=proof.http(c, req_headers={"Origin": probe}, mark=cors_marks,
                                         verdict="CORS allows every origin"))
        except Exception:
            pass

    if not issues:
        ctx.passed("http_headers_ok", asset_name, resp.url, source="http")


_cors_lock = threading.Lock()


def _first_header_check(ctx, origin: str) -> bool:
    """Response headers, cookies and mixed content are judged once per origin, however many of the
    organization's hosts redirect there."""
    with _cors_lock:
        done = ctx.__dict__.setdefault("_headers_checked", set())
        if origin in done:
            return False
        done.add(origin)
        return True


def _first_cors_probe(ctx, origin: str) -> bool:
    """CORS policy is per origin: probe each origin once, even when several of a host's URLs
    (e.g. two sign-in paths) end up on it."""
    with _cors_lock:
        done = ctx.__dict__.setdefault("_cors_probed", set())
        if origin in done:
            return False
        done.add(origin)
        return True


def _endpoints(ctx, a):
    """Return list of (tls_host, tls_port, https_url, http_url)."""
    eps = []
    explicit = [u for u in a.web.keys()]
    if explicit:
        for u in explicit:
            p = urlparse(u)
            if p.scheme == "https":
                eps.append((p.hostname, p.port or 443, u, None))
            else:
                eps.append((None, None, None, u))
        return eps
    if util.is_ip(a.host):
        return []  # bare IPs: covered by port scan; avoids cert-mismatch noise
    return [(a.host, 443, f"https://{a.host}/", f"http://{a.host}/")]


def _check_asset(ctx, a):
    eps = _endpoints(ctx, a)
    # HTTPS endpoints first so we know whether the host offers HTTPS at all
    eps.sort(key=lambda e: e[0] is None)
    any_tls = False
    for tls_host, tls_port, https_url, http_url in eps:
        tls_ok = False
        if tls_host:
            try:
                tls_ok = tls_check(ctx, tls_host, tls_port, a.host)
            except Exception as e:
                log.debug("tls_check %s: %s", tls_host, e)
            any_tls |= tls_ok
        http_check(ctx, a.host, https_url, http_url, tls_ok, https_elsewhere=any_tls)


def run(ctx) -> None:
    targets = [a for a in list(ctx.assets.values()) if a.ips or a.web]
    log.info("Web/TLS checks on %d hosts", len(targets))
    with ThreadPoolExecutor(max_workers=ctx.cfg.threads) as ex:
        list(ex.map(lambda a: _check_asset(ctx, a), targets))

    # security.txt once for the organization
    for base in (f"https://{ctx.domain}", f"https://www.{ctx.domain}"):
        try:
            r = ctx.session.get(base + "/.well-known/security.txt", timeout=ctx.cfg.timeout, verify=False)
            if r.status_code == 200 and "contact:" in r.text.lower():
                return
        except Exception:
            continue
    if any(a.web for a in ctx.assets.values() if a.host in (ctx.domain, "www." + ctx.domain)):
        ctx.add("http_security_txt_missing", ctx.domain, source="http")
