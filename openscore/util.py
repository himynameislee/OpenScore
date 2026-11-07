"""Shared helpers: HTTP session, DNS queries, subprocess, rate limiting."""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.exceptions import InsecureRequestWarning
    warnings.simplefilter("ignore", InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

log = logging.getLogger("openscore")

from . import REPO_URL, __version__

DEFAULT_UA = f"OpenScore/{__version__} (external security rating; +{REPO_URL})"


# ----------------------------------------------------------------------------- trust store
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
_LINUX_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                  "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem")
_bundle_cache: list = []


def _os_root_pems() -> list[str]:
    """Certificates the operating system trusts for TLS servers (incl. ones IT added)."""
    pems: list[str] = []
    if sys.platform == "win32":
        for store in ("ROOT", "CA"):
            try:
                items = ssl.enum_certificates(store)
            except Exception:
                continue
            for der, enc, trust in items:
                if enc == "x509_asn" and (trust is True or SERVER_AUTH in trust):
                    pems.append(ssl.DER_cert_to_PEM_cert(der))
        return pems
    paths = [ssl.get_default_verify_paths().cafile, *_LINUX_BUNDLES]
    for path in paths:
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    data = f.read()
            except OSError:
                continue
            pems += ["-----BEGIN CERTIFICATE-----" + c.split("-----END CERTIFICATE-----")[0]
                     + "-----END CERTIFICATE-----\n"
                     for c in data.split("-----BEGIN CERTIFICATE-----")[1:] if "-----END CERTIFICATE-----" in c]
            break
    return pems


def trust_bundle() -> str:
    """CA bundle for OpenScore's own data-source APIs (crt.sh, InternetDB, AbuseIPDB, endoflife.date,
    CISA KEV ...): Python's public list (certifi) plus what the OS trusts. Without the OS part these
    calls fail behind corporate TLS inspection (the proxy's root is in the Windows store, not in
    certifi) and whole factors silently go unassessed. Never used to judge a *target's* certificate:
    target checks use public trust only."""
    if _bundle_cache:
        return _bundle_cache[0]
    import certifi
    path = certifi.where()
    try:
        with open(path, encoding="utf-8") as f:
            base = f.read()
        norm = lambda p: "".join(p.split())          # noqa: E731
        known = {norm("-----BEGIN CERTIFICATE-----" + c) for c in base.split("-----BEGIN CERTIFICATE-----")[1:]}
        extra = [p for p in dict.fromkeys(_os_root_pems()) if norm(p) not in known]
        if extra:
            data = base.rstrip() + "\n\n# --- added from the operating system trust store ---\n" + "".join(extra)
            digest = hashlib.sha256(data.encode()).hexdigest()[:16]
            out = os.path.join(tempfile.gettempdir(), f"openscore-ca-{digest}.pem")
            if not os.path.exists(out):
                tmp = out + f".{os.getpid()}.tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(data)
                os.replace(tmp, out)
            log.debug("trust bundle: certifi + %d certificate(s) from the OS store", len(extra))
            path = out
    except Exception as e:                       # never let this break a scan
        log.debug("trust bundle: using certifi only (%s)", e)
    _bundle_cache.append(path)
    return path


def _issuer_org(der: bytes) -> str:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    name = x509.load_der_x509_certificate(der).issuer
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        vals = name.get_attributes_for_oid(oid)
        if vals:
            return str(vals[0].value)
    return name.rfc4514_string()


def issuer_org(der: bytes) -> str:
    """Organization (or CN) of a certificate's issuer."""
    try:
        return _issuer_org(der)
    except Exception:
        return ""


def detect_tls_inspection(host: str = "internetdb.shodan.io", port: int = 443, timeout: float = 8) -> dict:
    """Is this network re-signing HTTPS (corporate TLS inspection)? Probes a data source OpenScore
    uses anyway. Intercepted = the public site's certificate fails public trust but validates
    against a CA the OS added. Returns {"intercepted": True|False|None, "issuer": str}."""
    import certifi

    def handshake(ctx):
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as t:
                return t.getpeercert(binary_form=True)
    try:
        handshake(ssl.create_default_context(cafile=certifi.where()))
        return {"intercepted": False, "issuer": ""}
    except ssl.SSLCertVerificationError:
        pass
    except (OSError, ssl.SSLError) as e:
        return {"intercepted": None, "issuer": "", "error": f"{type(e).__name__}: {e}"}
    try:
        nc = ssl.create_default_context()
        nc.check_hostname, nc.verify_mode = False, ssl.CERT_NONE
        org = issuer_org(handshake(nc))
    except (OSError, ssl.SSLError) as e:
        return {"intercepted": None, "issuer": "", "error": f"{type(e).__name__}: {e}"}
    try:
        handshake(ssl.create_default_context(cafile=trust_bundle()))
        return {"intercepted": True, "issuer": org}
    except (OSError, ssl.SSLError):
        return {"intercepted": None, "issuer": org, "error": "certificate not trusted publicly or by this OS"}


def note_source_failure(ctx, module: str, source: str, err: Exception) -> None:
    """Count failures of a data source and keep the first error for the module notes, so a
    factor that couldn't be assessed says why instead of silently disappearing."""
    key = f"_fail_{module}_{source}"
    n = ctx.flags.get(key, 0) + 1
    ctx.flags[key] = n
    first = ctx.flags.setdefault(key + "_first", f"{type(err).__name__}: {err}"[:240])
    ctx.module_status.setdefault(module, {})[source] = f"{n} request(s) failed - {first}"


# ----------------------------------------------------------------------------- HTTP
def make_session(ua: str = DEFAULT_UA) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": ua, "Accept": "*/*"})
    adapter = HTTPAdapter(max_retries=1, pool_connections=32, pool_maxsize=32)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    # Data-source calls verify against public CAs + the OS store (works behind TLS inspection).
    # Requests to targets pass verify=False explicitly, so this doesn't affect them. An explicit
    # REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE from the user wins.
    if not (os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("CURL_CA_BUNDLE")):
        s.verify = trust_bundle()
    return s


def get_tolerant(session, url: str, max_bytes: int = 2_000_000, **kw) -> requests.Response:
    """GET that keeps the status, headers and whatever body arrived when a server ends the
    connection uncleanly (no Content-Length + TCP close without TLS close_notify). Old
    appliances do this a lot. Python 3.13 on Windows surfaces that EOF as a stray OSError
    (e.g. FileNotFoundError), which requests turns into ChunkedEncodingError and the whole
    response, headers included, is lost. Errors before the headers arrive still raise.
    The body is capped at max_bytes."""
    kw["stream"] = True
    r = session.get(url, **kw)
    buf = bytearray()
    clean = False
    try:
        while len(buf) < max_bytes:
            chunk = r.raw.read(min(65536, max_bytes - len(buf)), decode_content=True)
            if not chunk:
                clean = True
                break
            buf += chunk
    except Exception as e:
        log.debug("body of %s ended uncleanly after %d bytes: %s: %s", url, len(buf), type(e).__name__, e)
    finally:
        try:
            if clean:
                r.raw.release_conn()       # keep-alive still possible
            else:
                r.close()                  # unread data or broken connection: drop it
        except Exception:
            pass
    r._content = bytes(buf)
    r._content_consumed = True
    return r


class RateLimiter:
    """Minimum delay between requests to the same host (politeness for active checks)."""

    def __init__(self, delay: float):
        self.delay = delay
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, url_or_host: str) -> None:
        if self.delay <= 0:
            return
        host = urlparse(url_or_host).hostname or url_or_host
        with self._lock:
            now = time.monotonic()
            nxt = max(now, self._last.get(host, 0) + self.delay)
            self._last[host] = nxt
        sleep = nxt - time.monotonic()
        if sleep > 0:
            time.sleep(sleep)


# ------------------------------------------------------------------------------ DNS
class DNSResult:
    """status: ok | nxdomain | noanswer | error"""

    def __init__(self, status: str, records=None, error: str = ""):
        self.status = status
        self.records = records or []
        self.error = error

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def definitive_absent(self) -> bool:
        """True only when the DNS said 'no such record' — never on timeouts/network errors,
        so we don't report missing SPF/DMARC just because the resolver was unreachable."""
        return self.status in ("nxdomain", "noanswer")

    def __repr__(self):
        return f"DNSResult({self.status}, {self.records}, {self.error})"


class DNS:
    def __init__(self, nameservers=None, timeout: float = 5.0):
        self.r = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            self.r.nameservers = list(nameservers)
        self.r.lifetime = timeout
        self.r.timeout = timeout
        self._cache: dict = {}
        self._lock = threading.Lock()
        self._consec_errors = 0
        self._ever_ok = False

    @property
    def dead(self) -> bool:
        """Circuit breaker: resolver unreachable (several timeouts, never a good answer)."""
        return not self._ever_ok and self._consec_errors >= 4

    def query(self, name: str, rtype: str) -> DNSResult:
        key = (name.lower(), rtype)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            if self.dead:
                return DNSResult("error", error="resolver unreachable (circuit open)")
        res = self._query(name, rtype)
        with self._lock:
            if res.status == "error" and "SERVFAIL" not in res.error:
                self._consec_errors += 1
            else:
                self._consec_errors = 0
                self._ever_ok = True
            self._cache[key] = res
        return res

    def _query(self, name: str, rtype: str) -> DNSResult:
        try:
            ans = self.r.resolve(name, rtype, raise_on_no_answer=False)
            if ans.rrset is None:
                res = DNSResult("noanswer")
            else:
                recs = []
                for rr in ans:
                    if rtype == "TXT":
                        recs.append(b"".join(rr.strings).decode("utf-8", "replace"))
                    else:
                        recs.append(rr.to_text().rstrip("."))
                res = DNSResult("ok", recs)
        except dns.resolver.NXDOMAIN:
            res = DNSResult("nxdomain")
        except dns.resolver.NoAnswer:
            res = DNSResult("noanswer")
        except dns.resolver.NoNameservers as e:
            res = DNSResult("error", error=f"SERVFAIL/no nameservers: {e}")
        except (dns.exception.Timeout, dns.exception.DNSException, OSError) as e:
            res = DNSResult("error", error=str(e) or e.__class__.__name__)
        return res

    def txt(self, name: str) -> DNSResult:
        return self.query(name, "TXT")


# ----------------------------------------------------------------------- subprocess
def which(name: str):
    return shutil.which(name)


# Library-path variables PyInstaller points at its own unpacked bundle. A child program that
# inherits them loads the bundle's (older) libssl/libcrypto instead of the system's: the system
# openssl CLI then fails to start, and testssl.sh reports "cannot exec or find any openssl binary".
_BUNDLE_LIB_VARS = ("LD_LIBRARY_PATH", "LIBPATH", "DYLD_LIBRARY_PATH")


def child_env(environ=None, frozen=None) -> dict:
    """Environment for external tools (nmap, nuclei, subfinder, testssl.sh). From a PyInstaller
    binary, restore the library path the user had before the binary started (PyInstaller saves it
    as <VAR>_ORIG) or drop the variable if there was none."""
    env = dict(os.environ if environ is None else environ)
    if not (getattr(sys, "frozen", False) if frozen is None else frozen):
        return env
    for var in _BUNDLE_LIB_VARS:
        orig = env.pop(var + "_ORIG", None)
        if orig:
            env[var] = orig
        else:
            env.pop(var, None)
    return env


def loggable_url(url: str) -> str:
    """URL for the audit log: no query string or fragment (sign-in redirects carry one-time
    state/nonce/session values that don't belong in a log file)."""
    p = urlparse(url)
    return p._replace(query="", fragment="").geturl() + ("?…" if p.query else "")


def run(cmd: list[str], timeout: int = 600) -> tuple[int, str, str]:
    log.debug("exec: %s", " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env=child_env())
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except OSError as e:
        return -1, "", str(e)


def is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
