"""Corporate TLS inspection: data sources must keep working, inspection must be detected, and TLS
results that describe the proxy must not be reported as the target's.

Simulated with a local HTTPS server whose certificate is issued by a made-up "inspection CA" that
only the (patched) OS trust store contains, like a proxy root pushed to Windows by IT.
Run: python -m pytest tests/"""
import datetime as dt
import os
import socket
import ssl
import sys
import tempfile
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openscore import util  # noqa: E402
from openscore.models import ScanContext  # noqa: E402

CA_ORG = "Contoso TLS Inspection CA"


def _name(cn, org=None):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def _make_pki(d):
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("Inspection Root", CA_ORG)).issuer_name(_name("Inspection Root", CA_ORG))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(_name("localhost")).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            # Python 3.13+ verifies with VERIFY_X509_STRICT, which wants key identifiers (real CAs have them)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cert_path, key_path = os.path.join(d, "leaf.pem"), os.path.join(d, "leaf.key")
    with open(cert_path, "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return ca.public_bytes(serialization.Encoding.PEM).decode(), cert_path, key_path


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ports": []}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def proxy_site(monkeypatch):
    """HTTPS server on localhost signed by the 'inspection CA'; OS store patched to trust it."""
    d = tempfile.mkdtemp()
    ca_pem, cert_path, key_path = _make_pki(d)
    srv = HTTPServer(("127.0.0.1", 0), _H)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert_path, key_path)
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(util, "_os_root_pems", lambda: [ca_pem])
    monkeypatch.setattr(util, "_bundle_cache", [])
    yield srv.server_address[1]
    srv.shutdown()


def test_detects_inspection_and_names_the_issuer(proxy_site):
    r = util.detect_tls_inspection("localhost", proxy_site)
    assert r == {"intercepted": True, "issuer": CA_ORG}


def test_not_trusted_anywhere_is_not_called_inspection(proxy_site, monkeypatch):
    monkeypatch.setattr(util, "_os_root_pems", lambda: [])        # e.g. a broken site, not a proxy
    monkeypatch.setattr(util, "_bundle_cache", [])
    r = util.detect_tls_inspection("localhost", proxy_site)
    assert r["intercepted"] is None and r["issuer"] == CA_ORG


def test_unreachable_probe_is_unknown():
    with socket.socket() as s:                    # a port with nothing listening
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert util.detect_tls_inspection("127.0.0.1", port, timeout=2)["intercepted"] is None


def test_data_source_calls_work_behind_inspection(proxy_site, monkeypatch):
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    url = f"https://localhost:{proxy_site}/8.8.8.8"
    import certifi
    import requests
    with pytest.raises(requests.exceptions.SSLError):          # what happened on the work laptop
        requests.get(url, timeout=5, verify=certifi.where())
    s = util.make_session()
    assert s.verify != certifi.where() and os.path.isfile(s.verify)
    assert s.get(url, timeout=5).status_code == 200            # certifi + OS store


def test_user_ca_bundle_env_wins(monkeypatch):
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/some/corp-bundle.pem")
    assert util.make_session().verify is True                    # requests then reads the env var


def _ctx():
    cfg = types.SimpleNamespace(exclude=[], ip_ranges=[], hosts=[], urls=[], timeout=5, active=False,
                                delay=0, threads=2)
    ctx = ScanContext("example.com", cfg)
    ctx.session = util.make_session()
    return ctx


def test_tls_results_from_the_proxy_are_skipped(proxy_site):
    from openscore.modules import web
    ctx = _ctx()
    ctx.flags["tls_interceptor_org"] = CA_ORG
    assert web.tls_check(ctx, "localhost", proxy_site, "www.example.com") is True
    assert not [f for f in ctx.findings if f.source == "tls"]
    assert ctx.module_status["web"]["tls_intercepted"] == [f"localhost:{proxy_site}"]
    assert not ctx.flags.get("tls_real")


def test_tls_checks_still_run_without_inspection(proxy_site):
    from openscore.modules import web
    ctx = _ctx()                                              # no interceptor detected
    web.tls_check(ctx, "localhost", proxy_site, "www.example.com")
    assert ctx.flags.get("tls_real")
    assert any(f.check_id == "tls_cert_untrusted" for f in ctx.findings)   # public trust only


def test_source_failures_are_reported():
    ctx = _ctx()
    for _ in range(3):
        util.note_source_failure(ctx, "reputation", "shodan_internetdb", OSError("certificate verify failed"))
    assert ctx.module_status["reputation"]["shodan_internetdb"] == \
        "3 request(s) failed - OSError: certificate verify failed"


def test_tls_factor_not_graded_when_every_result_was_the_proxy():
    from openscore.cli import assessed_factors
    ctx = _ctx()
    ctx.flags.update(web_reached=True, tls_interceptor_org=CA_ORG)
    assert "tls" not in assessed_factors(ctx, {"web"})
    ctx.flags["tls_real"] = True                              # at least one host bypassed the proxy
    assert "tls" in assessed_factors(ctx, {"web"})
    ctx.flags.pop("tls_interceptor_org")
    assert "tls" in assessed_factors(ctx, {"web"})
