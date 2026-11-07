"""Deliberately misconfigured local web target for testing OpenScore end-to-end.

Starts:  HTTPS :8443 (self-signed, weak headers, exposed files)
         HTTP  :8080 (no HTTPS redirect)
         TCP   :6379 and :3389 dummy listeners (datastore / RDP exposure)
Usage:   python3 tests/fake_target.py
"""
import datetime as dt
import http.server
import os
import socket
import socketserver
import ssl
import tempfile
import threading
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FILES = {
    "/": (200, "text/html", "<html><head><title>Acme Portal</title><meta name='generator' content='WordPress 5.8.1'>"
          "<script src='http://cdn.example.net/jquery.js'></script></head><body>Welcome</body></html>"),
    "/.git/HEAD": (200, "text/plain", "ref: refs/heads/main\n"),
    "/.env": (200, "text/plain", "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n"),
    "/server-status": (200, "text/html", "<h1>Apache Server Status for localhost</h1>"),
    "/xmlrpc.php": (200, "text/plain", "XML-RPC server accepts POST requests only."),
}


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # Deliberately HTTP/1.0 with no Content-Length and no TLS close_notify, like many old appliances.
    # On Windows + Python 3.13 that EOF breaks plain requests.get(); the scanner must still read it
    # (util.get_tolerant). Don't "fix" this here: the Windows CI job is the regression test.
    def do_GET(self):
        code, ctype, body = FILES.get(self.path, (404, "text/html", "<html>Not found</html>"))
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "Apache/2.2.15 (CentOS)")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body.encode())


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def listener(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError as e:   # e.g. :3389 owned by Windows Remote Desktop on CI runners - it's open anyway
        print(f"tcp/{port}: not started ({e}); port is already in use", flush=True)
        return
    s.listen(50)
    while True:
        c, _ = s.accept()
        c.close()


def make_bad_cert(d):
    """Self-signed, RSA-1024, SHA-1, wrong hostname, expiring in 10 days — cross-platform (no openssl CLI)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong-host.invalid")])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
               .not_valid_after(now + dt.timedelta(days=10)))
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cert = builder.sign(key, hashes.SHA1())
    except Exception:  # newer cryptography builds refuse SHA-1
        cert = builder.sign(key, hashes.SHA256())
    kp, cp = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return kp, cp


def main():
    key, crt = make_bad_cert(tempfile.mkdtemp())
    https = TS(("127.0.0.1", 8443), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")  # allow the SHA-1 / 1024-bit cert to load
    except ssl.SSLError:
        pass
    ctx.load_cert_chain(crt, key)
    https.socket = ctx.wrap_socket(https.socket, server_side=True)
    http_ = TS(("127.0.0.1", 8080), H)
    for srv in (https, http_):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    for p in (6379, 3389):
        threading.Thread(target=listener, args=(p,), daemon=True).start()
    print("fake target up: https://127.0.0.1:8443  http://127.0.0.1:8080  tcp/6379 tcp/3389", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
