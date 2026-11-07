"""Offline tests: false-positive handling (suppressions, confidence upgrades, backport detection),
report helpers. Run: python -m pytest tests/  (or python tests/test_features.py)"""
import datetime as dt
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openscore import kb, report, scoring, suppress   # noqa: E402
from openscore.models import ScanContext           # noqa: E402
from openscore.modules import software             # noqa: E402


def make_ctx():
    cfg = types.SimpleNamespace(exclude=set(), ip_ranges=[], dkim_selectors=[], active=False, timeout=5)
    ctx = ScanContext("example.com", cfg)

    class S:
        headers = {"User-Agent": "t"}

        def get(self, *a, **k):
            raise OSError("offline")
    ctx.session = S()
    return ctx


def write_toml(text):
    fd, path = tempfile.mkstemp(suffix=".toml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def test_suppressions_apply_expire_unused_and_score():
    ctx = make_ctx()
    ctx.add("http_cookie_httponly", "app.example.com", "XSRF-TOKEN on https://app.example.com/")
    ctx.add("net_exposed_rdp", "203.0.113.5", "203.0.113.5:3389/tcp")
    ctx.add("exp_xmlrpc", "www.example.com")
    before = scoring.overall(ctx.findings, set(scoring.FACTORS))["score"]
    path = write_toml(f'''
[[suppress]]
check = "http_cookie_*"
asset = "*.example.com"
title_contains = "xsrf"
reason = "SPA must read CSRF cookie"

[[suppress]]
check = "net_exposed_rdp"
status = "compensating_control"
reason = "source-IP restricted"
expires = {(dt.date.today() + dt.timedelta(days=30)).isoformat()}

[[suppress]]
check = "exp_xmlrpc"
status = "accepted_risk"
reason = "old"
expires = 2020-01-01

[[suppress]]
check = "dns_caa_missing"
reason = "nothing matches"
''')
    rules = suppress.load(path)
    st = suppress.apply(ctx, rules)
    assert st["applied"] == 2, st
    assert len(st["expired"]) == 1 and "exp_xmlrpc" in st["expired"][0], st
    assert st["unused"] == ["#4 dns_caa_missing (*)"], st
    after = scoring.overall(ctx.findings, set(scoring.FACTORS))["score"]
    assert after > before
    assert next(f for f in ctx.findings if f.check_id == "exp_xmlrpc").suppression is None


def test_suppression_validation():
    bad = write_toml('[[suppress]]\ncheck = "x"\nreason = "r"\nstatus = "accepted_risk"\n')
    try:
        suppress.load(bad)
        raise AssertionError("accepted_risk without expires must be rejected")
    except ValueError:
        pass


def test_tentative_upgraded_by_live_confirmation():
    ctx = make_ctx()
    ctx.add("net_exposed_rdp", "203.0.113.5", "seen by Shodan", title="RDP (tcp/3389)",
            source="shodan-internetdb", confidence="tentative")
    ctx.add("net_exposed_rdp", "203.0.113.5", "nmap open", title="RDP (tcp/3389)", source="nmap")
    assert len(ctx.findings) == 1
    f = ctx.findings[0]
    assert f.confidence == "firm" and "nmap" in f.source, f


def test_distro_backport_marked_tentative():
    ctx = make_ctx()
    ctx.record_software("www.example.com", "php", "5.4.16", "http X-Powered-By", raw="PHP/5.4.16 (Red Hat)")
    ctx.record_software("old.example.com", "php", "5.6.40", "http X-Powered-By", raw="PHP/5.6.40")
    software.check_versions(ctx)
    by_asset = {f.asset: f for f in ctx.findings if f.check_id == "sw_eol"}
    assert by_asset["www.example.com"].confidence == "tentative"
    assert "backport" in by_asset["www.example.com"].evidence.lower()
    assert by_asset["old.example.com"].confidence == "firm"


def test_template_and_markdown():
    ctx = make_ctx()
    ctx.add("http_hsts_missing", "www.example.com", "https://www.example.com/")
    t = suppress.template(ctx.findings, "example.com")
    assert 'check = "http_hsts_missing"' in t
    html = report._md("Run `curl -sI https://x.example/` then see https://docs.example/a.")
    assert "<code>curl -sI https://x.example/</code>" in html          # no link inside code
    assert '<a href="https://docs.example/a">' in html                   # trailing '.' not in link



def test_html_report_dark_mode_toggle():
    ctx = make_ctx()
    ctx.cfg.client, ctx.cfg.authorization = "Example Inc", None
    ctx.add("http_hsts_missing", "www.example.com", "https://www.example.com/")
    result = report.build_result(ctx, set(scoring.FACTORS))
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "r.html")
        report.write_html(result, path)
        with open(path, encoding="utf-8") as f:
            html = f.read()
    assert 'id="theme-toggle"' in html
    # dark palette applies on screen only, so printed / PDF reports stay light
    assert "@media screen{:root[data-theme=dark]{" in html
    assert "@media print{.triage,#theme-toggle{display:none}}" in html
    # theme set in <head> before paint; storage access guarded (file:// / locked-down mail viewers)
    head = html.split("</head>")[0]
    assert 'setAttribute("data-theme"' in head and "prefers-color-scheme: dark" in head
    assert 'try{t=localStorage.getItem("openscore-theme")}catch(_){}' in head
    # no leftover hard-coded light backgrounds that would glare in dark mode
    style = html.split("<style>")[1].split("</style>")[0]
    for light in ("#eef2f6", "#f0f3f7", "#f0fff4", "#ebf8ff", "#fffbea", "#fffaf0"):
        assert style.count(light) == 1, light   # only as the light-theme variable value


def test_html_report_branding():
    from openscore import brand
    ctx = make_ctx()
    ctx.cfg.client, ctx.cfg.authorization = "Example Inc", None
    ctx.add("http_hsts_missing", "www.example.com", "https://www.example.com/")
    result = report.build_result(ctx, set(scoring.FACTORS))
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "r.html")
        report.write_html(result, path)
        with open(path, encoding="utf-8") as f:
            html = f.read()
    head = html.split("</head>")[0]
    assert '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,' in head
    body = html.split("<body", 1)[1]
    assert 'class="os-logo"' in body and 'aria-label="OpenScore"' in body
    # wordmark follows the theme (ink + accent are CSS variables, not hard-coded fills)
    assert "--logo-accent:#7C3AED" in html and "--logo-accent:#A78BFA" in html
    assert 'fill="#11151C"' not in body and 'fill="#7C3AED"' not in body
    assert "The attacker&#8217;s view" in html or "The attacker’s view" in html
    # embedded favicon stays in sync with the brand asset (docs/ absent in sdist/deb builds)
    src = os.path.join(os.path.dirname(__file__), "..", "docs", "brand", "favicon.svg")
    if os.path.exists(src):
        with open(src, encoding="utf-8") as f:
            assert f.read().strip() == brand.FAVICON_SVG.strip()


def test_https_fetch_failure_is_reported_not_silent():
    from openscore.modules import web
    import logging
    ctx = make_ctx()                      # session.get raises OSError("offline")
    ctx.asset("www.example.com")
    log = logging.getLogger("openscore")
    level, log.level = log.level, logging.ERROR     # expected warning; keep installer self-test output clean
    try:
        web.http_check(ctx, "www.example.com", "https://www.example.com/", None, tls_ok=True)
    finally:
        log.setLevel(level)
    notes = ctx.module_status["web"]["https_fetch_failed"]
    assert len(notes) == 1 and "https://www.example.com/" in notes[0] and "OSError: offline" in notes[0]
    assert "header checks skipped" in notes[0]


class _UncleanRaw:
    """Body arrives, then the read fails the way Python 3.13 on Windows reports a bare TLS EOF."""
    def __init__(self, data):
        self.data, self.closed = data, False

    def read(self, amt=None, decode_content=True):
        if self.data:
            n = len(self.data) if amt is None else amt
            out, self.data = self.data[:n], self.data[n:]
            return out
        raise FileNotFoundError(2, "No such file or directory")

    def release_conn(self):
        pass

    def close(self):
        self.closed = True


def _fake_resp(url, body, headers):
    import requests
    r = requests.models.Response()
    r.status_code, r.url, r.raw = 200, url, _UncleanRaw(body)
    r.headers.update(headers)
    return r


def test_get_tolerant_keeps_headers_and_body_on_unclean_close():
    from openscore import util
    body = b"<html><title>Acme Portal</title></html>"
    sess = types.SimpleNamespace(get=lambda url, **kw: _fake_resp(url, body, {"Content-Type": "text/html"}))
    r = util.get_tolerant(sess, "https://x.example/", timeout=5, verify=False)
    assert r.status_code == 200 and r.headers["Content-Type"] == "text/html"
    assert r.content == body and "Acme Portal" in r.text
    assert r.raw.closed                          # broken connection dropped, not returned to the pool
    capped = util.get_tolerant(sess, "https://x.example/", max_bytes=10)
    assert capped.content == body[:10]


def test_header_checks_run_despite_unclean_close():
    from openscore.modules import web
    ctx = make_ctx()
    ctx.asset("www.example.com")
    ctx.session.get = lambda url, **kw: _fake_resp(url, b"<html>hi</html>", {"Content-Type": "text/html"})
    web.http_check(ctx, "www.example.com", "https://www.example.com/", None, tls_ok=True)
    assert "http_hsts_missing" in {f.check_id for f in ctx.findings}
    assert "web" not in ctx.module_status          # not reported as a failed fetch


def _nmap_xml(ip, ports):
    rows = "".join(f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="{n}"/></port>'
                   for p, n in ports)
    return f'<nmaprun><host><address addr="{ip}"/><ports>{rows}</ports></host></nmaprun>'


def _patched(obj, **attrs):
    """Tiny stand-in for pytest's monkeypatch so these tests also run as a plain script
    (the installers run `python3 tests/test_features.py`)."""
    import contextlib

    @contextlib.contextmanager
    def cm():
        old = {k: getattr(obj, k) for k in attrs}
        for k, v in attrs.items():
            setattr(obj, k, v)
        try:
            yield
        finally:
            for k, v in old.items():
                setattr(obj, k, v)
    return cm()


def test_nmap_also_scans_high_risk_ports_outside_top_1000():
    from openscore import util
    from openscore.modules import ports
    ctx = make_ctx()
    ctx.cfg.full_ports = False
    calls = []

    def fake_run(cmd, timeout=600):
        calls.append(cmd)
        if "--top-ports" in cmd:                          # 6379 isn't in nmap's top 1000
            return 0, _nmap_xml("203.0.113.5", [(3389, "ms-wbt-server")]), ""
        return 0, _nmap_xml("203.0.113.5", [(3389, "ms-wbt-server"), (6379, "redis")]), ""
    with _patched(util, which=lambda name: "/usr/bin/" + name, run=fake_run):
        assert ports._nmap(ctx, ["203.0.113.5"]) is True
    assert len(calls) == 2
    spec = calls[1][calls[1].index("-p") + 1].split(",")
    for p in ("6379", "27017", "2375", "10250", "5985", "11211"):
        assert p in spec, p
    ids = [f.check_id for f in ctx.findings]
    assert "net_exposed_datastore" in ids
    assert ids.count("net_exposed_rdp") == 1               # seen in both passes, reported once
    assert sum("nmap" in a for a in ctx.audit) == 2         # both passes audit-logged


def test_nmap_full_ports_is_single_pass():
    from openscore import util
    from openscore.modules import ports
    ctx = make_ctx()
    ctx.cfg.full_ports = True
    calls = []
    fake = lambda cmd, timeout=600: calls.append(cmd) or (0, _nmap_xml("203.0.113.5", []), "")  # noqa: E731
    with _patched(util, which=lambda name: "/usr/bin/" + name, run=fake):
        assert ports._nmap(ctx, ["203.0.113.5"]) is True
    assert len(calls) == 1 and "-p-" in calls[0]



FAKE_NUCLEI = r"""
import json, sys, time
args = sys.argv[1:]
out = args[args.index("-o") + 1]
hang = "--hang" in open(args[args.index("-l") + 1], encoding="utf-8").read()
with open(out, "w", encoding="utf-8") as f:
    f.write(json.dumps({"template-id": "tech-detect", "matched-at": "https://www.example.com",
                        "info": {"name": "Tech", "severity": "info", "tags": ["tech"]}}) + "\n")
    f.write(json.dumps({"template-id": "exposed-panel", "matched-at": "https://www.example.com/admin",
                        "info": {"name": "Admin panel", "severity": "medium", "tags": ["panel"]}}) + "\n")
    f.flush()
    print(json.dumps({"percent": "42", "requests": "420", "total": "1000", "matched": "2",
                      "duration": "0:00:01"}), file=sys.stderr, flush=True)
    if hang:
        time.sleep(60)
"""


def _nuclei_ctx(timeout_min=60, hang=False):
    from openscore.modules import external_tools
    ctx = make_ctx()
    ctx.cfg.no_nuclei, ctx.cfg.nuclei_rate, ctx.cfg.nuclei_timeout = False, 30, timeout_min
    fd, script = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(FAKE_NUCLEI)
    root = "https://www.example.com" + ("/--hang" if hang else "")
    cmds = []

    def launcher(exe):
        cmds.append(exe)
        return [sys.executable, script]
    patches = _patched(external_tools, _launcher=launcher,
                       _web_roots=lambda c: [("www.example.com", root)])
    return ctx, patches, script


def _run_fake_nuclei(timeout_min=60, hang=False, interrupt_after=None):
    import _thread
    import threading
    from openscore import util
    from openscore.modules import external_tools
    ctx, patches, script = _nuclei_ctx(timeout_min, hang)
    t0 = __import__("time").time()
    try:
        with patches, _patched(util, which=lambda name: "nuclei"):
            if interrupt_after:
                threading.Timer(interrupt_after, _thread.interrupt_main).start()
            external_tools.nuclei(ctx)
    finally:
        os.unlink(script)
    return ctx, __import__("time").time() - t0


def test_nuclei_completes_and_skips_tech_fingerprints():
    from openscore.modules import external_tools
    assert "tech" not in external_tools.NUCLEI_TAGS.split(",")
    ctx, _ = _run_fake_nuclei()
    note = ctx.module_status["external_tools"]["nuclei"]
    assert note.startswith("completed; 1 findings"), note
    assert [f.title for f in ctx.findings if f.source == "nuclei"] == ["Admin panel"]


def test_nuclei_time_limit_keeps_partial_results():
    ctx, took = _run_fake_nuclei(timeout_min=0.05, hang=True)      # 3 s limit; fake runs 60 s
    note = ctx.module_status["external_tools"]["nuclei"]
    assert "minute limit" in note and "at 42%" in note and "partial results" in note, note
    assert any(f.title == "Admin panel" for f in ctx.findings)
    assert took < 30
    assert any("nuclei stopped after" in a for a in ctx.audit)


def test_nuclei_ctrl_c_stops_only_nuclei():
    ctx, took = _run_fake_nuclei(hang=True, interrupt_after=2)      # no KeyboardInterrupt escapes
    note = ctx.module_status["external_tools"]["nuclei"]
    assert note.startswith("stopped early (Ctrl+C) at 42%") and "partial results" in note, note
    assert any(f.title == "Admin panel" for f in ctx.findings)
    assert took < 30


def test_hosting_classification_real_world_cases():
    from openscore.modules.discovery import class_for_org as org, classify
    # Azure is the customer's own infrastructure (was wrongly "saas" -> excluded from score/scans)
    assert org("MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US") == "cloud"
    assert classify([], {"cloud"}) == "cloud"                                        # vpn/app on an Azure IP
    assert classify(["x.trafficmanager.net", "y.cloudapp.azure.com"], {"cloud"}) == "cloud"
    # Microsoft 365 is still SaaS, recognized by CNAME
    assert classify(["autodiscover.outlook.com", "autodiscover.geo.outlook.com"], {"cloud"}) == "saas"
    assert classify(["webdir.online.lync.com."], set()) == "saas"
    # Azure Front Door / CDN = edge
    assert classify(["ep-afd-x.a01.azurefd.net"], {"cloud"}) == "cdn"
    assert classify(["examplestatic.azureedge.net"], {"cloud"}) == "cdn"
    # Okta custom login domains sit on AWS IPs but Okta runs TLS/cookies (was "cloud" -> counted)
    for c in ("x.customdomains.okta.com", "x.customdomains.oktapreview.com", "x.customdomains.okta-dnssec.com"):
        assert classify([c], {"cloud"}) == "saas", c
    assert classify(["example.portals.safebase.io"], {"cdn"}) == "saas"
    assert classify(["okt.to"], {"cloud"}) == "saas"
    # email senders: never "owned" (that would put their IPs in the port scan)
    assert org("SENDGRID - SendGrid, Inc., US") == "saas"
    assert classify([], {org("SENDGRID - SendGrid, Inc., US")}) == "saas"
    # suffix matching, not substring
    assert classify(["notokta.com.example.net", "evil-outlook.com"], {"owned"}) == "owned"
    # first match wins
    assert org("AKAMAI CONNECTED CLOUD") == "cloud" and org("Akamai International B.V.") == "cdn"
    assert org("EXAMPLE-COLO - Example Hosting LLC, US") == "owned" and org("") == "unknown"
    assert classify([], set(), is_ip=True) == "owned"


def test_screenshots_skip_offsite_and_redact_audit_urls():
    from openscore.modules import screenshots
    ctx = make_ctx()
    ctx.cfg.max_screenshots = 10
    a = ctx.asset("ok.example.com")
    a.web["https://ok.example.com/"] = {"status": 200, "final_url": "https://www.oktopost.com/"}
    b = ctx.asset("portal.example.com")
    b.web["https://portal.example.com/"] = {"status": 200, "final_url": "https://portal.example.com/app"}
    urls = [j[1] for j in screenshots._plan(ctx)]
    assert urls == ["https://portal.example.com/app"]
    assert screenshots._loggable(
        "https://idp.example.com/authorize?client_id=1&state=abc&nonce=xyz#frag") == "https://idp.example.com/authorize?…"
    assert screenshots._loggable("https://www.example.com/") == "https://www.example.com/"


def test_triage_buttons_round_trip_through_suppressions():
    import datetime as dt
    from openscore import suppress
    ctx = make_ctx()
    ctx.cfg.client, ctx.cfg.authorization = "Example Inc", None
    ctx.add("http_hsts_missing", "www.example.com", "https://www.example.com/")
    result = report.build_result(ctx, set(scoring.FACTORS))
    f = next(x for x in result["findings"] if x["check_id"] == "http_hsts_missing")
    today = dt.date(2026, 11, 5)
    entries = {st: report._toml(f, st, today) for st in report.TRIAGE}
    assert "expires" not in entries["false_positive"]
    assert "expires = 2027-05-04" in entries["accepted_risk"]
    assert "expires = 2027-11-05" in entries["compensating_control"] and 'control = ""' in entries["compensating_control"]
    for st, text in entries.items():
        filled = text.replace('reason = ""', 'reason = "tested"', 1).replace('control = ""', 'control = "WAF rule 12"', 1)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.toml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(filled)
            rules = suppress.load(path)
        assert rules[0]["status"] == st
        c2 = make_ctx()
        c2.add("http_hsts_missing", "www.example.com", "https://www.example.com/")
        suppress.apply(c2, rules)
        sup = c2.findings[0].suppression
        assert sup and sup["status"] == st
        if st == "compensating_control":
            assert sup["control"] == "WAF rule 12"
            c2.cfg.client, c2.cfg.authorization = "Example Inc", None
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "r.html")
                report.write_html(report.build_result(c2, set(scoring.FACTORS)), out)
                with open(out, encoding="utf-8") as fh:
                    html = fh.read()
            assert "<b>Control:</b> WAF rule 12" in html and "compensating control" in html
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "r.html")
        report.write_html(result, out)
        with open(out, encoding="utf-8") as fh:
            html = fh.read()
    for label in ("False positive", "Accept risk", "Compensating control"):
        assert f'data-label="{label}"' in html, label
    assert "Mark false positive / accepted risk" not in html


def test_dangling_cname_claimability():
    from openscore.modules import discovery as d
    # whole-label suffix matching, not substrings
    assert d.takeover_service("x.github.io.attacker.example") is None
    assert d.takeover_service("Old.TrafficManager.net.")[1] == "Azure Traffic Manager"
    assert d.takeover_service("b.s3-website-us-east-1.amazonaws.com")[1] == "AWS S3 website"
    assert d.takeover_service("b.s3-website.eu-west-1.amazonaws.com")[1] == "AWS S3 website"
    assert d.claimable("old.trafficmanager.net", "trafficmanager.net") is True
    assert d.claimable("a.b.trafficmanager.net", "trafficmanager.net") is False
    assert d.claimable("gone.westeurope.cloudapp.azure.com", "cloudapp.azure.com") is True
    assert d.claimable("app-1a2b.eastus-01.azurewebsites.net", "azurewebsites.net") is False
    assert d.claimable("d111abcdef8.cloudfront.net", "cloudfront.net") is False
    assert d.claimable("help.zendesk.com", "zendesk.com") is None

    cases = {
        "tm.example.com": ("old.trafficmanager.net", "dns_dangling_cname", "high"),
        "tm2.example.com": ("a.b.trafficmanager.net", "dns_dangling_cname_stale", "low"),
        "vm.example.com": ("gone.westeurope.cloudapp.azure.com", "dns_dangling_cname", "high"),
        "app.example.com": ("app-1a2b.eastus-01.azurewebsites.net", "dns_dangling_cname_stale", "low"),
        "cdn.example.com": ("d111abcdef8.cloudfront.net", "dns_dangling_cname_stale", "low"),
        "help.example.com": ("help.zendesk.com", "dns_dangling_cname", "high"),
        "gh.example.com": ("x.github.io.attacker.example", "dns_dangling_cname_stale", "low"),
        "old.example.com": ("legacy.example-old.net", "dns_dangling_cname_stale", "low"),
    }
    from openscore.util import DNSResult

    class DNS:
        def query(self, name, rtype):
            for h, (t, _, _) in cases.items():
                if name == h and rtype == "CNAME":
                    return DNSResult("ok", [t])
            return DNSResult("nxdomain")
    ctx = make_ctx()
    ctx.dns = DNS()
    for h in cases:
        res = d._resolve(ctx, h)
        assert res["status"] == "dangling", res
        d._dangling(ctx, h, res["cnames"])
    got = {f.asset: (f.check_id, f.severity) for f in ctx.findings}
    assert got == {h: (c, sev) for h, (_, c, sev) in cases.items()}, got
    for f in ctx.findings:
        assert f.proof and f.proof["lines"], f
        meta = kb.get(f.check_id)
        assert meta["verify"] and meta["remediation"] and meta["description"]
    tm = next(f for f in ctx.findings if f.asset == "tm.example.com")
    assert any("check-dns --name old" in ln[0] for ln in tm.proof["lines"])


FAKE_TESTSSL = r"""
import json, sys, time
args = sys.argv[1:]
jf, tgt = args[args.index("--jsonfile") + 1], args[-1]
issue = {"id": "BREACH", "severity": "MEDIUM", "finding": "potentially VULNERABLE", "cve": "CVE-2013-3587"}
with open(jf, "w", encoding="utf-8") as f:
    if tgt.startswith("done"):
        json.dump([{"id": "TLS1_3", "severity": "OK", "finding": "offered"}, issue,
                   {"id": "scanTime", "severity": "INFO", "finding": "12"}], f)
    elif tgt.startswith("hang"):
        f.write('[\n  ' + json.dumps(issue) + ',\n  {"id": "TLS1_2", "sever')   # unclosed, like a killed run
        f.flush()
        if "trap" in tgt:     # real testssl.sh writes scanTime from its exit trap even when stopped
            f.write('ity": "OK", "finding": "offered"},\n  {"id": "scanTime", "severity": "INFO", "finding": "3"}\n]')
            f.flush()
        time.sleep(60)
    elif tgt.startswith("fail"):
        json.dump([{"id": "scanProblem", "severity": "FATAL", "finding": "Can't connect to fail:443"}], f)
        sys.exit(1)
"""


def _run_fake_testssl(hosts, timeout_min=5, interrupt_after=None):
    import _thread
    import threading
    from openscore import util
    from openscore.modules import external_tools
    ctx = make_ctx()
    ctx.cfg.no_testssl, ctx.cfg.testssl_timeout = False, timeout_min
    fd, script = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(FAKE_TESTSSL)
    targets = [(h.split(":")[0] + ".example.com", h) for h in hosts]
    t0 = __import__("time").time()
    try:
        with _patched(external_tools, _testssl_launcher=lambda exe: [sys.executable, script],
                      _testssl_targets=lambda c: targets), _patched(util, which=lambda name: "testssl.sh"):
            if interrupt_after:
                threading.Timer(interrupt_after, _thread.interrupt_main).start()
            external_tools.testssl(ctx)
    finally:
        os.unlink(script)
    return ctx, __import__("time").time() - t0


def test_testssl_progress_limit_and_failures_are_reported():
    ctx, took = _run_fake_testssl(["done:443", "hang:443", "fail:443", "hangtrap:443"], timeout_min=0.05)
    note = ctx.module_status["external_tools"]["testssl"]
    assert note.startswith("1/4 hosts completed; 3 issues"), note
    assert "hangtrap:443 stopped after" in note, note
    assert "hang:443 stopped after the 0.05-minute limit (--testssl-timeout) (1 partial issues kept)" in note, note
    assert "fail:443 exited with code 1, incomplete: Can't connect" in note, note
    breach = [f for f in ctx.findings if f.title == "TLS: BREACH"]
    assert len(breach) == 3, breach      # done + salvaged from both stopped runs
    assert any("testssl.sh hang:443 stopped" in a for a in ctx.audit)
    assert took < 45


def test_testssl_ctrl_c_skips_remaining_hosts():
    ctx, took = _run_fake_testssl(["hang:443", "done:443"], interrupt_after=2)
    note = ctx.module_status["external_tools"]["testssl"]
    assert note.startswith("0/2 hosts completed"), note
    assert "stopped early (Ctrl+C)" in note and "1 host(s) skipped (Ctrl+C)" in note, note
    assert took < 30


def test_testssl_json_salvage():
    from openscore.modules import external_tools
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "o.json")
        for text, n in (('[{"id": "a"}, {"id": "b"}]', 2), ('[\n {"id": "a"},\n {"id": "b"},\n', 2),
                        ('[\n {"id": "a"},\n {"id": "b', 1), ('[{"id": "a"}, {"x": }, {"id": "c"}]', 1),
                        ("", 0), ("[", 0), ("garbage", 0)):
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            assert len(external_tools._load_testssl_json(p)) == n, text


class _Resp:
    def __init__(self, code, text="", headers=None):
        self.status_code, self.text, self.headers = code, text, headers or {}


def _crtsh_with(responses):
    from openscore.modules import discovery as d
    ctx = make_ctx()
    calls = []

    def get(url, timeout=None):
        calls.append(url)
        r = responses[len(calls) - 1]
        if isinstance(r, Exception):
            raise r
        return r
    ctx.session = types.SimpleNamespace(get=get)
    with _patched(d, CRTSH_BACKOFF=(0, 0)):
        names = d._crtsh(ctx)
    return ctx, names, calls


def test_crtsh_retries_then_succeeds():
    ok = _Resp(200, '[{"name_value": "a.example.com\\n*.b.example.com"}]')
    ctx, names, calls = _crtsh_with([_Resp(503), _Resp(429, headers={"Retry-After": "0"}), ok])
    assert names == {"a.example.com", "b.example.com"} and len(calls) == 3
    assert "crt.sh" not in ctx.module_status.get("discovery", {})


def test_crtsh_failure_is_reported_in_notes_and_report():
    ctx, names, calls = _crtsh_with([_Resp(502), ValueError("not JSON"), _Resp(503)])
    assert names == set() and len(calls) == 3
    note = ctx.module_status["discovery"]["crt.sh"]
    assert "failed" in note and "HTTP 503" in note, note
    warn = report.coverage_warnings({"module_status": ctx.module_status})
    assert len(warn) == 1 and "common hostnames" in warn[0], warn
    # crt.sh answers 404 under load too (seen 11-07): retried like 429/5xx
    ctx, names, calls = _crtsh_with([_Resp(404), _Resp(404), _Resp(404)])
    assert len(calls) == 3 and "HTTP 404" in ctx.module_status["discovery"]["crt.sh"]
    # other client errors aren't retried
    ctx, names, calls = _crtsh_with([_Resp(403)])
    assert len(calls) == 1 and "HTTP 403" in ctx.module_status["discovery"]["crt.sh"]
    assert report.coverage_warnings({"module_status": {"tools": {"nmap": "found"}}}) == []


def test_httpapi_banner_is_not_iis_lifecycle():
    assert software._norm("Microsoft-HTTPAPI") is None and software._norm("microsoft-iis") == "iis"
    ctx = make_ctx()
    ctx.software = [{"product": "Microsoft-HTTPAPI", "version": "2.0", "asset": "app.example.com",
                     "source": "http Server", "raw": "Microsoft-HTTPAPI/2.0"},
                    {"product": "Microsoft-IIS", "version": "8.5", "asset": "old.example.com",
                     "source": "http Server", "raw": "Microsoft-IIS/8.5"}]
    with _patched(software, EOL=lambda c: None):
        software.check_versions(ctx)
    eol = {f.asset for f in ctx.findings if f.check_id == "sw_eol"}
    assert eol == {"old.example.com"}, eol


def test_distro_frozen_versions_get_a_note_not_a_downgrade():
    assert "RHEL 8" in software.frozen_note("Apache httpd", "2.4.37") and "rpm -q httpd" in \
        software.frozen_note("Apache httpd", "2.4.37")
    assert "dpkg -l openssh-server" in software.frozen_note("OpenSSH", "8.9p1")
    assert software.frozen_note("Apache httpd", "2.4.65") is None
    assert software.frozen_note("Microsoft-IIS", "10.0") is None
    ctx = make_ctx()
    ctx.software = [{"product": "Apache httpd", "version": "2.4.37", "asset": "203.0.113.5",
                     "source": "shodan", "raw": "Apache/2.4.37"}]
    ctx.cves = {"CVE-2021-40438": {"203.0.113.5"}, "CVE-2021-44790": {"203.0.113.5"}}

    class S:
        def get(self, url, params=None, timeout=None):
            if "epss" in url:
                return types.SimpleNamespace(json=lambda: {"data": [{"cve": "CVE-2021-44790", "epss": "0.9"}]})
            return types.SimpleNamespace(json=lambda: {"vulnerabilities": [
                {"cveID": "CVE-2021-40438", "vendorProject": "Apache", "product": "HTTP Server",
                 "vulnerabilityName": "SSRF"}]})
    ctx.session = S()
    software.check_cves(ctx)
    kev = next(f for f in ctx.findings if f.check_id == "vuln_kev")
    assert kev.severity == "critical" and kev.confidence == "tentative"      # unchanged
    assert "RHEL 8 ships" in kev.evidence and any("RHEL 8 ships" in ln[0] for ln in kev.proof["lines"])
    epss = next(f for f in ctx.findings if f.check_id == "vuln_high_epss")
    assert "RHEL 8 ships" in epss.evidence

if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
