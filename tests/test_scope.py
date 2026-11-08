"""Offline tests: active checks stay in scope, reflected probe paths don't create findings,
external tools get a clean environment from the release binary, and coverage gaps are reported.
Run: python -m pytest tests/  (or python tests/test_scope.py)"""
import contextlib
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests                                         # noqa: E402

from openscore import report, util                      # noqa: E402
from openscore.models import ScanContext                # noqa: E402
from openscore.modules import exposures, external_tools  # noqa: E402


def make_ctx(active=True):
    cfg = types.SimpleNamespace(exclude=set(), ip_ranges=[], dkim_selectors=[], active=active, timeout=5,
                                no_testssl=False, testssl_timeout=5, threads=2)
    ctx = ScanContext("example.com", cfg)
    ctx.session = types.SimpleNamespace(headers={"User-Agent": "t"})
    ctx.limiter = types.SimpleNamespace(wait=lambda url: None)
    return ctx


@contextlib.contextmanager
def patched(obj, **attrs):
    old = {k: getattr(obj, k) for k in attrs}
    for k, v in attrs.items():
        setattr(obj, k, v)
    try:
        yield
    finally:
        for k, v in old.items():
            setattr(obj, k, v)


def resp(url, body="", status=200, headers=None):
    r = requests.models.Response()
    r.status_code, r.url, r._content, r.encoding = status, url, body.encode("utf-8"), "utf-8"
    r.headers.update({"Content-Type": "text/html", **(headers or {})})
    return r


def _assets(ctx):
    """An owned host that redirects to another organization's site, a host that redirects to a
    SaaS sign-in page, the SaaS host itself, and a normal host."""
    own = ctx.asset("portal.example.com")
    own.hosting_class = "cloud"
    own.web = {"https://portal.example.com/": {"final_url": "https://www.other-company.example/"},
               "https://www.other-company.example/": {"final_url": "https://www.other-company.example/"}}
    app = ctx.asset("app.example.com")
    app.hosting_class = "cloud"
    app.web = {"https://app.example.com/": {"final_url": "https://login.example.com/app/home?session_hint=x"},
               "https://login.example.com/app/home?session_hint=x": {}}
    idp = ctx.asset("login.example.com")
    idp.hosting_class = "saas"
    idp.web = {"https://login.example.com/": {}, "https://tenant.idp-vendor.example/": {}}
    ok = ctx.asset("www.example.com")
    ok.hosting_class = "owned"
    ok.web = {"https://www.example.com/": {}, "http://www.example.com/": {}}


def test_active_modules_only_target_in_scope_hosts():
    ctx = make_ctx()
    _assets(ctx)
    assert ctx.active_ok("portal.example.com") and not ctx.active_ok("login.example.com")
    assert not ctx.active_ok("www.other-company.example") and not ctx.active_ok("")
    roots = external_tools._web_roots(ctx)
    hosts = {r.split("://")[1] for _, r in roots}
    assert hosts == {"portal.example.com", "app.example.com", "www.example.com"}, roots
    tls = {t for _, t in external_tools._testssl_targets(ctx)}
    assert tls == {"portal.example.com:443", "app.example.com:443", "www.example.com:443"}, tls
    # exposures: the redirect targets are never probed; the original URL is
    sent = []
    with patched(exposures, _probe_base=lambda c, asset, base: sent.append(base)), \
            patched(exposures, ThreadPoolExecutor=_Inline):
        exposures.run(ctx)
    assert set(sent) == {"https://portal.example.com", "https://app.example.com",
                         "https://www.example.com", "http://www.example.com"}, sent
    assert all("session_hint" not in a and "other-company" not in a for a in ctx.audit), ctx.audit
    # a name the operator supplied is always fair game, even on a SaaS host
    ctx.assets["login.example.com"].explicit = True
    assert ctx.active_ok("login.example.com")


class _Inline:
    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def map(self, fn, items):
        return [fn(i) for i in items]


def test_cors_probe_skips_saas_and_offsite_redirects_and_redacts_audit():
    from openscore.modules import web
    for start, final, expect in (
            ("app.example.com", "https://login.example.com/app/home?iss=x&session_hint=AUTH", False),
            ("portal.example.com", "https://www.other-company.example/", False),
            ("www.example.com", "https://www.example.com/start?next=%2Fhome", True)):
        ctx = make_ctx()
        _assets(ctx)
        probed = []

        def fake_get(session, url, **kw):
            if "Origin" in (kw.get("headers") or {}):
                probed.append(url)
            return resp(final, "<html><title>x</title></html>")
        with patched(util, get_tolerant=fake_get):
            web.http_check(ctx, start, f"https://{start}/", None, True)
        assert bool(probed) == expect, (start, final, probed)
        if expect:
            assert any(a.endswith("CORS probe https://www.example.com/start?…") for a in ctx.audit), ctx.audit
        assert all("session_hint" not in a and "next=" not in a for a in ctx.audit), ctx.audit


ATLASSIAN_LOGIN = ('<script>WRM._unparsedData["login-gateway-data"]="{\\u0022product\\u0022:\\u0022jira'
                   '\\u0022,\\u0022destination\\u0022:\\u0022{path}\\u0022}";</script>'
                   '<a class="aui-skip-link" href="/login.jsp?os_destination=https%3A%2F%2Fjira.example.com'
                   '{qpath}">Log in</a><a href="/login.jsp?os_destination={rawq}">Log In</a>'
                   '<p>Jira dashboard. Lots of other markup so the page is long enough.</p>' + "x" * 400)


def _atlassian(url):
    from urllib.parse import quote, urlparse
    path = urlparse(url).path
    return resp(url, ATLASSIAN_LOGIN.replace("{path}", path).replace("{qpath}", quote(path, safe=""))
                .replace("{rawq}", path))


def test_reflected_probe_path_is_not_an_appliance_or_exposure():
    ctx = make_ctx()
    with patched(util, get_tolerant=lambda s, url, **kw: _atlassian(url)):
        exposures._probe_base(ctx, "jira.example.com", "https://jira.example.com")
    assert not ctx.findings, [(f.check_id, f.title) for f in ctx.findings]


def test_real_appliance_and_exposure_still_found():
    pulse = ('<html><head><title>Ivanti Connect Secure</title><link href="/dana-na/css/ds.css"></head>'
             '<body>Welcome to Pulse Connect Secure</body></html>')

    def fake(s, url, **kw):
        if "welcome.cgi" in url:
            return resp(url, pulse)
        if url.endswith("/phpmyadmin/"):
            return resp(url, "<title>phpMyAdmin</title>" + "y" * 300)
        return resp(url, "not found", status=404)
    ctx = make_ctx()
    with patched(util, get_tolerant=fake):
        exposures._probe_base(ctx, "vpn.example.com", "https://vpn.example.com")
    got = {(f.check_id, f.title) for f in ctx.findings}
    assert ("edge_appliance_exposed", "Ivanti/Pulse Connect Secure exposed") in got, got
    assert any(c == "exp_admin_panel" for c, _ in got), got


def test_edge_probe_does_not_follow_redirects_out_of_scope():
    ctx = make_ctx()
    seen = []

    def fake(s, url, **kw):
        seen.append(url)
        assert kw.get("allow_redirects") is False
        if "welcome.cgi" in url:
            return resp(url, "", status=302, headers={"Location": "https://vendor-sso.example/dana-na/login"})
        return resp(url, "nope", status=404)
    with patched(util, get_tolerant=fake):
        exposures._probe_base(ctx, "vpn.example.com", "https://vpn.example.com")
    assert not any("vendor-sso" in u for u in seen), seen
    assert not ctx.findings


def test_strip_reflections_variants():
    p = "/global-protect/login.esp"
    body = ('a /global-protect/login.esp b %2Fglobal-protect%2Flogin.esp c \\/global-protect\\/login.esp '
            'd &#x2F;global-protect&#x2F;login.esp e %2fglobal-protect%2flogin.esp GlobalProtect Portal')
    out = exposures.strip_reflections(body, p)
    assert "global-protect" not in out.lower() and "GlobalProtect Portal" in out, out


def test_child_env_restores_library_path_for_release_binary():
    env = {"PATH": "/usr/bin", "LD_LIBRARY_PATH": "/tmp/_MEI123", "LD_LIBRARY_PATH_ORIG": "/opt/lib"}
    assert util.child_env(env, frozen=True)["LD_LIBRARY_PATH"] == "/opt/lib"
    out = util.child_env({"PATH": "/usr/bin", "LD_LIBRARY_PATH": "/tmp/_MEI123"}, frozen=True)
    assert "LD_LIBRARY_PATH" not in out and out["PATH"] == "/usr/bin"
    assert util.child_env(env, frozen=False) == env          # source installs: untouched
    assert "LD_LIBRARY_PATH_ORIG" not in util.child_env(env, frozen=True)


FAKE_TESTSSL_NO_OPENSSL = r"""
import sys
open(sys.argv[sys.argv.index("--jsonfile") + 1], "w").write("")
with open(sys.argv[0] + ".calls", "a") as f:
    f.write(sys.argv[-1] + "\n")
sys.exit(250)
"""


def test_testssl_stops_when_it_cannot_run_and_report_says_so():
    ctx = make_ctx()
    fd, script = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(FAKE_TESTSSL_NO_OPENSSL)
    targets = [(f"h{i}.example.com", f"h{i}.example.com:443") for i in range(5)]
    try:
        with patched(external_tools, _testssl_launcher=lambda exe: [sys.executable, script],
                     _testssl_targets=lambda c: targets), patched(util, which=lambda name: "testssl.sh"):
            external_tools.testssl(ctx)
        with open(script + ".calls", encoding="utf-8") as f:
            calls = f.read().split()
    finally:
        for p in (script, script + ".calls"):
            if os.path.exists(p):
                os.unlink(p)
    assert calls == ["h0.example.com:443"], calls          # not retried on the other 4 hosts
    note = ctx.module_status["external_tools"]["testssl"]
    assert note.startswith("could not run: testssl.sh can't use an openssl binary") and "0/5" in note, note
    warn = report.coverage_warnings({"module_status": ctx.module_status})
    assert len(warn) == 1 and warn[0].startswith("testssl.sh: didn't complete on any host"), warn


def test_coverage_gaps_for_rate_limits_partial_tools_and_crtsh_with_subfinder():
    ms = {"tools": {"subfinder": "found"},
          "discovery": {"crt.sh": "1 request(s) failed - RuntimeError: HTTP 404"},
          "reputation": {"greynoise": "rate limited (community API)", "seconds": 3.1},
          "external_tools": {"testssl": "0/3 hosts completed; 0 issues; 1.0 min; a:443 stopped after ...",
                             "nuclei": "stopped after the 60-minute limit (--nuclei-timeout); 10 findings"}}
    warn = report.coverage_warnings({"module_status": ms})
    text = " | ".join(warn)
    assert "relied on subfinder" in text and "only checked common hostnames" not in text, text
    assert "greynoise: rate limited" in text and "testssl.sh: didn't complete" in text, text
    assert "nuclei: stopped after the 60-minute limit" in text, text
    ok = {"external_tools": {"testssl": "3/3 hosts completed; 2 issues; 4.0 min", "nuclei": "completed; 5 findings"}}
    assert report.coverage_warnings({"module_status": ok}) == []


def test_nuclei_ignores_third_party_results_and_verify_names_template():
    from openscore import kb
    ctx = make_ctx()
    ctx.asset("www.example.com").hosting_class = "owned"
    lines = ['{"template-id": "azure-domain-tenant", "matched-at": "https://login.microsoftonline.com/x", '
             '"info": {"name": "Tenant", "severity": "info", "tags": ["azure"]}}',
             '{"template-id": "ssl-issuer", "matched-at": "tenant.idp-vendor.example:443", '
             '"info": {"name": "Issuer", "severity": "info", "tags": ["ssl"]}}',
             '{"template-id": "tomcat-stacktraces", "matched-at": "https://www.example.com/x", '
             '"info": {"name": "Tomcat Stack Traces", "severity": "low", "tags": ["misconfig"]}}']
    n = external_tools._ingest(ctx, lines, {"https://www.example.com": "www.example.com"})
    assert n == 1 and [f.asset for f in ctx.findings] == ["www.example.com"], ctx.findings
    assert ctx.flags["nuclei_offscope"] == 2
    f = ctx.findings[0].to_dict()
    v = report._verify(kb.get("nuclei_finding"), f, "example.com")
    assert "-id tomcat-stacktraces" in v and "<template-id>" not in v, v
    assert "azure-domain-tenant" in external_tools.NUCLEI_EXCLUDE_IDS
    assert external_tools._nuclei_concurrency(30) == 10 and external_tools._nuclei_concurrency(100) == 25
    assert external_tools._nuclei_concurrency(1000) == 50


def test_baseline_diff_ignores_info_findings():
    base = {"started": "2026-11-01T00:00:00", "overall": {"score": 80, "grade": "B"}, "findings": [
        {"check_id": "a", "asset": "h", "title": "A", "severity": "medium"}]}
    now = {"overall": {"score": 80, "grade": "B"}, "findings": [
        {"check_id": "a", "asset": "h", "title": "A", "severity": "medium"},
        {"check_id": "nuclei_finding", "asset": "h", "title": "SSL DNS Names", "severity": "info"}]}
    d = report.diff(now, base)
    assert d["new"] == [] and d["resolved"] == [], d


def test_baseline_diff_includes_vendor_hosted_and_flags_unlike_scans():
    base = {"started": "2026-11-07T15:20:00+00:00", "mode": "passive+light", "overall": {"score": 96, "grade": "A"},
            "assets": [{"host": "example.com"}],
            "findings": [{"check_id": "a", "asset": "example.com", "title": "A", "severity": "low"}]}
    now = {"mode": "active", "overall": {"score": 74, "grade": "C"},
           "assets": [{"host": f"h{i}.example.com"} for i in range(10)],
           "findings": [{"check_id": "b", "asset": "h1.example.com", "title": "B", "severity": "low"},
                        {"check_id": "c", "asset": "h2.example.com", "title": "C", "severity": "high"},
                        {"check_id": "w", "asset": "login.example.com", "title": "W", "severity": "medium",
                         "third_party": True}]}
    d = report.diff(now, base, "/tmp/reports/example.com-20261107-1520.json")
    assert [f["check_id"] for f in d["new"]] == ["c", "w", "b"], d["new"]     # vendor-hosted counts; by severity
    assert [f["check_id"] for f in d["resolved"]] == ["a"]
    assert d["baseline_file"] == "example.com-20261107-1520.json"
    assert any("passive+light mode" in c for c in d["caveats"]) and any("1 asset(s)" in c for c in d["caveats"])
    r = {"mode": "active", "assets": [{}] * 10, "overall": now["overall"], "findings": []}
    assert report.diff(r, dict(base, mode="active", assets=[{}] * 9))["caveats"] == []
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "r.html")
        ctx = make_ctx()
        ctx.cfg.client, ctx.cfg.authorization = "Example", "t"
        ctx.asset("www.example.com").hosting_class = "owned"
        res = report.build_result(ctx, {"tls"})
        report.write_html(res, p, d)
        page = open(p, encoding="utf-8").read()
    assert "example.com-20261107-1520.json" in page and "Not a like-for-like comparison" in page


def test_cors_probe_once_per_origin():
    from openscore.modules import web
    ctx = make_ctx()
    assert web._first_cors_probe(ctx, "https://app.example.com")
    assert not web._first_cors_probe(ctx, "https://app.example.com")
    assert web._first_cors_probe(ctx, "https://www.example.com")


def test_testssl_rows_already_covered_are_skipped_and_heuristics_are_tentative():
    ctx = make_ctx()
    ctx.asset("www.example.com").hosting_class = "owned"
    rows = [
        {"id": "cert_expirationStatus", "severity": "HIGH", "finding": "expires < 30 days (0)"},
        {"id": "cert_notAfter <hostCert#1>", "severity": "HIGH", "finding": "2026-01-01 23:59"},
        {"id": "cert_trust", "severity": "HIGH", "finding": "certificate does not match supplied URI"},
        {"id": "DNS_CAArecord", "severity": "LOW", "finding": "--"},
        {"id": "OCSP_stapling", "severity": "LOW", "finding": "not offered"},
        {"id": "cert_trust_wildcard", "severity": "LOW", "finding": "trust is via wildcard"},
        {"id": "BREACH", "severity": "MEDIUM", "finding": "potentially VULNERABLE, gzip HTTP compression detected",
         "cve": "CVE-2013-3587"},
        {"id": "LUCKY13", "severity": "LOW", "finding": "potentially vulnerable, uses obsolete TLS CBC ciphers"},
        {"id": "ROBOT", "severity": "HIGH", "finding": "VULNERABLE (NOT ok)"},
        {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
        {"id": "BEAST_CBC_TLS1", "severity": "MEDIUM", "finding": "ECDHE-RSA-AES128-SHA"},
        {"id": "BEAST", "severity": "LOW", "finding": "VULNERABLE -- but also supports higher protocols"},
        {"id": "scanTime", "severity": "WARN", "finding": "30"},
    ]
    n, dup = external_tools._ingest_testssl(ctx, "www.example.com", "www.example.com:443", rows)
    assert (n, dup) == (7, 5), (n, dup)
    by_title = {f.title: f for f in ctx.findings}
    assert not any("cert_" in t and "wildcard" not in t for t in by_title) and "TLS: DNS_CAArecord" not in by_title
    assert by_title["TLS: OCSP_stapling"].severity == "info"
    assert by_title["TLS: cert_trust_wildcard"].severity == "info"
    assert by_title["TLS: BREACH"].confidence == "tentative" and by_title["TLS: BREACH"].severity == "medium"
    assert by_title["TLS: LUCKY13"].confidence == "tentative"
    assert by_title["TLS: ROBOT"].confidence == "firm" and by_title["TLS: ROBOT"].severity == "high"
    assert any(f.check_id == "tls_old_protocol" for f in ctx.findings)
    assert "TLS: BEAST" in by_title and "TLS: BEAST_CBC_TLS1" not in by_title


def test_each_origin_is_tested_once_under_its_own_asset():
    """A homepage redirect to a sibling host that's also an asset: probe that host once, as itself."""
    ctx = make_ctx()
    sib = ctx.asset("app.example.com")
    sib.hosting_class = "cloud"
    sib.web = {"https://app.example.com/": {"final_url": "https://app.example.com/login"}}
    old = ctx.asset("old.example.com")
    old.hosting_class = "cloud"
    old.web = {"https://old.example.com/": {"final_url": "https://app.example.com/login"},
               "https://app.example.com/login": {}}
    tls = external_tools._testssl_targets(ctx)
    assert tls == [("app.example.com", "app.example.com:443"), ("old.example.com", "old.example.com:443")], tls
    roots = external_tools._web_roots(ctx)
    assert roots == [("app.example.com", "https://app.example.com"),
                     ("old.example.com", "https://old.example.com")], roots
    sent = []
    with patched(exposures, _probe_base=lambda c, asset, base: sent.append((asset, base))), \
            patched(exposures, ThreadPoolExecutor=_Inline):
        exposures.run(ctx)
    assert sent == [("app.example.com", "https://app.example.com")], sent   # old.* ends up on app.*
    assert sum("exposure probes" in a for a in ctx.audit) == 1, ctx.audit


def test_ip_findings_show_the_sites_on_that_ip():
    ctx = make_ctx()
    ctx.cfg.client, ctx.cfg.authorization = "Example", "test"
    a = ctx.asset("app.example.com")
    a.ips, a.hosting_class = ["203.0.113.5"], "owned"
    a.web = {"https://app.example.com/": {"final_url": "https://app.example.com/login?next=x"},
             "https://app.example.com/login?next=x": {}, "http://app.example.com/": {}}
    b = ctx.asset("mail.example.com")
    b.ips, b.hosting_class = ["203.0.113.5"], "owned"            # no website
    s = ctx.asset("crm.example.com")
    s.ips, s.hosting_class = ["203.0.113.5"], "saas"             # vendor-hosted: listed too
    ctx.asset("203.0.113.5").hosting_class = "owned"
    assert ctx.hosts_on_ip("203.0.113.5") == [{"host": "app.example.com", "url": "https://app.example.com/"},
                                              {"host": "crm.example.com", "url": None},
                                              {"host": "mail.example.com", "url": None}]
    ctx.add("vuln_high_epss", "203.0.113.5", "CVE-2021-44790", title="1 CVE(s) with high exploit probability",
            confidence="tentative")
    ctx.add("tls_testssl", "app.example.com", "x", severity="medium", title="TLS: BREACH")
    ctx.add("tls_testssl", "app.example.com", "x", severity="high", title="TLS: ROBOT")
    r = report.build_result(ctx, {"patching", "tls"})
    f = next(x for x in r["findings"] if x["asset"] == "203.0.113.5")
    assert [h["host"] for h in f["hosts"]] == ["app.example.com", "crm.example.com", "mail.example.com"], f
    assert "hosts" not in next(x for x in r["findings"] if x["asset"] == "app.example.com")
    assert "next=x" not in str(r["ip_hosts"])
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "r.html")
        report.write_html(r, p)
        page = open(p, encoding="utf-8").read()
    assert 'sites on this IP:</span> <a href="https://app.example.com/">' in page, page[:200]
    assert "203.0.113.5 (app.example.com +2)" in page
    # "fixing the top items" removes exactly the listed issues (check + title), not every testssl row
    only_robot = dict(r, quick_wins=[w for w in r["quick_wins"] if w["title"] == "TLS: ROBOT"])
    both = dict(r, quick_wins=[w for w in r["quick_wins"] if w["check_id"] == "tls_testssl"])
    assert report.summary_sentence(only_robot) != report.summary_sentence(both)


def test_certificate_expiry_severity_and_priority_fixes_split_by_title():
    from openscore import scoring
    from openscore.modules import web
    assert [web.expiry_severity(d) for d in (0, 7, 8, 13, 14, 29)] == \
        ["high", "high", "medium", "medium", "low", "low"]
    ctx = make_ctx()
    for h in ("a.example.com", "b.example.com"):
        ctx.asset(h).hosting_class = "owned"
        ctx.add("tls_testssl", h, "x", severity="medium", title="TLS: BREACH")
        ctx.add("tls_testssl", h, "x", severity="low", title="TLS: LUCKY13")
    wins = scoring.quick_wins(ctx.findings, {"tls"})
    assert sorted(w["title"] for w in wins) == ["TLS: BREACH", "TLS: LUCKY13"], wins
    assert all(len(w["assets"]) == 2 for w in wins), wins



def test_saas_ranges_announced_by_a_cdn_are_saas():
    """A SaaS-hosted root domain has no CNAME, only A/AAAA records into the provider's range, which
    another network may announce (HubSpot's 199.60.103.0/24 via a Cloudflare ASN)."""
    from openscore.modules import discovery
    from openscore.util import DNSResult
    assert discovery.saas_provider_for_ip("199.60.103.28") == "HubSpot"
    assert discovery.saas_provider_for_ip("2606:2c40::c73c:671c") == "HubSpot"
    assert discovery.saas_provider_for_ip("199.60.104.28") == ""
    assert discovery.saas_provider_for_ip("not-an-ip") == ""

    answers = {"28.103.60.199.origin.asn.cymru.com": ["209242 | 199.60.103.0/24 | US | arin | 2015-01-01"],
               "AS209242.asn.cymru.com": ["209242 | US | ripencc | 2015-01-01 | CLOUDFLARESPECTRUM - Cloudflare London, LLC, US"],
               "1.1.0.192.origin.asn.cymru.com": ["13335 | 192.0.1.0/24 | US | arin | 2010-01-01"],
               "AS13335.asn.cymru.com": ["13335 | US | arin | 2010-01-01 | CLOUDFLARENET - Cloudflare, Inc., US"]}
    ctx = make_ctx(active=False)
    ctx.dns = types.SimpleNamespace(txt=lambda q: DNSResult("ok", answers[q]) if q in answers
                                    else DNSResult("nxdomain"))
    hub = discovery._asn(ctx, "199.60.103.28")
    assert hub["class"] == "saas" and hub["provider"] == "HubSpot" and "Cloudflare" in hub["org"], hub
    assert discovery._asn(ctx, "192.0.1.1")["class"] == "cdn"                 # a real CDN customer stays cdn
    assert discovery._asn(ctx, "199.60.103.128") == {"class": "saas", "provider": "HubSpot"}   # no ASN answer
    assert discovery.classify([], {"saas"}) == "saas"


def test_header_findings_belong_to_the_host_that_sent_them():
    """apex -> www (SaaS site builder) and dashboard -> www: the missing headers are www's, filed once,
    under www (scored, labeled with the vendor); the apex and dashboard get nothing."""
    from openscore.modules import web
    ctx = make_ctx(active=False)
    for h, cls in (("example.com", "owned"), ("www.example.com", "saas"), ("dashboard.example.com", "owned")):
        ctx.asset(h).hosting_class = cls
    bare = {"Content-Type": "text/html", "Set-Cookie": "sid=1; Path=/"}

    def fake_get(session, url, **kw):
        return resp("https://www.example.com/", "<html><title>x</title></html>", headers=bare)
    with patched(util, get_tolerant=fake_get):
        for start in ("example.com", "dashboard.example.com", "www.example.com"):
            web.http_check(ctx, start, f"https://{start}/", None, True)
    hdr = [f for f in ctx.findings if f.check_id.startswith("http_") and f.check_id != "http_no_redirect"]
    assert hdr and {f.asset for f in hdr} == {"www.example.com"}, [(f.check_id, f.asset) for f in hdr]
    assert all(f.third_party for f in hdr)
    assert len(hdr) == len({f.check_id for f in hdr}), "each header issue reported once"
    # a host that serves its own page still gets its own findings
    ctx2 = make_ctx(active=False)
    ctx2.asset("app.example.com").hosting_class = "owned"
    with patched(util, get_tolerant=lambda s, url, **kw: resp("https://app.example.com/login", "<html></html>",
                                                              headers=bare)):
        web.http_check(ctx2, "app.example.com", "https://app.example.com/", None, True)
    assert {f.asset for f in ctx2.findings if f.check_id == "http_xfo_missing"} == {"app.example.com"}


def test_mta_sts_finding_names_the_domains_own_mx_hosts():
    from openscore import kb
    from openscore.modules import dns_email
    from openscore.util import DNSResult
    ctx = make_ctx(active=False)
    recs = {("example.com", "MX"): ["10 mxa-001.gslb.pphosted.example.", "10 mxb-001.gslb.pphosted.example."]}
    ctx.dns = types.SimpleNamespace(
        dead=False, query=lambda n, t: DNSResult("ok", recs[(n, t)]) if (n, t) in recs else DNSResult("nxdomain"),
        txt=lambda n: DNSResult("nxdomain"))
    ctx.session = types.SimpleNamespace(headers={}, get=lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    dns_email.run(ctx)
    f = next(f for f in ctx.findings if f.check_id == "email_mtasts_missing")
    assert "mxa-001.gslb.pphosted.example, mxb-001.gslb.pphosted.example" in f.evidence, f.evidence
    assert "mx: *.mail.protection.outlook.com`, `max_age" not in kb.CHECKS["email_mtasts_missing"]["remediation"]


def test_vendor_hosted_findings_are_scored_and_labeled():
    """Findings on SaaS/CDN-hosted hosts count like any other; the report names the vendor and says
    where the fix lives. No separate 'excluded' section."""
    from openscore import scoring
    from openscore.modules import discovery
    ctx = make_ctx(active=False)
    ctx.cfg.client, ctx.cfg.authorization = "Example", ""
    www = ctx.asset("www.example.com")
    www.hosting_class, www.cnames = "saas", ["1234.group27.sites.hubspot.net."]
    own = ctx.asset("app.example.com")
    own.hosting_class = "owned"
    ctx.add("http_xfo_missing", "www.example.com", "https://www.example.com/")
    assert ctx.findings[0].third_party                                # still flagged as vendor-hosted
    assert scoring.factor_scores(ctx.findings, {"appsec"})["appsec"] < 100   # ...and scored
    r = report.build_result(ctx, {"appsec"})
    f = next(x for x in r["findings"] if x["check_id"] == "http_xfo_missing")
    assert f["vendor"] == "HubSpot" and r["overall"]["score"] < 100
    assert "1 low" in report.summary_sentence(r)
    assert r["quick_wins"] and r["quick_wins"][0]["assets"] == ["www.example.com"]
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "r.html")
        report.write_html(r, p)
        page = open(p, encoding="utf-8").read()
    assert "hosted by HubSpot" in page and "Vendor-hosted (HubSpot)" in page
    assert "excluded from score" not in page
    # vendor names: CNAME suffix, documented IP range, ASN org; own hosts get none
    okta = ctx.asset("login.example.com")
    okta.hosting_class, okta.cnames = "saas", ["tenant.customdomains.okta-dnssec.com"]
    edge = ctx.asset("cdn.example.com")
    edge.hosting_class, edge.hosting = "cdn", {"192.0.2.1": {"class": "cdn",
                                                             "org": "CLOUDFLARENET - Cloudflare, Inc., US"}}
    apex = ctx.asset("example.com")
    apex.hosting_class, apex.hosting = "saas", {"199.60.103.28": {"class": "saas", "provider": "HubSpot"}}
    assert [discovery.vendor_for(x) for x in (okta, edge, apex, own)] == ["Okta", "Cloudflare, Inc.", "HubSpot", ""]


def test_info_only_factor_stays_not_assessed():
    from openscore import scoring
    ctx = make_ctx(active=False)
    ctx.add("rep_shodan_tag", "192.0.2.9", "x", severity="info")     # an info finding under reputation
    assert scoring.factor_scores(ctx.findings, set())["reputation"] is None
    ctx.add("rep_shodan_tag", "192.0.2.10", "x", severity="low")
    assert scoring.factor_scores(ctx.findings, set())["reputation"] is not None


def test_vendor_ips_get_shodan_ports_but_no_blocklists_or_live_checks():
    """Risky ports Shodan saw on a vendor's IP are scored (tentative, passive only); blocklist and
    abuse lookups stay on the organization's own IPs, and nothing contacts the vendor IP."""
    from openscore.modules import ports, reputation
    ctx = make_ctx(active=False)
    ctx.cfg.threads, ctx.cfg.abuseipdb_key, ctx.cfg.greynoise_key, ctx.cfg.hibp_key = 2, "", "", ""
    site = ctx.asset("www.example.com")
    site.hosting_class, site.ips, site.cnames = "saas", ["192.0.2.50"], ["x.sites.vendor.example"]
    mine = ctx.asset("vpn.example.com")
    mine.hosting_class, mine.ips = "owned", ["198.51.100.7"]
    looked_up, listed = [], []

    def get(url, **kw):
        looked_up.append(url)
        ports_ = [3389, 443] if url.endswith("/192.0.2.50") else []
        return resp(url, '{"ports": %s, "cpes": [], "vulns": [], "tags": []}' % ports_,
                    headers={"Content-Type": "application/json"})
    ctx.session = types.SimpleNamespace(headers={}, get=get)
    with patched(reputation, _dnsbl=lambda c, ip: listed.append(ip), _domain_bl=lambda c: None,
                 _abuseipdb=lambda c, ip: listed.append(ip), _greynoise=lambda c, ip: listed.append(ip)):
        reputation.run(ctx)
    assert sorted(u.rsplit("/", 1)[1] for u in looked_up) == ["192.0.2.50", "198.51.100.7"]
    assert set(listed) == {"198.51.100.7"}, listed                   # no blocklists for the vendor IP
    rdp = [f for f in ctx.findings if f.factor == "network" and f.asset == "192.0.2.50"]
    assert rdp and rdp[0].confidence == "tentative" and "www.example.com" in rdp[0].evidence
    assert ctx.flags.get("internetdb_ok")
    ctx.cfg.client, ctx.cfg.authorization = "Example", ""
    r = report.build_result(ctx, {"network"})
    assert next(x for x in r["findings"] if x["asset"] == "192.0.2.50")["vendor"] == "a SaaS provider"
    # live confirmation only ever touches IPs OpenScore port-scanned itself (never vendor IPs)
    touched = []
    with patched(ports, _connect=lambda ip, port, t: touched.append(ip) or False):
        ports.confirm_passive_ports(ctx, scanned={"198.51.100.7"})
    assert "192.0.2.50" not in touched

if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
