"""Offline tests for SPF/DMARC/DKIM/DNS logic using a fake resolver.
Run: python3 -m pytest tests/  (or python3 tests/test_dns_email.py)"""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openscore import scoring                       # noqa: E402
from openscore.models import ScanContext            # noqa: E402
from openscore.modules import dns_email, software   # noqa: E402
from openscore.util import DNSResult                # noqa: E402

M365_DKIM = ("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwH8M1n2ZhvH7Rfiyr0o5BYAk3yGShnNO"
             "HsUW0Cq0SuYqf+pG+oP2h5aV6QDDWmSKbvGcvqN9a7Sw2XHn4G5WGiFBFqyY4qf9q3Jv7yS4zj6nLwZJpPq2xU2GgrJm"
             "Ce0d0cEnu6UUdT0FrJDHLqF2t0lbEc7zg6iUqfI7HJ1RkJp6tFJMh1pPZ2N0R8sIGQ5gqN5RNzZ3Pq6J9iX2ZPwZtqR"
             "Uz8T9yWfq8E5ZtR4QJh6kgW8H5bH3oG1N8F7VZ1mY6xDwlQ1V6Bd6Ve2G3Bo1k2xJ1vUk2tY2G9h5O1wOq8ETfnHL7l"
             "5Q8rM2nWk7d0Zb3t1gU6K0wIDAQAB")


class FakeDNS:
    def __init__(self, records):
        self.records = records
        self.dead = False

    def query(self, name, rtype):
        v = self.records.get((name, rtype))
        if v is None:
            return DNSResult("nxdomain")
        if isinstance(v, DNSResult):
            return v
        return DNSResult("ok", v)

    def txt(self, name):
        return self.query(name, "TXT")


def make_ctx(records):
    cfg = types.SimpleNamespace(exclude=set(), ip_ranges=[], dkim_selectors=[], active=False,
                                timeout=5, client=None, authorization="")
    ctx = ScanContext("example.com", cfg)
    ctx.dns = FakeDNS(records)

    class S:
        headers = {"User-Agent": "t"}

        def get(self, *a, **k):
            raise OSError("offline")
    ctx.session = S()
    return ctx


def ids(ctx):
    return {f.check_id: f.severity for f in ctx.findings}


def test_good_m365_domain():
    ctx = make_ctx({
        ("example.com", "MX"): ["0 example-com.mail.protection.outlook.com"],
        ("example.com", "TXT"): ["v=spf1 include:spf.protection.outlook.com -all", "MS=ms123"],
        ("spf.protection.outlook.com", "TXT"): ["v=spf1 ip4:40.92.0.0/15 include:spfd.protection.outlook.com -all"],
        ("spfd.protection.outlook.com", "TXT"): ["v=spf1 ip4:51.4.72.0/24 -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
        ("selector1._domainkey.example.com", "TXT"): [M365_DKIM],
        ("example.com", "NS"): ["ns1.example.net", "ns2.example.net"],
        ("example.com", "CAA"): ['0 issue "digicert.com"'],
        ("example.com", "DNSKEY"): ["257 3 13 abc"], ("example.com", "DS"): ["1 13 2 abc"],
        ("_mta-sts.example.com", "TXT"): DNSResult("nxdomain"),
    })
    dns_email.check_spf(ctx, True)
    dns_email.check_dmarc(ctx)
    dns_email.check_dkim(ctx, True)
    i = ids(ctx)
    assert i.get("email_spf_ok") == "pass", i
    assert i.get("email_dmarc_ok") == "pass", i
    assert "email_dkim_not_found" not in i, i


def test_bad_domain():
    ctx = make_ctx({
        ("example.com", "MX"): ["10 mail.example.com"],
        ("example.com", "TXT"): ["v=spf1 a mx ptr include:a.com include:b.com ?all", "v=spf1 -all"],
        ("a.com", "TXT"): ["v=spf1 include:c.com include:d.com include:e.com -all"],
        ("c.com", "TXT"): ["v=spf1 a mx include:f.com -all"], ("d.com", "TXT"): ["v=spf1 a mx -all"],
        ("e.com", "TXT"): ["v=spf1 a -all"], ("f.com", "TXT"): ["v=spf1 a -all"],
        ("b.com", "TXT"): ["v=spf1 mx -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
    })
    dns_email.check_spf(ctx, True)
    dns_email.check_dmarc(ctx)
    dns_email.check_dkim(ctx, True)
    i = ids(ctx)
    for want in ("email_spf_multiple", "email_spf_permissive", "email_spf_ptr", "email_spf_too_many_lookups",
                 "email_dmarc_none", "email_dmarc_no_rua", "email_dkim_not_found"):
        assert want in i, (want, i)


def test_missing_records_vs_resolver_error():
    # NXDOMAIN → findings
    ctx = make_ctx({("example.com", "MX"): ["10 mx.example.com"]})
    dns_email.check_spf(ctx, True)
    dns_email.check_dmarc(ctx)
    assert {"email_spf_missing", "email_dmarc_missing"} <= set(ids(ctx))
    # resolver failure → NO findings (we must not accuse the client of missing SPF)
    err = DNSResult("error", error="timeout")
    ctx = make_ctx({("example.com", "TXT"): err, ("_dmarc.example.com", "TXT"): err})
    dns_email.check_spf(ctx, True)
    dns_email.check_dmarc(ctx)
    assert not ctx.findings, ctx.findings


def test_non_mail_domain_spf_guidance():
    ctx = make_ctx({})
    dns_email.check_spf(ctx, has_mx=False)
    f = ctx.findings[0]
    assert f.check_id == "email_spf_missing" and f.severity == "medium" and "-all" in f.evidence


def test_iis_exchange_eol():
    assert software._iis("8.5")[0] == "eol"
    assert software._iis("10.0")[0] == "supported"
    assert software._exchange("15.1.2507.39")[0] == "eol"
    assert software._exchange("15.2.2562.17")[0] == "supported"
    assert software._fallback("php", "7.4.33")[0] == "eol"


def test_scoring_dampening_and_cap():
    ctx = make_ctx({})
    for i in range(10):
        ctx.add("http_hsts_missing", f"h{i}.example.com")
    fs = scoring.factor_scores(ctx.findings, {"appsec"})
    # 8 + 4 + 2 + 1 + ... < 16 → appsec stays above 84
    assert fs["appsec"] >= 84, fs
    ctx.add("exp_git", "www.example.com")
    ov = scoring.overall(ctx.findings, set(scoring.FACTORS))
    assert ov["capped"] and ov["score"] == 79 and ov["grade"] == "C", ov


def test_tentative_critical_does_not_cap():
    ctx = make_ctx({})
    ctx.add("vuln_kev", "203.0.113.5", "CVE-2021-40438", confidence="tentative")
    ov = scoring.overall(ctx.findings, set(scoring.FACTORS))
    assert not ov["capped"] and ov["cap_pending"] and ov["score"] > 79, ov
    from openscore import report
    text = report.summary_sentence({"overall": ov, "findings": [], "assets": [], "client": "Example",
                                    "quick_wins": [], "assessed_factors": list(scoring.FACTORS)})
    assert "still needs verification" in text and "capped at C" in text, text
    # a firm critical (e.g. live-confirmed) still caps
    ctx.add("exp_git", "www.example.com")
    ov = scoring.overall(ctx.findings, set(scoring.FACTORS))
    assert ov["capped"] and ov["score"] == 79 and not ov["cap_pending"], ov


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
