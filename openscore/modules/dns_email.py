"""DNS health and email authentication (passive, except AXFR which is active)."""
from __future__ import annotations

import base64
import logging
import re

import dns.message
import dns.query
import dns.zone

from .. import proof

log = logging.getLogger("openscore")
MODE = "passive"

DKIM_SELECTORS = ["selector1", "selector2", "google", "default", "k1", "k2", "k3", "s1", "s2",
                  "dkim", "mail", "smtp", "mx", "sig1", "everlytickey1", "everlytickey2", "mxvault",
                  "zoho", "zmail", "protonmail", "protonmail2", "mandrill", "mailjet", "sendgrid",
                  "smtpapi", "m1", "pm", "hs1", "hs2", "cm", "ctct1", "ctct2", "fd", "fd2",
                  "mimecast20190104", "dk", "key1", "key2", "200608", "20161025", "20230601"]

LOOKUP_MECHS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


# ------------------------------------------------------------------------- SPF
def parse_spf(record: str) -> dict:
    terms = record.split()[1:]
    allq = None
    for t in terms:
        m = re.fullmatch(r"([+\-~?]?)all", t.lower())
        if m:
            allq = m.group(1) or "+"
    return {"terms": terms, "all": allq, "redirect": next((t.split("=", 1)[1] for t in terms
                                                          if t.lower().startswith("redirect=")), None)}


def _is_lookup(term: str) -> bool:
    t = term.lower().lstrip("+-~?")
    return (t.startswith(("include:", "exists:", "redirect=")) or t in ("a", "mx", "ptr")
            or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:")))


def count_spf_lookups(ctx, domain: str, depth: int = 0, seen=None, trace=None) -> tuple[int, bool]:
    """Recursively count DNS-querying mechanisms. Returns (count, complete).
    trace (list) receives (depth, domain, term) for the evidence exhibit."""
    seen = seen or set()
    if depth > 10 or domain in seen:
        return 0, True
    seen.add(domain)
    r = ctx.dns.txt(domain)
    if not r.ok:
        return 0, r.definitive_absent
    spf = [t for t in r.records if t.lower().startswith("v=spf1")]
    if not spf:
        return 0, True
    count, complete = 0, True
    for term in spf[0].split()[1:]:
        if not _is_lookup(term):
            continue
        count += 1
        t = term.lstrip("+-~?")
        if trace is not None:
            trace.append((depth, domain, t))
        if t.lower().startswith("include:"):
            c, ok = count_spf_lookups(ctx, t.split(":", 1)[1], depth + 1, seen, trace)
            count += c
            complete &= ok
        elif t.lower().startswith("redirect="):
            c, ok = count_spf_lookups(ctx, t.split("=", 1)[1], depth + 1, seen, trace)
            count += c
            complete &= ok
    return count, complete


def _spf_absent_proof(d, r):
    p = proof.dns(d, "TXT", r, absent_note="no SPF record", verdict=f"{d} publishes no SPF record")
    if r.ok:
        p["lines"].append(["(none of these TXT records start with v=spf1)", "bad", "no SPF record"])
    return p


def check_spf(ctx, has_mx: bool) -> None:
    d = ctx.domain
    r = ctx.dns.txt(d)
    if not r.ok and not r.definitive_absent:
        ctx.module_status.setdefault("dns_email", {})["spf"] = f"lookup error: {r.error}"
        return
    spf = [t for t in r.records if t.lower().startswith("v=spf1")]

    def txt_proof(note_for, verdict):
        return proof.dns(d, "TXT", r, mark=lambda rec: ("bad", note_for(rec)) if note_for(rec) else None,
                         verdict=verdict, absent_note="no SPF record")
    if not spf:
        sev = "high" if has_mx else "medium"
        ctx.add("email_spf_missing", d, "No v=spf1 TXT record at the apex" +
                ("" if has_mx else " (domain has no MX; publish `v=spf1 -all` to stop spoofing)"),
                severity=sev, source="dns", proof=_spf_absent_proof(d, r))
        return
    if len(spf) > 1:
        ctx.add("email_spf_multiple", d, "\n".join(spf), source="dns",
                proof=txt_proof(lambda x: "duplicate SPF record" if x.lower().startswith("v=spf1") else None,
                                f"{len(spf)} SPF records — receivers return permerror"))
    rec = spf[0]
    p = parse_spf(rec)
    issues = False
    is_spf = lambda x: x.lower().startswith("v=spf1")  # noqa: E731
    if p["all"] in ("+", "?"):
        ctx.add("email_spf_permissive", d, rec, source="dns",
                proof=txt_proof(lambda x: f"ends with {p['all']}all" if is_spf(x) else None,
                                "SPF lets any server send as this domain")); issues = True
    elif p["all"] == "~":
        ctx.add("email_spf_softfail", d, rec, source="dns",
                proof=txt_proof(lambda x: "~all = soft fail" if is_spf(x) else None,
                                "SPF soft-fails instead of rejecting")); issues = True
    elif p["all"] is None and not p["redirect"]:
        ctx.add("email_spf_permissive", d, rec + "\n(no 'all' mechanism — defaults to neutral)",
                source="dns", proof=txt_proof(lambda x: "no 'all' mechanism" if is_spf(x) else None,
                                              "SPF has no final 'all' — defaults to neutral")); issues = True
    if any(t.lower().lstrip("+-~?").startswith("ptr") for t in p["terms"]):
        ctx.add("email_spf_ptr", d, rec, source="dns",
                proof=txt_proof(lambda x: "uses ptr" if is_spf(x) else None, "Deprecated ptr mechanism"))
        issues = True
    trace = []
    n, complete = count_spf_lookups(ctx, d, trace=trace)
    if n > 10:
        lines = [[f"{'  ' * dep}{dom}: {term}", "bad" if i >= 10 else None,
                  f"lookup #{i + 1}" + (" — over the limit" if i >= 10 else "")]
                 for i, (dep, dom, term) in enumerate(trace)]
        ctx.add("email_spf_too_many_lookups", d, f"{n} DNS lookups (limit 10)\n{rec}", source="dns",
                proof=proof.make("SPF lookup tree (recursive)", f"spf-lookup-count {d}", lines,
                                 verdict=f"{n} DNS-querying mechanisms — RFC 7208 limit is 10")); issues = True
    if not issues and len(spf) == 1:
        ctx.passed("email_spf_ok", d, f"{rec}  [{n} lookups]", source="dns")


# ----------------------------------------------------------------------- DMARC
def parse_dmarc(rec: str) -> dict:
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dmarc(ctx) -> None:
    d = ctx.domain
    r = ctx.dns.txt(f"_dmarc.{d}")
    if not r.ok and not r.definitive_absent:
        return
    recs = [t for t in r.records if t.lower().startswith("v=dmarc1")]

    def dp(note, verdict):
        return proof.dns(f"_dmarc.{d}", "TXT", r, mark=lambda x: ("bad", note) if x.lower().startswith("v=dmarc1")
                         else None, verdict=verdict, absent_note="no DMARC record")
    if not recs:
        ctx.add("email_dmarc_missing", d, f"No v=DMARC1 TXT at _dmarc.{d}", source="dns",
                proof=dp(None, f"_dmarc.{d} has no DMARC policy"))
        return
    if len(recs) > 1:
        ctx.add("email_dmarc_invalid", d, "Multiple DMARC records:\n" + "\n".join(recs), source="dns",
                proof=dp("duplicate", "More than one DMARC record — receivers ignore DMARC"))
        return
    rec = recs[0]
    t = parse_dmarc(rec)
    p = t.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        ctx.add("email_dmarc_invalid", d, rec, source="dns", proof=dp("missing/invalid p= tag", "Malformed DMARC"))
        return
    issues = False
    if p == "none":
        ctx.add("email_dmarc_none", d, rec, source="dns",
                proof=dp("p=none → monitor only", "DMARC does not block spoofed mail")); issues = True
    try:
        pct = int(t.get("pct", "100"))
    except ValueError:
        pct = 100
    if p != "none" and pct < 100:
        ctx.add("email_dmarc_partial", d, rec, source="dns",
                proof=dp(f"pct={pct}", f"Policy applies to only {pct}% of failing mail")); issues = True
    if "rua" not in t:
        ctx.add("email_dmarc_no_rua", d, rec, source="dns",
                proof=dp("no rua= reporting address", "No DMARC aggregate reports")); issues = True
    sp = t.get("sp", p).lower()
    order = {"none": 0, "quarantine": 1, "reject": 2}
    if order.get(sp, 0) < order.get(p, 0):
        ctx.add("email_dmarc_weak_sp", d, rec, source="dns",
                proof=dp(f"sp={sp} weaker than p={p}", "Subdomains can be spoofed")); issues = True
    if not issues:
        ctx.passed("email_dmarc_ok", d, rec, source="dns")


# ------------------------------------------------------------------------ DKIM
def _dkim_bits(rec: str):
    m = re.search(r"p=([A-Za-z0-9+/=\s]+)", rec)
    if not m or not m.group(1).strip():
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        key = load_der_public_key(base64.b64decode(re.sub(r"\s", "", m.group(1))))
        return getattr(key, "key_size", None)
    except Exception:
        return None


def check_dkim(ctx, has_mx: bool) -> None:
    d = ctx.domain
    found, checked = [], []
    for sel in ctx.cfg.dkim_selectors + DKIM_SELECTORS:
        name = f"{sel}._domainkey.{d}"
        r = ctx.dns.txt(name)
        checked.append((name, r.status))
        if r.ok:
            for rec in r.records:
                if "p=" in rec:
                    found.append((sel, rec))
    if not found:
        if has_mx:
            lines = [[f"{n:<48} {st.upper()}", None, None] for n, st in checked]
            ctx.add("email_dkim_not_found", d, f"Checked {len(checked)} common selectors",
                    source="dns", confidence="tentative",
                    proof=proof.make("DKIM selector probes", f"dig +short TXT <selector>._domainkey.{d}", lines,
                                     verdict=f"No DKIM key at {len(checked)} common selectors — check a real "
                                             "email's DKIM-Signature s= tag to confirm"))
        return
    weak = False
    for sel, rec in found:
        bits = _dkim_bits(rec)
        if bits and bits < 2048:
            ctx.add("email_dkim_weak_key", d, f"selector {sel}: {bits}-bit RSA",
                    severity="high" if bits < 1024 else "medium", source="dns",
                    proof=proof.make("DKIM key", f"dig +short TXT {sel}._domainkey.{d}",
                                     [[rec[:200], "bad", f"{bits}-bit RSA key"]],
                                     verdict=f"DKIM key is {bits} bits (2048 recommended)"))
            weak = True
    if not weak:
        ctx.passed("email_dkim_ok", d, "selectors: " + ", ".join(s for s, _ in found), source="dns")


# -------------------------------------------------------------- MTA-STS / TLS-RPT
def check_mtasts(ctx, has_mx: bool) -> None:
    if not has_mx:
        return
    d = ctx.domain
    r = ctx.dns.txt(f"_mta-sts.{d}")
    if r.definitive_absent or (r.ok and not any(x.lower().startswith("v=stsv1") for x in r.records)):
        ctx.add("email_mtasts_missing", d, source="dns",
                proof=proof.dns(f"_mta-sts.{d}", "TXT", r, verdict="No MTA-STS policy published"))
    elif r.ok:
        try:
            pol = ctx.session.get(f"https://mta-sts.{d}/.well-known/mta-sts.txt", timeout=10).text
            if "mode: enforce" in pol.replace("\t", " "):
                ctx.passed("email_mtasts_ok", d, pol[:300], source="dns")
            elif "mode: testing" in pol:
                ctx.add("email_mtasts_testing", d, pol[:300], source="dns")
            else:
                ctx.add("email_mtasts_missing", d, "TXT present but policy file unreadable/invalid",
                        source="dns")
        except Exception as e:
            ctx.add("email_mtasts_missing", d, f"TXT present but policy fetch failed: {e}", source="dns")
    t = ctx.dns.txt(f"_smtp._tls.{d}")
    if t.definitive_absent or (t.ok and not any("v=tlsrptv1" in x.lower() for x in t.records)):
        ctx.add("email_tlsrpt_missing", d, source="dns",
                proof=proof.dns(f"_smtp._tls.{d}", "TXT", t, verdict="No TLS-RPT record"))


# ------------------------------------------------------------------- DNS health
def check_dns_health(ctx) -> list[str]:
    d = ctx.domain
    ns = ctx.dns.query(d, "NS")
    nameservers = ns.records if ns.ok else []
    if ns.ok:
        if len(nameservers) < 2:
            ctx.add("dns_ns_single", d, ", ".join(nameservers), source="dns",
                    proof=proof.dns(d, "NS", ns, mark=lambda x: ("bad", "only nameserver"),
                                    verdict="Single point of failure"))
        lame = []
        for n in nameservers:
            ip = ctx.dns.query(n, "A")
            if not ip.ok:
                lame.append(f"{n} (no A record)")
                continue
            try:
                q = dns.message.make_query(d, "SOA")
                resp = dns.query.udp(q, ip.records[0], timeout=4)
                if not (resp.flags & 0x0400):  # AA bit
                    lame.append(f"{n} (not authoritative)")
            except Exception as e:
                lame.append(f"{n} ({e.__class__.__name__})")
        if lame and len(lame) < len(nameservers):
            ctx.add("dns_ns_lame", d, "\n".join(lame), source="dns",
                    proof=proof.make("Authoritative check per nameserver", f"dig @<ns> SOA {d}",
                                     [[n, "bad" if any(n in x for x in lame) else "good",
                                       next((x for x in lame if n in x), "authoritative")] for n in nameservers],
                                     verdict=f"{len(lame)} of {len(nameservers)} nameservers not answering"))
        elif not lame:
            ctx.passed("dns_ok", d, ", ".join(nameservers), source="dns")

    dk = ctx.dns.query(d, "DNSKEY")
    ds = ctx.dns.query(d, "DS")
    if dk.ok and ds.ok:
        ctx.passed("dns_dnssec_ok", d, "DNSKEY + DS present", source="dns")
    elif dk.definitive_absent or ds.definitive_absent:
        ctx.add("dns_dnssec_missing", d, f"DNSKEY: {dk.status}, DS: {ds.status}", source="dns",
                proof=proof.merge(proof.dns(d, "DS", ds), proof.dns(d, "DNSKEY", dk),
                                  verdict="Zone is not DNSSEC-signed"))

    caa = ctx.dns.query(d, "CAA")
    if caa.ok:
        ctx.passed("dns_caa_ok", d, "\n".join(caa.records), source="dns")
    elif caa.definitive_absent:
        ctx.add("dns_caa_missing", d, source="dns",
                proof=proof.dns(d, "CAA", caa, verdict="Any certificate authority may issue for this domain"))
    return nameservers


def check_axfr(ctx, nameservers: list[str]) -> None:
    d = ctx.domain
    for n in nameservers:
        ip = ctx.dns.query(n, "A")
        if not ip.ok:
            continue
        ctx.audit_log(f"AXFR attempt {d} @ {n} ({ip.records[0]})")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ip.records[0], d, timeout=8, lifetime=15))
            names = sorted(str(k) for k in z.nodes.keys())
            ctx.add("dns_axfr_allowed", d, f"{n} returned {len(names)} records, e.g. {', '.join(names[:10])}",
                    source="dns", proof=proof.make("Zone transfer", f"dig AXFR {d} @{n}",
                                                   [[x, None, None] for x in names[:25]],
                                                   verdict=f"{n} handed out the full zone ({len(names)} names)"))
        except Exception:
            pass


def run(ctx) -> None:
    mx = ctx.dns.query(ctx.domain, "MX")
    has_mx = mx.ok and any(r.split()[-1] not in (".", "") for r in mx.records)
    if mx.status == "error":
        ctx.flags["dns_failed"] = True
        log.warning("DNS lookups failing (%s) — email/DNS checks may be incomplete", mx.error)
        ctx.module_status.setdefault("dns_email", {})["warning"] = f"resolver error: {mx.error}"
        if ctx.dns.dead:
            return
    check_spf(ctx, has_mx)
    check_dmarc(ctx)
    check_dkim(ctx, has_mx)
    check_mtasts(ctx, has_mx)
    nameservers = check_dns_health(ctx)
    if ctx.cfg.active and nameservers:
        check_axfr(ctx, nameservers)
