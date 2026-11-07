"""JSON + self-contained HTML report generation, and baseline diffing."""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
from collections import OrderedDict, defaultdict
from dataclasses import fields

from jinja2 import Environment
from markupsafe import Markup

from . import __version__, brand, kb, proof, scoring, util
from .models import SEV_RANK, Finding


def _md(text: str) -> str:
    """Tiny markdown: `code` spans, and links outside code spans."""
    out = []
    for i, part in enumerate((text or "").split("`")):
        part = html.escape(part)
        if i % 2:
            out.append(f"<code>{part}</code>")
        else:
            out.append(re.sub(r"(https?://[^\s<)]+[^\s<).,;])", r'<a href="\1">\1</a>', part))
    return "".join(out)


def build_result(ctx, assessed: set[str]) -> dict:
    ov = scoring.overall(ctx.findings, assessed)
    findings = [f.to_dict() for f in sorted(ctx.findings, key=lambda f: (SEV_RANK[f.severity], f.factor))]
    # Findings from IP-based sources name an IP; add the hostnames/sites on it so the reader sees what's affected
    ip_hosts: dict = {}
    for d in findings:
        if util.is_ip(d["asset"]):
            if d["asset"] not in ip_hosts:
                ip_hosts[d["asset"]] = ctx.hosts_on_ip(d["asset"])
            if ip_hosts[d["asset"]]:
                d["hosts"] = ip_hosts[d["asset"]]
    # Fields for ticketing/trackers built from the JSON: a stable key, and the same why/verify/fix
    # text the HTML report shows (knowledge-base text only; evidence stays in "evidence"/"proof").
    for d in findings:
        meta = kb.get(d["check_id"])
        d["key"] = finding_key(d)
        d["description"] = meta.get("description", "")
        d["remediation"] = meta.get("remediation", "")
        d["verify"] = verify_text(meta, d, ctx.domain)
    return {
        "tool": "OpenScore", "version": __version__,
        "domain": ctx.domain, "client": ctx.cfg.client or ctx.domain,
        "started": ctx.started.isoformat(timespec="seconds"),
        "mode": "active" if ctx.cfg.active else "passive+light",
        "authorization": ctx.cfg.authorization,
        "overall": ov,
        "quick_wins": scoring.quick_wins(ctx.findings, assessed),
        "assessed_factors": sorted(assessed),
        "findings": findings,
        "ip_hosts": {ip: hs for ip, hs in ip_hosts.items() if hs},
        "assets": [a.to_dict() for a in sorted(ctx.assets.values(), key=lambda a: a.host)],
        "software": ctx.software,
        "cves": {k: sorted(v) for k, v in ctx.cves.items()},
        "module_status": ctx.module_status,
        "suppressions": getattr(ctx, "suppression_status", None),
        "audit": ctx.audit,
    }


def diff(result: dict, baseline: dict, baseline_path: str = "") -> dict:
    def keys(r):
        # Info, suppressed and third-party (SaaS) findings don't affect the score; leaving them out
        # keeps "new/resolved" about things that moved the grade.
        return {(f["check_id"], f["asset"], f["title"]): f for f in r["findings"]
                if f["severity"] not in ("pass", "info") and not f.get("suppression") and not f.get("third_party")}

    def ordered(fs):
        return sorted(fs, key=lambda f: (SEV_RANK.get(f["severity"], 9), f["title"], f["asset"]))

    now, before = keys(result), keys(baseline)
    b_mode, b_assets = baseline.get("mode"), len(baseline.get("assets") or [])
    n_assets = len(result.get("assets") or [])
    caveats = []
    if b_mode and result.get("mode") and b_mode != result["mode"]:
        caveats.append(f"the previous scan ran in {b_mode} mode, this one in {result['mode']}")
    if b_assets and n_assets and min(b_assets, n_assets) / max(b_assets, n_assets) < 0.75:
        caveats.append(f"the previous scan covered {b_assets} asset(s), this one {n_assets}")
    return {
        "baseline_date": baseline.get("started"), "baseline_file": os.path.basename(baseline_path),
        "baseline_mode": b_mode, "baseline_assets": b_assets, "caveats": caveats,
        "baseline_score": baseline["overall"]["score"], "baseline_grade": baseline["overall"]["grade"],
        "delta": round(result["overall"]["score"] - baseline["overall"]["score"], 1),
        "new": ordered(now[k] for k in now.keys() - before.keys()),
        "resolved": ordered(before[k] for k in before.keys() - now.keys()),
    }


def finding_key(f: dict) -> str:
    """Stable ID for one finding across scans: same check, asset and title -> same key.

    The scan-to-scan diff uses the same identity, so a tracker keyed on this stays in step with
    the report's "new" and "resolved" lists."""
    raw = "\x1f".join((f["check_id"], f["asset"], f["title"]))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def verify_text(meta: dict, entry: dict, domain: str) -> str:
    """The KB verify command with {url}/{asset}/{domain}/{template} filled in (plain text)."""
    v = meta.get("verify", "")
    if not v:
        return ""
    asset = entry["asset"]
    m = re.search(r"https?://[^\s\]]+", entry.get("evidence", ""))
    url = m.group(0).rstrip(".,:;)") if m else f"https://{asset}/"
    if "{template}" in v:       # nuclei findings: evidence starts with "<template-id>: <matched>"
        t = re.match(r"([A-Za-z0-9_.-]+): ", entry.get("evidence", ""))
        v = v.replace("{template}", t.group(1) if t else "<template-id>")
    return v.replace("{url}", url).replace("{asset}", asset).replace("{domain}", domain)


def _verify(meta: dict, entry: dict, domain: str) -> str:
    return _md(verify_text(meta, entry, domain))


# Triage buttons in the HTML report: status -> (button label, default review period in days)
TRIAGE = {"false_positive": ("False positive", None),
          "accepted_risk": ("Accept risk", 180),
          "compensating_control": ("Compensating control", 365)}


def _toml(f: dict, status: str = "false_positive", today=None) -> str:
    """A suppressions-file entry for one finding, ready to paste."""
    import datetime as dt
    today = today or dt.date.today()
    out = (f'[[suppress]]\ncheck = "{f["check_id"]}"\nasset = "{f["asset"]}"\n'
           f'status = "{status}"\n')
    if status == "false_positive":
        out += 'reason = ""                  # why this isn\'t a real issue\n'
    elif status == "accepted_risk":
        out += 'reason = ""                  # why the risk is accepted (business need, low exposure ...)\n'
    else:
        out += ('reason = ""                  # the risk that remains\n'
                'control = ""                 # what mitigates it, e.g. "WAF rule blocks /admin from the internet"\n')
    out += 'approved_by = ""\n'
    days = TRIAGE[status][1]
    if days:
        out += f"expires = {(today + dt.timedelta(days=days)).isoformat()}   # review date (required)\n"
    return out


def _group(findings: list[dict], domain: str = ""):
    """factor -> list of groups {check_id,title,severity,items:[finding]} sorted by severity."""
    out = OrderedDict((f, []) for f in kb.FACTORS)
    groups = defaultdict(list)
    for f in findings:
        groups[(f["factor"], f["check_id"], f["title"])].append(dict(f))
    for (fac, check, title), items in groups.items():
        sev = min(items, key=lambda f: SEV_RANK[f["severity"]])["severity"]
        meta = kb.get(check)
        for i in items:
            i["triage"] = [(st, label, _toml(i, st)) for st, (label, _) in TRIAGE.items()]
        out.setdefault(fac, []).append({
            "verify": _verify(meta, items[0], domain),
            "check_id": check, "title": title, "severity": sev, "entries": items,
            "tentative": all(i["confidence"] == "tentative" for i in items),
            "description": _md(meta.get("description", "")), "remediation": _md(meta.get("remediation", "")),
            "refs": meta.get("refs", []),
        })
    for fac in out:
        out[fac].sort(key=lambda g: (SEV_RANK[g["severity"]], -len(g["entries"]), g["title"]))

    # Order sections by severity profile: most criticals first, then highs, mediums, lows.
    def profile(fac):
        sevs = [g["severity"] for g in out[fac]]
        return tuple(-sevs.count(s) for s in ("critical", "high", "medium", "low", "info"))
    return OrderedDict(sorted(out.items(), key=lambda kv: profile(kv[0])))


SOURCE_GAPS = {
    "crt.sh": "certificate transparency (crt.sh) was unavailable, so discovery only checked common "
              "hostnames and the asset list is probably incomplete. Rerun later (crt.sh is often "
              "overloaded) or install subfinder.",
}


def coverage_warnings(result: dict) -> list[str]:
    """Data sources and tools that failed or were cut short during the scan, worded for the top of
    the report: a clean-looking report built on missing data must say so where people will read it."""
    out = []
    status = result.get("module_status") or {}
    tools = status.get("tools") or {}
    for module, st in status.items():
        if not isinstance(st, dict):
            continue
        for source, val in st.items():
            if not isinstance(val, str):
                continue
            if "request(s) failed" in val:
                if source == "crt.sh" and tools.get("subfinder") == "found":
                    out.append("crt.sh: certificate transparency (crt.sh) was unavailable, so discovery "
                               "relied on subfinder and common hostnames. The asset list may be "
                               "incomplete; rerun later (crt.sh is often overloaded).")
                else:
                    out.append(f"{source}: " + SOURCE_GAPS.get(
                        source, f"this data source failed ({module}), so its checks may be incomplete. "
                                "See Module notes."))
            elif val.startswith("rate limited"):
                out.append(f"{source}: {val}. IPs checked after the limit have no {source} data, so "
                           "reputation results may be incomplete.")
            elif source == "testssl" and (val.startswith("could not run") or val.startswith("failed to start")
                                          or re.match(r"0/[1-9]\d* hosts completed", val)):
                out.append("testssl.sh: didn't complete on any host (" + val.split(";")[0] + "), so TLS "
                           "results come from OpenScore's built-in checks only. See Module notes.")
            elif source == "nuclei" and (val.startswith("failed to start") or val.startswith("exited")
                                         or val.startswith("stopped")):
                out.append("nuclei: " + val.split(";")[0] + ", so template checks may be incomplete. "
                           "See Module notes.")
    return out


def summary_sentence(result: dict) -> str:
    sc = [f for f in result["findings"] if f["severity"] not in ("pass", "info") and not f["third_party"]
          and not f.get("suppression")]
    counts = defaultdict(int)
    for f in sc:
        counts[f["severity"]] += 1
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts[s]]
    ov = result["overall"]
    s = (f"{result['client']} scored {ov['score']:.0f}/100 (grade {ov['grade']}) across "
         f"{len(result['assets'])} discovered asset{'s' if len(result['assets']) != 1 else ''}, with {', '.join(parts) or 'no'} issues.")
    wins = result["quick_wins"][:5]
    if wins:
        gain = 0.0
        keep = {fl.name for fl in fields(Finding)}
        remaining = [Finding(**{k: v for k, v in f.items() if k in keep}) for f in result["findings"]]
        for w in wins:
            remaining = [f for f in remaining if not (f.check_id == w["check_id"] and f.title == w["title"]
                                                       and f.factor == w["factor"])]
        new = scoring.overall(remaining, set(result["assessed_factors"]))
        gain = new["score"] - ov["score"]
        if gain >= 1:
            s += (f" Fixing the top {len(wins)} items below would raise the score to about "
                  f"{new['score']:.0f} ({new['grade']}).")
    if ov["capped"]:
        s += " The overall grade is capped at C while a critical finding remains open."
    elif ov.get("cap_pending"):
        s += (" A critical finding still needs verification; if it's confirmed, the overall grade "
              "is capped at C.")
    return s


def write_json(result: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)


def _data_uri(rel: str | None, outdir: str) -> str:
    """Embed evidence images so the report is a single file you can email."""
    if not rel:
        return ""
    p = os.path.join(outdir, rel)
    try:
        with open(p, "rb") as f:
            return "data:image/jpeg;base64," + base64.b64encode(f.read()).decode()
    except OSError:
        return ""


def write_html(result: dict, path: str, delta: dict | None = None) -> None:
    outdir = os.path.dirname(path) or "."
    env = Environment(autoescape=True)
    env.filters["md"] = _md
    env.filters["exhibit"] = lambda p, src="": Markup(proof.to_html(p, src))
    tmpl = env.from_string(TEMPLATE)
    open_ = [f for f in result["findings"] if f["severity"] != "pass" and not f.get("suppression")]
    active = [f for f in open_ if not f["third_party"]]
    third = [f for f in open_ if f["third_party"]]
    suppressed = [f for f in result["findings"] if f.get("suppression")]
    passed = [f for f in result["findings"] if f["severity"] == "pass"]
    counts = defaultdict(int)
    fcounts = defaultdict(int)
    for f in active:
        counts[f["severity"]] += 1
        if f["severity"] != "info":
            fcounts[f["factor"]] += 1
    for f in result["findings"]:
        f["_shot"] = _data_uri(f.get("screenshot"), outdir)
    for a in result["assets"]:
        a["_shot"] = _data_uri(a.get("screenshot"), outdir)
    page = tmpl.render(
        r=result, factors=kb.FACTORS, groups=_group(active, result["domain"]),
        third=_group(third, result["domain"]), passed=passed, suppressed=suppressed,
        counts=counts, fcounts=fcounts, summary=summary_sentence(result), delta=delta,
        coverage=coverage_warnings(result),
        scoring_doc=scoring.__doc__, exhibit_css=Markup(proof.EXHIBIT_CSS),
        favicon=brand.favicon_data_uri(), logo=Markup(brand.LOGO_INLINE_SVG), tagline=brand.TAGLINE,
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    for f in result["findings"]:
        f.pop("_shot", None)
    for a in result["assets"]:
        a.pop("_shot", None)


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Rating — {{ r.client }}</title>
<link rel="icon" type="image/svg+xml" href="{{ favicon }}">
<script>
(function(){var t=null;try{t=localStorage.getItem("openscore-theme")}catch(_){}
if(t!=="dark"&&t!=="light"){t=(window.matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light"}
document.documentElement.setAttribute("data-theme",t)})();
</script>
<style>
:root{--ink:#16202a;--muted:#5d6b78;--line:#e3e8ee;--bg:#f6f8fa;--card:#fff;
--crit:#8b1a1a;--high:#c2410c;--med:#b7791f;--low:#2b6cb0;--info:#64748b;--pass:#2f855a;
--A:#2f855a;--B:#5a9e3a;--C:#b7791f;--D:#c2410c;--F:#8b1a1a;
--link:#1d4ed8;--code-bg:#eef2f6;--th-bg:#f0f3f7;--btn-bg:#fff;--toast-bg:#16202a;--pre-line:transparent;
--fix-bg:#f0fff4;--fix-line:#c6f6d5;--verify-bg:#ebf8ff;--verify-line:#bee3f8;
--note-bg:#fffbea;--note-line:#f6e05e;--tent-bg:#fffaf0;--tent-line:#f6ad55;--tent-ink:#9c4221;--logo-accent:#7C3AED;color-scheme:light}
/* Dark theme: screen only, so printing / "Save as PDF" always uses the light palette. */
@media screen{:root[data-theme=dark]{--ink:#e6edf3;--muted:#9aa7b4;--line:#30363d;--bg:#0d1117;--card:#161b22;
--crit:#d1453f;--high:#d9622b;--med:#b8841c;--low:#3b7dc4;--info:#6e7c8a;--pass:#2f8a52;
--A:#2f8a52;--B:#4f9a33;--C:#b8841c;--D:#d9622b;--F:#d1453f;
--link:#6cb6ff;--code-bg:#262c36;--th-bg:#1c2128;--btn-bg:#21262d;--toast-bg:#30363d;--pre-line:#30363d;
--fix-bg:rgba(46,160,67,.12);--fix-line:rgba(46,160,67,.45);--verify-bg:rgba(56,139,253,.12);--verify-line:rgba(56,139,253,.45);
--note-bg:rgba(187,128,9,.13);--note-line:rgba(210,153,34,.5);--tent-bg:rgba(187,128,9,.15);--tent-line:#d29922;--tent-ink:#e3b341;--logo-accent:#A78BFA;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 -apple-system,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 80px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:40px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin:24px 0 8px}
.muted{color:var(--muted)}.small{font-size:13px}
.cov{margin:10px 0 0;padding:8px 12px;border:1px solid var(--med);border-left-width:4px;border-radius:6px;font-size:14px}
code{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code-bg);padding:1px 5px;border-radius:4px;word-break:break-word}
pre{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#0f1720;color:#e6edf3;border:1px solid var(--pre-line);padding:10px 12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;margin:6px 0}
a{color:var(--link)}
.hero{display:flex;gap:28px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px}
.gradebig{flex:none;width:118px;height:118px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#fff}
.gradebig b{font-size:52px;line-height:1}.gradebig span{font-size:14px;opacity:.9}
.g-A{background:var(--A)}.g-B{background:var(--B)}.g-C{background:var(--C)}.g-D{background:var(--D)}.g-F{background:var(--F)}
.c-A{color:var(--A)}.c-B{color:var(--B)}.c-C{color:var(--C)}.c-D{color:var(--D)}.c-F{color:var(--F)}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.pill{font-size:12px;font-weight:600;padding:3px 9px;border-radius:999px;color:#fff;text-transform:uppercase;letter-spacing:.03em}
.s-critical{background:var(--crit)}.s-high{background:var(--high)}.s-medium{background:var(--med)}.s-low{background:var(--low)}.s-info{background:var(--info)}.s-pass{background:var(--pass)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.fac{display:flex;justify-content:space-between;align-items:baseline}.fac b{font-size:28px}
.bar{height:6px;background:var(--line);border-radius:3px;margin:8px 0 6px;overflow:hidden}.bar i{display:block;height:100%}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--th-bg);font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}
td code{white-space:nowrap}
details.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;margin:8px 0}
details.f[data-s=critical]{border-left-color:var(--crit)}details.f[data-s=high]{border-left-color:var(--high)}
details.f[data-s=medium]{border-left-color:var(--med)}details.f[data-s=low]{border-left-color:var(--low)}
details.f summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:center;list-style:none}
details.f summary::-webkit-details-marker{display:none}
details.f .body{padding:0 16px 14px}
.fix{background:var(--fix-bg);border:1px solid var(--fix-line);border-radius:6px;padding:10px 12px;margin-top:8px}
.why{margin-top:6px}
.tag{font-size:11px;border:1px solid var(--line);border-radius:4px;padding:1px 6px;color:var(--muted)}
.tag.tent{border-color:var(--tent-line);color:var(--tent-ink);background:var(--tent-bg)}
.verify{background:var(--verify-bg);border:1px solid var(--verify-line);border-radius:6px;padding:10px 12px;margin-top:8px}
.triage{margin-left:8px;white-space:nowrap}
button.fp{font:inherit;font-size:11px;margin-left:6px;padding:1px 8px;border:1px solid var(--line);border-radius:4px;background:var(--btn-bg);color:var(--muted);cursor:pointer}
button.fp:hover{border-color:var(--link);color:var(--link)}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--toast-bg);color:#fff;padding:8px 16px;border-radius:6px;font-size:13px;display:none}
#theme-toggle{position:fixed;top:14px;right:14px;z-index:50;font:inherit;font-size:13px;padding:5px 12px;
  border:1px solid var(--line);border-radius:999px;background:var(--card);color:var(--ink);cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.12)}
#theme-toggle:hover{border-color:var(--link)}
@media print{.triage,#theme-toggle{display:none}}
.brandbar{margin:4px 0 18px}
.os-logo{height:30px;width:auto;display:block}
.os-ink{fill:var(--ink)}
.os-accent{fill:var(--logo-accent)}
{{ exhibit_css }}
@media print{.exhibit{break-inside:avoid;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
img.shot{display:block;max-width:460px;width:100%;margin:8px 0;border:1px solid var(--line);border-radius:6px;cursor:zoom-in;box-shadow:0 1px 3px rgba(0,0,0,.08)}
img.shot.thumb{max-width:150px;margin:0}
#lightbox{position:fixed;inset:0;background:rgba(10,15,20,.85);display:none;align-items:center;justify-content:center;z-index:99;cursor:zoom-out}
#lightbox img{max-width:95vw;max-height:92vh;border-radius:6px}
@media print{img.shot{max-width:100%;page-break-inside:avoid}img.shot.thumb{max-width:120px}}
.delta-up{color:var(--pass);font-weight:700}.delta-down{color:var(--crit);font-weight:700}
.note{background:var(--note-bg);border:1px solid var(--note-line);border-radius:8px;padding:10px 14px;margin:10px 0}
@media print{body{background:#fff}.wrap{padding:0}details.f{break-inside:avoid}details.f .body{display:block}details:not([open]) .body{display:block}}
@media (max-width:640px){.hero{flex-direction:column;text-align:center}}
</style></head><body>
<button id="theme-toggle" type="button" title="Switch between light and dark mode (printing always uses light)">Dark mode</button>
<div class="wrap">
<div class="brandbar">{{ logo }}</div>

<div class="hero">
  <div class="gradebig g-{{ r.overall.grade }}"><b>{{ r.overall.grade }}</b><span>{{ "%.0f"|format(r.overall.score) }}/100</span></div>
  <div>
    <h1>{{ r.client }} — External Security Rating</h1>
    <div class="muted">{{ r.domain }} · scanned {{ r.started[:16].replace("T"," ") }} UTC · mode: <b>{{ r.mode }}</b>
    {% if r.authorization %} · authorization: {{ r.authorization }}{% endif %}</div>
    <p style="margin:10px 0 0">{{ summary }}</p>
    {% for w in coverage %}<div class="cov"><b>Coverage gap</b> — {{ w }}</div>{% endfor %}
    <div class="pills">
      {% for s in ["critical","high","medium","low","info"] %}{% if counts[s] %}<span class="pill s-{{s}}">{{ counts[s] }} {{ s }}</span>{% endif %}{% endfor %}
      <span class="pill s-pass">{{ passed|length }} passed</span>
    </div>
  </div>
</div>

{% if delta %}
<h2>Change since last scan</h2>
<div class="card">
  <div class="small muted">Compared with {% if delta.baseline_file %}<code>{{ delta.baseline_file }}</code>, {% endif %}scanned {{ (delta.baseline_date or "")[:16]|replace("T", " ") }} UTC{% if delta.baseline_mode %} ({{ delta.baseline_mode }}{% if delta.baseline_assets %}, {{ delta.baseline_assets }} assets{% endif %}){% endif %}. Use <code>--baseline FILE</code> to pick another scan.</div>
  {% if delta.caveats %}<div class="note">Not a like-for-like comparison: {{ delta.caveats|join("; ") }}. Some new or resolved items below may reflect what each scan looked at, not changes on your side.</div>{% endif %}
  {{ (delta.baseline_date or "")[:10] }}: {{ "%.0f"|format(delta.baseline_score) }} ({{ delta.baseline_grade }}) → now {{ "%.0f"|format(r.overall.score) }} ({{ r.overall.grade }})
  <span class="{{ 'delta-up' if delta.delta >= 0 else 'delta-down' }}">{{ "%+.1f"|format(delta.delta) }}</span>
  · <b>{{ delta.resolved|length }}</b> resolved · <b>{{ delta.new|length }}</b> new
  {% if delta.new %}<h3>New</h3><ul>{% for f in delta.new %}<li><span class="pill s-{{f.severity}}">{{f.severity}}</span> {{ f.title }} — <code>{{ f.asset }}</code></li>{% endfor %}</ul>{% endif %}
  {% if delta.resolved %}<h3>Resolved</h3><ul>{% for f in delta.resolved %}<li><span class="pill s-{{f.severity}}">{{f.severity}}</span> {{ f.title }} — <code>{{ f.asset }}</code></li>{% endfor %}</ul>{% endif %}
</div>
{% endif %}

<h2>Factor scores</h2>
<div class="grid">
{% for key, fac in factors.items() %}{% set s = r.overall.factors[key] %}
  <div class="card">
    <div class="fac"><div><b class="{% if s %}c-{{ s.grade }}{% endif %}">{{ s.grade if s else "–" }}</b></div>
      <div class="muted small">{{ ("%.0f"|format(s.score)) ~ "/100" if s else "not assessed" }}</div></div>
    <div style="font-weight:600">{{ fac.name }}</div>
    <div class="bar"><i class="g-{{ s.grade if s else 'A' }}" style="width:{{ s.score if s else 0 }}%"></i></div>
    <div class="muted small">{{ fcounts[key] }} issue{{ "" if fcounts[key]==1 else "s" }} · {{ fac.desc }}</div>
  </div>
{% endfor %}
</div>

{% if r.quick_wins %}
<h2>Priority fixes (biggest score gain first)</h2>
<table><tr><th>Fix</th><th>Severity</th><th>Factor</th><th>Assets</th><th>Score gain</th></tr>
{% for w in r.quick_wins %}<tr><td>{{ w.title }}</td><td><span class="pill s-{{ w.severity }}">{{ w.severity }}</span></td>
<td>{{ factors[w.factor].name }}</td><td class="small">{% for a in w.assets[:4] %}{{ a }}{% set hs = (r.ip_hosts or {}).get(a) %}{% if hs %} ({{ hs[0].host }}{% if hs|length > 1 %} +{{ hs|length - 1 }}{% endif %}){% endif %}{% if not loop.last %}, {% endif %}{% endfor %}{% if w.assets|length > 4 %} +{{ w.assets|length-4 }} more{% endif %}</td>
<td><b>+{{ "%.1f"|format(w.gain) }}</b></td></tr>{% endfor %}
</table>
{% endif %}

<h2>Findings &amp; remediation</h2>
{% for key, gs in groups.items() %}{% if gs %}
<h3>{{ factors[key].name }}</h3>
{% for g in gs %}
<details class="f" data-s="{{ g.severity }}" {% if g.severity in ["critical","high"] %}open{% endif %}>
  <summary><span class="pill s-{{ g.severity }}">{{ g.severity }}</span><b>{{ g.title }}</b>
  <span class="muted small">{{ g.entries|length }} asset{{ "" if g.entries|length==1 else "s" }}</span>
  {% if g.tentative %}<span class="tag">needs verification</span>{% endif %}</summary>
  <div class="body">
    {% if g.description %}<div class="why"><b>Why it matters:</b> {{ g.description|safe }}</div>{% endif %}
    {% for i in g.entries %}<div class="small" style="margin-top:8px"><code>{{ i.asset }}</code>{% if i.hosts %}
    <span class="muted">sites on this IP:</span> {% for h in i.hosts[:6] %}{% if h.url %}<a href="{{ h.url }}">{{ h.url }}</a>{% else %}<code>{{ h.host }}</code>{% endif %}{% if not loop.last %}, {% endif %}{% endfor %}{% if i.hosts|length > 6 %} +{{ i.hosts|length - 6 }} more{% endif %}{% endif %}
    <span class="tag">{{ i.source }}</span>
    {% if i.confidence == "tentative" %}<span class="tag tent">needs verification</span>{% endif %}
    <span class="triage"><span class="muted small">Triage:</span>{% for st, label, toml in i.triage %}<button class="fp" data-toml="{{ toml }}" data-label="{{ label }}" title="Copy a suppressions-file entry ({{ label|lower }}) for this finding">{{ label }}</button>{% endfor %}</span></div>
    {% if i.proof %}{{ i.proof|exhibit(i.source) }}{% elif i.evidence %}<pre>{{ i.evidence }}</pre>{% endif %}
    {% if i._shot %}<div class="small muted" style="margin-top:6px">Page screenshot</div>
    <img class="shot" src="{{ i._shot }}" alt="Screenshot evidence for {{ i.asset }}" title="Click to enlarge">{% endif %}{% endfor %}
    {% if g.verify %}<div class="verify"><b>How to verify:</b> {{ g.verify|safe }}</div>{% endif %}
    {% if g.remediation %}<div class="fix"><b>How to fix:</b> {{ g.remediation|safe }}
    {% if g.refs %}<div class="small" style="margin-top:6px">{% for ref in g.refs %}<a href="{{ ref }}">{{ ref }}</a>{% if not loop.last %} · {% endif %}{% endfor %}</div>{% endif %}</div>{% endif %}
  </div>
</details>
{% endfor %}{% endif %}{% endfor %}
{% if not counts %}<p>No issues found.</p>{% endif %}

{% set has_third = namespace(v=false) %}{% for k, gs in third.items() %}{% if gs %}{% set has_third.v = true %}{% endif %}{% endfor %}
{% if has_third.v %}
<h2>Third-party hosted (excluded from score)</h2>
<div class="note">These hosts resolve to SaaS providers (e.g. Microsoft 365 autodiscover, a marketing platform). The provider controls these settings.
If an external assessment counts them against you, <b>dispute them as third-party infrastructure</b>.</div>
{% for key, gs in third.items() %}{% for g in gs %}
<details class="f" data-s="{{ g.severity }}"><summary><span class="pill s-{{ g.severity }}">{{ g.severity }}</span><b>{{ g.title }}</b>
<span class="muted small">{{ g.entries|map(attribute="asset")|unique|join(", ") }}</span></summary>
<div class="body">{% for i in g.entries %}<pre>{{ i.asset }}: {{ i.evidence }}</pre>{% endfor %}</div></details>
{% endfor %}{% endfor %}
{% endif %}

{% if suppressed or (r.suppressions and (r.suppressions.expired or r.suppressions.unused)) %}
<h2>Suppressed findings ({{ suppressed|length }})</h2>
<div class="note small">Triaged in the suppressions file as a false positive, an accepted risk or covered by a compensating control — excluded from the score. Expiring entries come back automatically.</div>
{% if suppressed %}<table><tr><th>Finding</th><th>Asset</th><th>Status</th><th>Reason</th><th>Approved</th><th>Expires</th></tr>
{% for f in suppressed %}<tr><td><span class="pill s-{{ f.severity }}">{{ f.severity }}</span> {{ f.title }}</td><td><code>{{ f.asset }}</code></td>
<td>{{ f.suppression.status.replace("_"," ") }}</td><td class="small">{{ f.suppression.reason }}{% if f.suppression.control %}<br><b>Control:</b> {{ f.suppression.control }}{% endif %}</td>
<td class="small">{{ f.suppression.approved_by }}</td><td class="small">{{ f.suppression.expires or "never" }}</td></tr>{% endfor %}</table>{% endif %}
{% if r.suppressions.expired %}<div class="note small"><b>Expired suppressions (findings are counted again):</b><br>{{ r.suppressions.expired|join("<br>")|safe }}</div>{% endif %}
{% if r.suppressions.unused %}<div class="note small"><b>Suppressions that matched nothing (issue fixed? remove them):</b><br>{{ r.suppressions.unused|join("<br>") }}</div>{% endif %}
{% endif %}

{% if passed %}
<h2>Passed checks</h2>
<table><tr><th>Check</th><th>Asset</th><th>Detail</th></tr>
{% for f in passed %}<tr><td>✅ {{ f.title }}</td><td><code>{{ f.asset }}</code></td><td class="small">{{ f.evidence[:180] }}</td></tr>{% endfor %}
</table>
{% endif %}

<h2>Asset inventory</h2>
<div class="note small">Automated scanners attribute IPs to organizations from DNS and registry data and often get it wrong (old IPs, shared hosting, vendor infrastructure).
Check this list and flag anything that isn't yours.</div>
<table><tr><th>Host</th><th>IPs</th><th>Hosting (ASN)</th><th>Class</th><th>Web</th><th>Preview</th></tr>
{% for a in r.assets %}<tr>
<td><code>{{ a.host }}</code>{% if a.cnames %}<div class="muted small">→ {{ a.cnames|join(" → ") }}</div>{% endif %}</td>
<td class="small">{{ a.ips[:4]|join(", ") }}{% if a.ips|length>4 %} +{{ a.ips|length-4 }}{% endif %}</td>
<td class="small">{% for ip, h in a.hosting.items() %}{% if h.org %}{{ h.org }} (AS{{ h.asn }}){% if not loop.last %}<br>{% endif %}{% endif %}{% endfor %}</td>
<td><span class="tag">{{ a.hosting_class }}</span></td>
<td class="small">{% for u, w in a.web.items() %}{% if w.status %}{{ w.status }} {{ w.title[:50] }}{% if w.note %} <span class="muted">({{ w.note }})</span>{% endif %}<br>{% endif %}{% endfor %}</td>
<td>{% if a._shot %}<img class="shot thumb" src="{{ a._shot }}" alt="{{ a.host }} homepage" title="Click to enlarge">{% endif %}</td>
</tr>{% endfor %}
</table>

<h2>Methodology</h2>
<div class="card small">
<p><b>Mode:</b> {{ r.mode }}. Passive checks query public DNS, certificate transparency and threat-intel APIs without touching the target.
Light checks behave like a normal browser visit (TLS handshake, homepage, security.txt).
{% if r.mode == "active" %}Active checks (port scan, well-known-path probes, CORS probe, and nuclei safe-tag templates / testssl.sh when installed) ran under the authorization noted above; every action is listed in the audit log.{% else %}Active checks were not run.{% endif %}</p>
<p><b>Assessed factors:</b> {{ r.assessed_factors|map("title")|join(", ") }}</p>
<pre>{{ scoring_doc.strip() }}</pre>
{% if r.module_status %}<p><b>Module notes:</b></p><pre>{% for m, st in r.module_status.items() %}{{ m }}: {{ st }}
{% endfor %}</pre>{% endif %}
{% if r.audit %}<details><summary>Audit log ({{ r.audit|length }} entries)</summary><pre>{{ r.audit|join("\n") }}</pre></details>{% endif %}
<p class="muted">Generated by OpenScore {{ r.version }} · {{ tagline }} Version-based vulnerability matches are marked “needs verification”.</p>
</div>
</div>
<div id="lightbox"><img alt=""></div>
<div id="toast" data-file="suppressions/{{ r.domain }}.toml">Copied</div>
<script>
(function(){var b=document.getElementById("theme-toggle"),root=document.documentElement;
function label(){b.textContent=root.getAttribute("data-theme")==="dark"?"\u2600 Light mode":"\u263E Dark mode"}
b.addEventListener("click",function(){var t=root.getAttribute("data-theme")==="dark"?"light":"dark";
  root.setAttribute("data-theme",t);try{localStorage.setItem("openscore-theme",t)}catch(_){}label()});
label()})();
(function(){var lb=document.getElementById("lightbox"),li=lb.querySelector("img");
document.querySelectorAll("img.shot").forEach(function(i){i.addEventListener("click",function(){li.src=i.src;lb.style.display="flex"})});
lb.addEventListener("click",function(){lb.style.display="none"});
document.addEventListener("keydown",function(e){if(e.key==="Escape")lb.style.display="none"})})();
document.querySelectorAll("button.fp").forEach(function(b){b.addEventListener("click",function(e){
  e.preventDefault();var t=b.getAttribute("data-toml");
  function done(){var x=document.getElementById("toast");
    x.textContent="Copied \u201c"+b.getAttribute("data-label")+"\u201d entry \u2014 paste into "+x.getAttribute("data-file")+" and fill in the blanks";
    x.style.display="block";setTimeout(function(){x.style.display="none"},3000)}
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(done,fallback)}else{fallback()}
  function fallback(){var a=document.createElement("textarea");a.value=t;document.body.appendChild(a);a.select();
    try{document.execCommand("copy");done()}catch(_){prompt("Copy this into your suppressions file:",t)}a.remove()}
})});
</script></body></html>
"""
