"""Build the OpenScore website (GitHub Pages) and docs/faq.md.

    python3 website/build.py --out _site [--base-url URL] [--sample REPORT.html]
    python3 website/build.py --faq-md        # rewrite docs/faq.md from website/faq.py
    python3 website/build.py --check         # exit 1 if docs/faq.md is out of date

The site is static HTML with self-hosted fonts and no third-party requests. Factor names, check
counts and the example finding come from openscore.kb, and the FAQ from website/faq.py, so the
site, docs/faq.md and the FAQ schema can't drift apart.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import importlib.util
import json
import math
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: E402
from markupsafe import Markup  # noqa: E402

from openscore import __version__, kb  # noqa: E402

DEFAULT_BASE = "https://himynameislee.github.io/OpenScore/"
FAQ_MD = os.path.join(ROOT, "docs", "faq.md")


def _load_faq():
    spec = importlib.util.spec_from_file_location("openscore_site_faq", os.path.join(HERE, "faq.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FAQMOD = _load_faq()
REPO, DOCS, FAQ = FAQMOD.REPO, FAQMOD.DOCS, FAQMOD.FAQ

LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
CODE = re.compile(r"`([^`]+)`")


# ----------------------------------------------------------------------------- text helpers
def schema_text(text: str) -> str:
    """Markdown -> Answer text for the schema: same words as the page, links kept as <a> (allowed in
    schema.org Answer text), code ticks dropped. Stripping tags from either gives identical text."""
    out = html.escape(text.replace("`", ""), quote=False)
    return LINK.sub(lambda m: f'<a href="{html.escape(m.group(2))}">{m.group(1)}</a>', out)


def inline_html(text: str) -> Markup:
    """The small Markdown subset used in the FAQ and KB text -> safe HTML."""
    out = html.escape(text, quote=False)
    out = CODE.sub(lambda m: f"<code>{m.group(1)}</code>", out)
    out = LINK.sub(lambda m: f'<a href="{html.escape(m.group(2))}">{m.group(1)}</a>', out)
    return Markup(out)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def answer(lead: str, more: str) -> str:
    return lead + (" " + more if more else "")


# ----------------------------------------------------------------------------- docs/faq.md
def faq_md() -> str:
    rel = lambda t: t.replace(DOCS, "")  # noqa: E731  (docs link to each other relatively)
    out = ["<!-- Generated from website/faq.py by `python3 website/build.py --faq-md`. "
           "Don't edit by hand. -->\n\n",
           "# OpenScore FAQ\n\n",
           "Answers to common questions about OpenScore, the free, open-source external security "
           "rating tool. For the full documentation, see the [docs index](README.md).\n"]
    for section, items in FAQ:
        out.append(f"\n## {section}\n")
        for q, lead, more in items:
            out.append(f"\n### {q}\n\n{rel(answer(lead, more))}\n")
    return "".join(out)


def faq_md_stale() -> bool:
    try:
        with open(FAQ_MD, encoding="utf-8") as fh:
            return fh.read() != faq_md()
    except OSError:
        return True


# ----------------------------------------------------------------------------- structured data
def software_ld(base: str) -> dict:
    return {
        "@type": "SoftwareApplication", "@id": base + "#software",
        "name": "OpenScore",
        "alternateName": "OpenScore external security rating",
        "description": "Free, open-source external security rating and attack-surface review tool. "
                       "Grades a domain A-F across eight factors, with evidence, verify commands and "
                       "remediation for every finding.",
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Linux, Windows",
        "softwareVersion": __version__,
        "license": "https://opensource.org/license/mit",
        "isAccessibleForFree": True,
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
        "url": base,
        "downloadUrl": REPO + "/releases",
        "sameAs": [REPO],
    }


def faq_ld(base: str) -> dict:
    page = base + "faq/"
    return {
        "@context": "https://schema.org",
        "@graph": [
            software_ld(base),
            {"@type": "FAQPage", "@id": page + "#faq", "url": page,
             "about": {"@id": base + "#software"},
             "mainEntity": [{"@type": "Question", "name": q,
                             "acceptedAnswer": {"@type": "Answer", "text": schema_text(answer(lead, more))}}
                            for _, items in FAQ for q, lead, more in items]},
        ],
    }


def home_ld(base: str) -> dict:
    return {"@context": "https://schema.org", "@graph": [
        {"@type": "WebSite", "@id": base + "#website", "url": base, "name": "OpenScore",
         "about": {"@id": base + "#software"}},
        software_ld(base)]}


def ld_script(data: dict) -> Markup:
    # "</" can't appear inside a <script> element
    return Markup(json.dumps(data, indent=2, ensure_ascii=False).replace("</", "<\\/"))


# ----------------------------------------------------------------------------- the Aperture diagram
# Clockwise from the top, matching the eight segments (and colors) of the brand mark.
RING = [("email", "Email security", "#6C6BF6"), ("dns", "DNS health", "#417FF6"),
        ("tls", "TLS", "#417FF6"), ("appsec", "Web apps", "#6C6BF6"),
        ("network", "Network", "#AD54B5"), ("patching", "Patching", "#DE4A5A"),
        ("reputation", "Reputation", "#DE4A5A"), ("exposure", "Exposure", "#AD54B5")]


def aperture_svg() -> Markup:
    cx, cy, r, sw = 310, 230, 128, 40
    gap = 7.0                                   # degrees between segments, as in the mark

    def pt(rad, deg):
        a = math.radians(deg)
        return cx + rad * math.sin(a), cy - rad * math.cos(a)

    parts = ['<svg class="aperture" viewBox="0 0 620 460" role="img" '
             'aria-labelledby="ap-title ap-desc">'
             '<title id="ap-title">The OpenScore mark as a diagram of the eight factors</title>'
             '<desc id="ap-desc">Eight ring segments, one per scored factor: email security, DNS '
             'health, TLS, web application security, network exposure, patching, reputation and '
             'information exposure. The block at the center stands for the evidence behind every '
             'finding.</desc>']
    for i, (key, label, color) in enumerate(RING):
        a0, a1 = i * 45 + gap / 2, (i + 1) * 45 - gap / 2
        (x0, y0), (x1, y1) = pt(r, a0), pt(r, a1)
        mid = i * 45 + 22.5
        (lx0, ly0), (lx1, ly1), (tx, ty) = pt(r + sw / 2 + 6, mid), pt(r + 52, mid), pt(r + 60, mid)
        anchor = "start" if tx > cx else "end"
        parts.append(
            f'<a href="#f-{key}" class="seg" style="--i:{i}">'
            f'<path d="M{x0:.2f} {y0:.2f}A{r} {r} 0 0 1 {x1:.2f} {y1:.2f}" stroke="{color}" '
            f'stroke-width="{sw}" fill="none" pathLength="1"/>'
            f'<line x1="{lx0:.1f}" y1="{ly0:.1f}" x2="{lx1:.1f}" y2="{ly1:.1f}"/>'
            f'<text x="{tx:.1f}" y="{ty + 6:.1f}" text-anchor="{anchor}">{label}</text></a>')
    s = 64
    parts.append(f'<rect class="core" x="{cx - s / 2}" y="{cy - s / 2}" width="{s}" height="{s}" rx="11"/>')
    parts.append("</svg>")
    return Markup("".join(parts))


# ----------------------------------------------------------------------------- page data
def factors():
    counts = {}
    for c in kb.CHECKS.values():
        if c["severity"] != "pass":
            counts[c["factor"]] = counts.get(c["factor"], 0) + 1
    colors = {k: col for k, _, col in RING}
    return [{"key": k, "name": kb.FACTORS[k]["name"], "desc": kb.FACTORS[k]["desc"],
             "weight": kb.FACTORS[k]["weight"], "checks": counts.get(k, 0), "color": colors[k]}
            for k, _, _ in RING]


def example_finding():
    c = kb.CHECKS["http_hsts_missing"]
    verify = kb.VERIFY["http_hsts_missing"].replace("{url}", "https://www.example.com/") \
                                            .replace("{asset}", "www.example.com")
    return {
        "severity": c["severity"], "title": c["title"], "asset": "www.example.com",
        "description": inline_html(c["description"]), "remediation": inline_html(c["remediation"]),
        "verify": inline_html(verify),
        "lines": [("$ curl -sI https://www.example.com/", "cmd"),
                  ("HTTP/2 200", ""),
                  ("content-type: text/html; charset=utf-8", ""),
                  ("server: nginx", ""),
                  ("strict-transport-security: (not present)", "bad"),
                  ("x-content-type-options: nosniff", ""),
                  ("x-frame-options: SAMEORIGIN", "")],
    }


def faq_sections():
    return [{"title": section, "id": slug(section),
             "items": [{"q": q, "id": slug(q), "a": inline_html(answer(lead, more))}
                       for q, lead, more in items]}
            for section, items in FAQ]


PREVIEW = ["Is OpenScore free?", "Do I need permission to scan a domain with OpenScore?",
           "Does OpenScore exploit vulnerabilities?", "Does OpenScore send my scan results anywhere?"]


# ----------------------------------------------------------------------------- build
BRAND_FILES = {"openscore-logo-light.svg": "logo-light.svg", "openscore-logo-dark.svg": "logo-dark.svg",
               "favicon.svg": "favicon.svg", "social-preview.png": "social-preview.png",
               "openscore-avatar-512.png": "icon-512.png"}


def build(out: str, base: str, sample: str | None = None) -> list[str]:
    base = base.rstrip("/") + "/"
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(os.path.join(out, "assets"))
    shutil.copytree(os.path.join(HERE, "assets", "fonts"), os.path.join(out, "assets", "fonts"))
    shutil.copy(os.path.join(HERE, "assets", "site.css"), os.path.join(out, "assets", "site.css"))
    shutil.copy(os.path.join(HERE, "assets", "site.js"), os.path.join(out, "assets", "site.js"))
    for src, dst in BRAND_FILES.items():
        shutil.copy(os.path.join(ROOT, "docs", "brand", src), os.path.join(out, "assets", dst))
    has_sample = bool(sample)
    if sample:
        shutil.copy(sample, os.path.join(out, "sample-report.html"))

    env = Environment(loader=FileSystemLoader(os.path.join(HERE, "templates")),
                      autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
    sections = faq_sections()
    by_q = {i["q"]: i for s in sections for i in s["items"]}
    common = dict(base=base, repo=REPO, docs=DOCS, version=__version__, has_sample=has_sample,
                  year=dt.date.today().year)
    pages = {
        "index.html": env.get_template("index.html").render(
            **common, page_url=base, ld=ld_script(home_ld(base)), aperture=aperture_svg(),
            factors=factors(), finding=example_finding(), preview=[by_q[q] for q in PREVIEW],
            faq_count=sum(len(s["items"]) for s in sections)),
        "faq/index.html": env.get_template("faq.html").render(
            **common, nav="faq", page_url=base + "faq/", ld=ld_script(faq_ld(base)), sections=sections),
        "404.html": env.get_template("404.html").render(**common, page_url=base),
    }
    for rel, text in pages.items():
        path = os.path.join(out, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    today = dt.date.today().isoformat()
    urls = [base, base + "faq/"]
    with open(os.path.join(out, "sitemap.xml"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write('<?xml version="1.0" encoding="UTF-8"?>\n'
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
        for u in urls:
            fh.write(f"  <url><loc>{html.escape(u)}</loc><lastmod>{today}</lastmod></url>\n")
        fh.write("</urlset>\n")
    with open(os.path.join(out, "robots.txt"), "w", encoding="utf-8", newline="\n") as fh:
        # The sample report is lab data; keep it out of search results and AI answers.
        fh.write(f"User-agent: *\nAllow: /\nDisallow: {_path(base)}sample-report.html\n\n"
                 f"Sitemap: {base}sitemap.xml\n")
    return sorted(os.path.relpath(os.path.join(d, f), out) for d, _, fs in os.walk(out) for f in fs)


def _path(base: str) -> str:
    m = re.match(r"https?://[^/]+(/.*)", base)
    return m.group(1) if m else "/"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python3 website/build.py")
    ap.add_argument("--out", help="Build the site into this directory")
    ap.add_argument("--base-url", default=DEFAULT_BASE, help=f"Public URL of the site (default {DEFAULT_BASE})")
    ap.add_argument("--sample", help="A lab-target HTML report to publish as sample-report.html")
    ap.add_argument("--faq-md", action="store_true", help="Rewrite docs/faq.md from website/faq.py")
    ap.add_argument("--check", action="store_true", help="Exit 1 if docs/faq.md is out of date")
    a = ap.parse_args(argv)
    if a.check:
        if faq_md_stale():
            print("docs/faq.md is out of date: run python3 website/build.py --faq-md")
            return 1
        return 0
    if a.faq_md:
        with open(FAQ_MD, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(faq_md())
        print("wrote docs/faq.md")
    if a.out:
        files = build(a.out, a.base_url, a.sample)
        print(f"built {len(files)} files into {a.out}")
    if not (a.out or a.faq_md):
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
