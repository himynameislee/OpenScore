"""The website (website/) builds, its FAQ schema matches the visible text, and docs/faq.md is current."""
import html
import importlib.util
import json
import os
import re
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SITE = os.path.join(ROOT, "website", "build.py")
BASE = "https://example.github.io/OpenScore/"


def _build_mod():
    spec = importlib.util.spec_from_file_location("openscore_site_build", SITE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _text(fragment: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", fragment)).split())


def _ld(page: str) -> dict:
    m = re.search(r'<script type="application/ld\+json">(.*?)</script>', page, re.S)
    return json.loads(m.group(1))


def test_site_builds_and_faq_schema_matches_page():
    if not os.path.exists(SITE):          # sdist / Debian build dir ship without website/
        return
    b = _build_mod()
    assert not b.faq_md_stale(), "run: python3 website/build.py --faq-md"
    with tempfile.TemporaryDirectory() as d:
        sample = os.path.join(d, "report.html")
        with open(sample, "w", encoding="utf-8") as fh:
            fh.write("<html>lab</html>")
        out = os.path.join(d, "site")
        files = b.build(out, BASE, sample)
        for f in ("index.html", "faq/index.html", "404.html", "sitemap.xml", "robots.txt",
                  "sample-report.html", "assets/site.css", "assets/favicon.svg"):
            assert f in files, f
        with open(os.path.join(out, "faq", "index.html"), encoding="utf-8") as fh:
            faq = fh.read()
        with open(os.path.join(out, "index.html"), encoding="utf-8") as fh:
            home = fh.read()
        with open(os.path.join(out, "robots.txt"), encoding="utf-8") as fh:
            robots = fh.read()

        # FAQPage: every question and answer is on the page, word for word
        graph = {n["@type"]: n for n in _ld(faq)["@graph"]}
        qa = graph["FAQPage"]["mainEntity"]
        assert len(qa) == sum(len(items) for _, items in b.FAQ) >= 15
        visible = {_text(q): _text(a) for q, a in re.findall(
            r'<h3 id="[^"]+"><a class="anchor"[^>]*>(.*?)</a></h3>\s*<p>(.*?)</p>', faq, re.S)}
        for item in qa:
            assert visible[item["name"]] == _text(item["acceptedAnswer"]["text"]), item["name"]
        assert graph["FAQPage"]["url"] == BASE + "faq/"
        assert graph["FAQPage"]["about"]["@id"] == graph["SoftwareApplication"]["@id"]
        assert '<link rel="canonical" href="%sfaq/">' % BASE in faq
        assert "<\\/" not in json.dumps(qa) and "</script" not in faq.split("application/ld+json")[1].split("</script>")[0]

        # home page: structured data, the KB-driven example and factor list, the sample link
        assert {n["@type"] for n in _ld(home)["@graph"]} == {"WebSite", "SoftwareApplication"}
        assert 'href="%ssample-report.html"' % BASE in home
        from openscore import kb
        assert kb.CHECKS["http_hsts_missing"]["title"] in home
        for f in kb.FACTORS.values():
            assert html.escape(f["name"]) in home
        assert "Disallow: /OpenScore/sample-report.html" in robots and "Sitemap: %ssitemap.xml" % BASE in robots

        # no third-party requests: every stylesheet, script, font and image is local
        for page in (home, faq):
            for url in re.findall(r'(?:src|href)="([^"]+)"', page):
                if url.endswith((".css", ".js", ".woff2", ".svg", ".png")):
                    assert url.startswith(BASE + "assets/"), url
            for url in re.findall(r'href="(%s[^"#]*)' % re.escape(BASE), page):
                rel = url[len(BASE):] or "index.html"
                if rel.endswith("/"):
                    rel += "index.html"
                assert rel in files, url


if __name__ == "__main__":
    sys.path.insert(0, ROOT)
    test_site_builds_and_faq_schema_matches_page()
    print("ok  test_site_builds_and_faq_schema_matches_page")
