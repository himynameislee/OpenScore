"""Evidence exhibits: offending lines are marked, and secrets never enter a proof."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from openscore import proof  # noqa: E402


class _Raw:
    version = 11

    def __init__(self, items):
        self._items = items

    @property
    def headers(self):
        return self

    def items(self):
        return list(self._items)


class FakeResp:
    def __init__(self, status=200, headers=(), body="", url="https://www.example.com/"):
        self.status_code, self.reason, self.url = status, "OK", url
        self.raw = _Raw(headers)
        self.headers = {k: v for k, v in headers}
        self.text = body
        self.content = body.encode()


def flat(p):
    return "\n".join(str(t) for t, _, _ in p["lines"])


def test_missing_header_marked_and_cookie_values_masked():
    r = FakeResp(headers=[("Server", "nginx"), ("Set-Cookie", "session=SUPERSECRET123; Path=/"),
                          ("Set-Cookie", "lang=en; Secure")])
    p = proof.http(r, missing=[("Strict-Transport-Security", "required")], verdict="x")
    assert "SUPERSECRET123" not in flat(p)
    assert "session=••••••; Path=/" in flat(p) and "lang=••••••; Secure" in flat(p)
    bad = [t for t, m, _ in p["lines"] if m == "bad"]
    assert bad == ["Strict-Transport-Security: (not present)"]
    assert p["cmd"] == "curl -sI https://www.example.com/"


def test_callable_mark_targets_only_matching_cookie():
    r = FakeResp(headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "PHPSESSID=2; path=/")])
    p = proof.http(r, mark={"set-cookie": lambda v: ("bad", "no Secure") if v.startswith("PHPSESSID") else None})
    marked = [t for t, m, _ in p["lines"] if m == "bad"]
    assert marked == ["Set-Cookie: PHPSESSID=••••••; path=/"]


def test_secret_body_excerpt_masks_values():
    r = FakeResp(headers=[("Content-Type", "text/plain")],
                 body="APP_KEY=base64:zzz\nDB_PASSWORD=hunter2\n# comment\n")
    p = proof.body_excerpt(r, "https://x/.env", r"(?m)^(APP_KEY|DB_PASSWORD)\s*=", secret=True,
                           control="control: GET /random → HTTP 404")
    text = flat(p)
    assert "hunter2" not in text and "base64:zzz" not in text
    assert "APP_KEY=••••••" in text
    assert sum(1 for _, m, n in p["lines"] if m == "bad" and n == "matched signature") == 2
    assert p["lines"][0][1] == "good"   # control request shown as proof of non-catch-all


def test_html_render_escapes():
    p = proof.make("t", "curl x", [["<script>alert(1)</script>", "bad", "<b>n</b>"]], verdict="<v>")
    html = proof.to_html(p)
    assert "<script>" not in html and "&lt;script&gt;" in html and "&lt;v&gt;" in html
