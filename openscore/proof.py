"""Proof capture: the raw evidence behind each finding, with the offending line highlighted.

A proof is a small dict stored on the Finding and rendered in the report as a terminal-style
exhibit (and exported as PNG for tickets):

    {"title": "HTTP response headers",
     "cmd":   "curl -sI https://www.example.com/",
     "lines": [[text, mark, note], ...],    # mark: "bad" | "good" | "warn" | None
     "verdict": "Strict-Transport-Security header is not sent"}

Secrets never enter a proof: cookie values are masked, and bodies of secret-bearing files are
value-masked before storage.
"""
from __future__ import annotations

import re

MAX_LINES = 40
MASK = "••••••"
_SECRET_VALUE = re.compile(r"""([=:]\s*["']?)[^\s"',;}<]+""")


def mask_values(text: str) -> str:
    return _SECRET_VALUE.sub(lambda m: m.group(1) + MASK, text)


def make(title: str, cmd: str, lines: list, verdict: str = "") -> dict:
    out = []
    for ln in lines[:MAX_LINES]:
        if isinstance(ln, str):
            ln = [ln, None, None]
        text, mark, note = (list(ln) + [None, None])[:3]
        out.append([str(text)[:220], mark, note])
    if len(lines) > MAX_LINES:
        out.append([f"… {len(lines) - MAX_LINES} more lines", None, None])
    return {"title": title, "cmd": cmd, "lines": out, "verdict": verdict}


# ------------------------------------------------------------------------- HTTP
def _status_line(resp) -> str:
    ver = {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}.get(getattr(resp.raw, "version", 11), "HTTP/1.1")
    return f"{ver} {resp.status_code} {resp.reason or ''}".strip()


def _header_items(resp):
    try:
        return list(resp.raw.headers.items())     # keeps duplicate Set-Cookie headers
    except Exception:
        return list(resp.headers.items())


def _redact_cookie(value: str) -> str:
    name, _, rest = value.partition("=")
    val, sep, attrs = rest.partition(";")
    return f"{name}={MASK}{sep}{attrs}" if val else value


def http(resp, *, method: str = "GET", url: str | None = None, req_headers: dict | None = None,
         mark: dict | None = None, missing: list | None = None, body_marks: list | None = None,
         verdict: str = "", title: str = "HTTP response") -> dict:
    """mark: {header-name-lower: (mark, note) or callable(value)->(mark,note)|None}
    missing: [(Header-Name, note)] rendered as synthetic red lines.
    body_marks: [(regex, mark, note)] — show matching body lines (max 8)."""
    url = url or resp.url
    flags = "-sI" if not body_marks else "-si"
    extra = "".join(f" -H '{k}: {v}'" for k, v in (req_headers or {}).items())
    cmd = f"curl {flags}{extra} {url}"
    lines = [[_status_line(resp), "bad" if resp.status_code >= 500 else None, None]]
    mark = mark or {}
    for k, v in _header_items(resp):
        shown = _redact_cookie(v) if k.lower() == "set-cookie" else v
        m = mark.get(k.lower())
        if callable(m):
            m = m(v)
        lines.append([f"{k}: {shown}", *(m if m else (None, None))])
    for name, note in (missing or []):
        lines.append([f"{name}: (not present)", "bad", note])
    if body_marks:
        body = resp.text[:200000] if "text" in resp.headers.get("Content-Type", "") or \
            "json" in resp.headers.get("Content-Type", "") else ""
        shown = 0
        lines.append(["", None, None])
        for ln in body.splitlines():
            for rx, mk, note in body_marks:
                if re.search(rx, ln, re.I):
                    lines.append([ln.strip()[:200], mk, note])
                    shown += 1
                    break
            if shown >= 8:
                break
    return make(title, cmd, lines, verdict)


def body_excerpt(resp, url: str, signature: str, secret: bool, control: str | None = None) -> dict:
    """For exposed files: status + key headers + first lines of the body, matched line marked."""
    lines = []
    if control:
        lines.append([control, "good", "control request for a random path — proves this isn't a catch-all page"])
        lines.append(["", None, None])
    lines.append([_status_line(resp), "bad", "file is served to anyone"])
    for k in ("Content-Type", "Content-Length", "Last-Modified", "Server"):
        if resp.headers.get(k):
            lines.append([f"{k}: {resp.headers[k]}", None, None])
    lines.append(["", None, None])
    if signature.startswith("BYTES:"):
        head = resp.content[:16]
        lines.append([f"first bytes: {head.hex(' ')}", "bad", "file signature matched"])
    else:
        text = resp.text[:20000]
        rx = re.compile(signature, re.I | re.M)
        for i, ln in enumerate(text.splitlines()[:14]):
            shown = mask_values(ln) if secret else ln
            hit = bool(rx.search(ln))
            lines.append([shown[:200], "bad" if hit else None, "matched signature" if hit else None])
        if secret:
            lines.append(["(values masked by OpenScore — secrets are never stored)", "warn", None])
    return make("HTTP response (body excerpt)", f"curl -si {url}", lines)


# -------------------------------------------------------------------------- DNS
def dns(qname: str, rtype: str, result, mark=None, verdict: str = "", absent_note: str = "") -> dict:
    """mark: callable(record)->(mark,note)|None"""
    cmd = f"dig +short {rtype} {qname}"
    lines = []
    if result.ok and result.records:
        for r in result.records:
            m = mark(r) if mark else None
            lines.append([r, *(m if m else (None, None))])
    else:
        status = {"nxdomain": "NXDOMAIN — name does not exist", "noanswer": "NOERROR — no records of this type",
                  "error": f"query failed: {result.error}"}.get(result.status, result.status)
        lines.append([f";; {status}", "bad", absent_note or None])
    return make(f"DNS {rtype} lookup", cmd, lines, verdict)


def merge(*proofs, verdict: str = "") -> dict:
    """Combine several captures into one exhibit (e.g. two DNS lookups)."""
    lines = []
    for p in proofs:
        if lines:
            lines.append(["", None, None])
        lines.append([f"$ {p['cmd']}", "cmd", None])
        lines += p["lines"]
    first = proofs[0]
    return {"title": first["title"], "cmd": "", "lines": lines[: MAX_LINES * 2],
            "verdict": verdict or first.get("verdict", "")}


# ----------------------------------------------------------------------- render
EXHIBIT_CSS = """
.exhibit{background:#0f1720;border-radius:8px;overflow:hidden;margin:8px 0;border:1px solid #1f2a36;
  font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#d6dee6}
.exhibit .ex-head{background:#1b2633;padding:6px 12px;display:flex;align-items:center;gap:10px;color:#9fb0c2;
  font:600 12px/1.4 -apple-system,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif}
.exhibit .dots{letter-spacing:2px;color:#4a5a6b}
.exhibit .ex-src{margin-left:auto;font-weight:400;color:#6b7c8f}
.exhibit .ex-body{padding:8px 0;overflow-x:auto}
.exhibit .ln{display:flex;gap:16px;padding:1px 12px;white-space:pre-wrap;word-break:break-word;min-height:1.5em}
.exhibit .ln .t{flex:1 1 auto}
.exhibit .ln .n{flex:0 0 auto;max-width:42%;font-size:11.5px;padding:0 6px;border-radius:3px;align-self:flex-start;
  font-family:-apple-system,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif}
.exhibit .ln.cmd .t{color:#7dd3fc}.exhibit .ln.cmd .t:before{content:"$ ";color:#64748b}
.exhibit .ln.bad{background:rgba(229,62,62,.18);box-shadow:inset 3px 0 0 #f56565}
.exhibit .ln.bad .t{color:#fed7d7}.exhibit .ln.bad .n{background:#c53030;color:#fff}
.exhibit .ln.warn{background:rgba(236,201,75,.13);box-shadow:inset 3px 0 0 #ecc94b}
.exhibit .ln.warn .n{background:#b7791f;color:#fff}
.exhibit .ln.good{background:rgba(72,187,120,.13);box-shadow:inset 3px 0 0 #48bb78}
.exhibit .ln.good .n{background:#2f855a;color:#fff}
.exhibit .ex-verdict{background:#2a1215;color:#feb2b2;padding:7px 12px;border-top:1px solid #3b1d22;
  font:600 12.5px/1.4 -apple-system,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif}
.exhibit .ex-verdict:before{content:"\\26A0  "}
"""


def to_html(p: dict, source: str = "") -> str:
    from html import escape as e
    if not p:
        return ""
    out = [f'<div class="exhibit"><div class="ex-head"><span class="dots">●●●</span>{e(p.get("title", ""))}'
           f'<span class="ex-src">{e(source)}</span></div><div class="ex-body">']
    if p.get("cmd"):
        out.append(f'<div class="ln cmd"><span class="t">{e(p["cmd"])}</span></div>')
    for text, mark, note in p.get("lines", []):
        if mark == "cmd":
            out.append(f'<div class="ln cmd"><span class="t">{e(str(text).lstrip("$ "))}</span></div>')
            continue
        cls = f" {mark}" if mark in ("bad", "warn", "good") else ""
        n = f'<span class="n">◀ {e(str(note))}</span>' if note else ""
        out.append(f'<div class="ln{cls}"><span class="t">{e(str(text)) or "&nbsp;"}</span>{n}</div>')
    out.append("</div>")
    if p.get("verdict"):
        out.append(f'<div class="ex-verdict">{e(p["verdict"])}</div>')
    out.append("</div>")
    return "".join(out)
