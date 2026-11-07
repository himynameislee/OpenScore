"""Screenshot evidence (light / active) using headless Chromium via Playwright.

* Homepage of every in-scope web host        -> asset inventory thumbnails (normal browsing)
* URL-based findings (exposed files, panels,  -> evidence image attached to the finding
  VPN portals, directory listings, mgmt UIs)

Every image is stamped with an evidence banner (URL, HTTP status, UTC timestamp, tool version)
so it stands on its own in a client report. Files that contain secrets (.env, credentials,
config backups) are BLURRED in the image — proof of exposure without copying the secret.
Binary downloads (zip/sql/heapdump) are never opened.

Optional: pip install playwright && python -m playwright install chromium
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
import re
from urllib.parse import urlparse

from .. import __version__, proof, util

log = logging.getLogger("openscore")
MODE = "light"

# check_id -> how to capture. Page screenshots are only taken where SEEING the page adds proof
# (login portals, panels, status pages, listings). Raw-file and header findings are proven by
# their text exhibit instead (see proof.py), so they're not screenshotted.
CAPTURE = {
    "exp_server_status": "page", "exp_phpinfo": "page", "exp_debug_handler": "page",
    "exp_admin_panel": "page", "exp_api_docs": "page", "http_dir_listing": "page",
    "edge_appliance_exposed": "page", "exchange_onprem_exposed": "page", "net_exposed_admin_web": "page",
    # never screenshotted: secrets or downloads (redact mode kept as a safety net if re-enabled)
    "exp_env": None, "exp_aws_creds": None, "exp_config_backup": None, "exp_actuator": None,
    "exp_backup_archive": None, "exp_ds_store": None,
}

URL_RE = re.compile(r"https?://[^\s\]\)\"']+")
BANNER_JS = r"""
([url, status, when, ver, redacted, note]) => {
  const b = document.createElement('div');
  b.setAttribute('style', 'position:fixed;top:0;left:0;right:0;z-index:2147483647;' +
    'background:#16202a;color:#fff;font:13px/1.4 Consolas,Menlo,monospace;padding:6px 10px;' +
    'display:flex;gap:14px;align-items:center;box-shadow:0 2px 6px rgba(0,0,0,.4);filter:none');
  const s = (t, c) => { const e = document.createElement('span'); e.textContent = t;
                        if (c) e.style.color = c; b.appendChild(e); };
  s('OpenScore evidence', '#9ae6b4'); s(url); s('HTTP ' + status, status < 400 ? '#fbd38d' : '#feb2b2');
  s(when); s('v' + ver, '#a0aec0');
  if (redacted) s('CONTENTS BLURRED — secrets not captured', '#feb2b2');
  document.documentElement.appendChild(b);
  let top = 34;
  if (note) {
    const n = document.createElement('div');
    n.textContent = note;
    n.setAttribute('style', 'position:fixed;top:30px;left:0;right:0;z-index:2147483647;background:#7b341e;' +
      'color:#fff;font:12px/1.4 Consolas,Menlo,monospace;padding:5px 10px;white-space:pre-wrap;filter:none');
    document.documentElement.appendChild(n);
    top = 34 + n.getBoundingClientRect().height;
  }
  if (document.body) document.body.style.marginTop = top + 'px';
  if (redacted && document.body) {
    // Layer 1: mask every value in the page text (KEY=value, key: value, "key":"value")
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const nodes = []; while (w.nextNode()) nodes.push(w.currentNode);
    for (const n of nodes) {
      n.nodeValue = n.nodeValue.replace(/([=:]\s*["']?)[^\s"',;}<]+/g, '$1••••••');
    }
    // Layer 2: blur the whole page body (the evidence banner lives outside <body>)
    const st = document.createElement('style');
    st.textContent = 'body{filter:blur(6px)!important}';
    document.documentElement.appendChild(st);
  }
  return top;
}
"""


# Bottom edge of the rendered content (scrollHeight never reports less than the viewport)
CONTENT_BOTTOM_JS = """
() => {
  if (!document.body) return 800;
  const r = document.createRange();
  r.selectNodeContents(document.body);
  let bottom = r.getBoundingClientRect().bottom;
  for (const el of document.body.querySelectorAll('img,video,iframe,canvas,svg')) {
    bottom = Math.max(bottom, el.getBoundingClientRect().bottom);
  }
  return Math.ceil(bottom + window.scrollY);
}
"""


def available() -> bool:
    import importlib.util
    return importlib.util.find_spec("playwright") is not None


def _first_url(text: str):
    m = URL_RE.search(text or "")
    return m.group(0).rstrip(".,:;") if m else None


def _note(f) -> str:
    """Second banner line: the finding itself, so the image is self-explanatory."""
    if f.check_id.startswith("tls_"):
        first = (f.evidence or "").splitlines()
        detail = " | ".join(x.strip() for x in first[:2] if x.strip())
        return f"Finding: {f.title}\n{detail[:300]}"
    return f"Finding: {f.title}"


_loggable = util.loggable_url      # kept for existing callers/tests


def _in_scope_url(ctx, url: str) -> bool:
    return ctx.in_scope((urlparse(url).hostname or "").lower())


def _plan(ctx):
    """Return list of jobs: (key, url, mode, finding_or_None, asset)."""
    jobs, seen = [], set()
    for f in ctx.findings:
        if f.severity == "pass" or f.third_party:
            continue
        mode = CAPTURE.get(f.check_id, "absent")
        if mode in (None, "absent"):
            continue
        url = _first_url(f.evidence)
        if not url and f.check_id == "net_exposed_admin_web":
            m = re.search(r"\(tcp/(\d+)\)", f.title)
            if m:
                url = f"https://{f.asset}:{m.group(1)}/"
        if not url:
            continue
        host = urlparse(url).hostname or ""
        if not (ctx.in_scope(host) or host == f.asset):
            continue
        if f.check_id.startswith(("exp_", "net_")) and not ctx.cfg.active:
            continue  # found by active modules only; don't re-request without authorization
        jobs.append((f"f{len(jobs)}", url, mode, f, f.asset))
    for a in ctx.assets.values():
        if a.hosting_class == "saas" and not a.explicit:
            continue
        for url, meta in list(a.web.items()):
            final = meta.get("final_url") or url
            if not meta.get("status") or final in seen:
                continue
            if not _in_scope_url(ctx, final):
                continue   # redirects off-site (SSO provider, marketing site ...): not ours to capture
            seen.add(final)
            jobs.append((f"h{len(jobs)}", final, "page", None, a.host))
            break  # one homepage per host
    return jobs[: ctx.cfg.max_screenshots]


FIX_CMD = ("pip install --break-system-packages --ignore-installed playwright && "
           "python3 -m playwright install chromium")


def _quiet_loop_errors(loop, context):
    """Playwright leaves an orphaned init task when its driver dies; keep that traceback out of
    the console (the real error is caught and reported once, below)."""
    exc = context.get("exception")
    log.debug("asyncio: %s %s", context.get("message"), exc)


async def _shoot_all(ctx, jobs, outdir, notes):
    asyncio.get_running_loop().set_exception_handler(_quiet_loop_errors)
    from playwright.async_api import async_playwright
    results = {}
    offsite: list[str] = []
    sem = asyncio.Semaphore(4)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(args=["--disable-dev-shm-usage"])
        bctx = await browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 800},
                                         user_agent=ctx.session.headers.get("User-Agent"),
                                         java_script_enabled=True, accept_downloads=False)

        async def one(key, url, mode, asset):
            async with sem:
                page = await bctx.new_page()
                try:
                    ctx.audit_log(f"screenshot {_loggable(url)}")
                    resp = await page.goto(url, wait_until="domcontentloaded", timeout=20000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=4000)
                    except Exception:
                        pass
                    if not _in_scope_url(ctx, page.url):
                        # the browser ended up on another organization's site (e.g. a JS redirect
                        # to an identity provider): don't keep a picture of it
                        offsite.append(_loggable(page.url))
                        return
                    status = resp.status if resp else 0
                    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    top = await page.evaluate(BANNER_JS, [url, status, when, __version__, mode == "redact",
                                                          notes.get(key, "")])
                    path = os.path.join(outdir, f"{key}-{re.sub(r'[^a-zA-Z0-9.-]+', '_', asset)[:60]}.jpg")
                    # crop short pages (raw files, error pages) instead of saving 800px of white
                    h = await page.evaluate(CONTENT_BOTTOM_JS)
                    clip_h = int(max(top + 160, min(h + 24, 800)))
                    await page.screenshot(path=path, type="jpeg", quality=72,
                                          clip={"x": 0, "y": 0, "width": 1280, "height": clip_h})
                    results[key] = {"path": path, "url": url, "status": status, "taken": when}
                except Exception as e:
                    log.debug("screenshot %s failed: %s", url, e)
                finally:
                    await page.close()

        await asyncio.gather(*(one(k, u, m, a) for k, u, m, _, a in jobs))
        if offsite:
            ctx.module_status.setdefault("screenshots", {})["skipped_offsite"] = (
                f"{len(offsite)} page(s) ended up out of scope and weren't kept: " + ", ".join(sorted(set(offsite))[:5]))
        await _render_proofs(ctx, bctx, outdir)
        await browser.close()
    return results


PROOF_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><style>
body{{margin:0;padding:14px;background:#fff;width:1080px;font-family:-apple-system,"Segoe UI",Inter,Roboto,Arial,sans-serif}}
.cap{{display:flex;gap:10px;align-items:center;font-size:13px;color:#16202a;margin:0 0 6px}}
.sev{{color:#fff;font-weight:700;font-size:11px;text-transform:uppercase;padding:2px 8px;border-radius:999px}}
.critical{{background:#8b1a1a}}.high{{background:#c2410c}}.medium{{background:#b7791f}}.low{{background:#2b6cb0}}.info{{background:#64748b}}
.meta{{color:#5d6b78;margin-left:auto;font-size:12px}}
{css}</style></head><body><div id="card"><div class="cap"><span class="sev {sev}">{sev}</span><b>{title}</b>
<span class="meta">{asset} · {when} · OpenScore v{ver}</span></div>{exhibit}</div></body></html>"""


async def _render_proofs(ctx, bctx, outdir):
    """Export every finding's exhibit as a PNG — ready to paste into a ticket or email."""
    from html import escape
    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    todo = [f for f in ctx.findings if f.proof and f.severity != "pass"][:ctx.cfg.max_proof_images]
    page = await bctx.new_page()
    try:
        for i, f in enumerate(todo):
            html = PROOF_PAGE.format(css=proof.EXHIBIT_CSS, sev=f.severity, title=escape(f.title),
                                     asset=escape(f.asset), when=when, ver=__version__,
                                     exhibit=proof.to_html(f.proof, f.source))
            try:
                await page.set_content(html)
                path = os.path.join(outdir, f"proof-{i:03d}-{f.check_id}.png")
                await page.locator("#card").screenshot(path=path)
                f.proof_image = os.path.relpath(path, ctx.cfg.output)
            except Exception as e:
                log.debug("proof render %s failed: %s", f.check_id, e)
    finally:
        await page.close()


def run(ctx) -> None:
    if ctx.cfg.no_screenshots:
        return
    if not available():
        ctx.module_status.setdefault("screenshots", {})["note"] = (
            "Playwright not installed — run: pip install playwright && python -m playwright install chromium")
        return
    jobs = _plan(ctx)
    if not jobs and not any(f.proof for f in ctx.findings):
        return
    outdir = ctx.evidence_dir
    os.makedirs(outdir, exist_ok=True)
    log.info("Capturing %d screenshots", len(jobs))
    try:
        notes = {k: _note(f) for k, _, _, f, _ in jobs if f is not None}
        results = asyncio.run(_shoot_all(ctx, jobs, outdir, notes))
    except Exception as e:
        msg = str(e).splitlines()[0][:200]
        if "Executable doesn't exist" in str(e) or "playwright install" in str(e):
            msg = "Chromium for Playwright missing — run: python -m playwright install chromium"
        elif "closed while reading from the driver" in str(e) or "driver" in str(e).lower():
            import playwright
            where = os.path.dirname(playwright.__file__)
            msg = (f"Playwright driver failed to start ({where}). If that path is /usr/lib/python3/"
                   f"dist-packages it's the distro package — replace it with: {FIX_CMD}")
        ctx.module_status.setdefault("screenshots", {})["error"] = msg
        log.warning("Screenshots unavailable: %s", msg)
        return
    for key, url, mode, finding, asset in jobs:
        r = results.get(key)
        if not r:
            continue
        rel = os.path.relpath(r["path"], ctx.cfg.output)
        if finding is not None:
            finding.screenshot = rel
        else:
            a = ctx.assets.get(asset)
            if a:
                a.screenshot = rel
    ctx.module_status.setdefault("screenshots", {})["captured"] = f"{len(results)}/{len(jobs)}"
    n = sum(1 for f in ctx.findings if f.proof_image)
    if n:
        ctx.module_status["screenshots"]["proof_images"] = f"{n} PNG exhibits in {os.path.basename(outdir)}/"
