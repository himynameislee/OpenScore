"""Optional external tool integrations (ACTIVE): nuclei (safe template tags only) and testssl.sh.
Both are skipped silently when not installed."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlparse

from .. import proof, util

log = logging.getLogger("openscore")
MODE = "active"

# No "tech" tag: technology fingerprints are info-only and were always discarded below,
# but they're hundreds of templates per web root.
NUCLEI_TAGS = "exposure,misconfig,ssl,takeover,config,exposed-panels,panel,cve,kev"
STATS_EVERY = 60          # seconds between nuclei progress lines
TESTSSL_TICK = 60         # seconds between "still running" lines for one testssl.sh host
STOPPED_CTRL_C = "stopped early (Ctrl+C)"
# testssl.sh exit codes that mean it can't run on this machine at all (missing/unusable openssl,
# bad bash, command-line error). Retrying on the next host gives the same result.
TESTSSL_ENV_ERRORS = {250: "testssl.sh can't use an openssl binary on this machine",
                      254: "testssl.sh rejected its command line",
                      255: "testssl.sh needs a newer bash"}
NUCLEI_EXCLUDE = "intrusive,dos,fuzz,bruteforce,brute-force,default-login,sqli,xss,rce,lfi,ssrf,oast,headless"
# Templates that repeat OpenScore's own built-in checks (TLS certificate/protocol details, security
# headers, cookie flags) or describe a third-party service rather than the target. They added
# hundreds of duplicate info findings per scan and slowed nuclei down.
NUCLEI_EXCLUDE_IDS = ("ssl-dns-names", "ssl-issuer", "tls-version", "wildcard-tls", "mismatched-ssl-certificate",
                      "expired-ssl", "self-signed-ssl", "untrusted-root-certificate", "deprecated-tls",
                      "weak-cipher-suites", "http-missing-security-headers", "missing-cookie-samesite-strict",
                      "cookies-without-httponly", "cookies-without-secure", "missing-sri", "weak-csp-detect",
                      "azure-domain-tenant")
SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
           "unknown": "info"}


def _web_roots(ctx):
    roots = set()
    for a in ctx.assets.values():
        for url in ctx.active_urls(a):
            p = urlparse(url)
            roots.add((a.host, f"{p.scheme}://{p.netloc}"))
    return ctx.one_per_target(roots)


def _nuclei_concurrency(rate: int) -> int:
    """Templates in flight: enough to reach the rate limit, which is what actually paces nuclei."""
    return max(10, min(50, int(rate or 0) // 4))


def _launcher(exe: str) -> list[str]:
    return [exe]          # tests swap this for a fake nuclei


def _stat(d: dict, key: str) -> str:
    v = d.get(key)
    return "" if v is None else str(v)


def _stop(proc) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _supervise(proc, timeout_s: float, limit_flag: str, on_tick=None, tick_every: float = 60) -> str:
    """Wait for proc with a time limit. Ctrl+C stops proc only (the caller decides what's next).
    on_tick(elapsed_seconds) is called every tick_every seconds while it runs."""
    t0 = time.monotonic()
    deadline, next_tick = t0 + timeout_s, t0 + tick_every
    try:
        # Short waits so Ctrl+C is noticed promptly (a long wait isn't interruptible on Windows).
        while True:
            try:
                rc = proc.wait(timeout=1)
                return "completed" if rc == 0 else f"exited with code {rc}"
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                if now >= deadline:
                    _stop(proc)
                    return f"stopped after the {timeout_s / 60:g}-minute limit ({limit_flag})"
                if on_tick and now >= next_tick:
                    next_tick = now + tick_every
                    on_tick(now - t0)
    except KeyboardInterrupt:
        _stop(proc)
        return STOPPED_CTRL_C


def _run_nuclei(cmd: list[str], timeout_s: float) -> tuple[str, dict, list[str]]:
    """Run nuclei with results streamed to the -o file (so nothing is lost if it's stopped early).
    Logs a progress line from nuclei's JSON stats. Ctrl+C stops nuclei only; the scan continues.
    Returns (status, last stats, last stderr lines)."""
    last: dict = {}
    tail: list[str] = []
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", env=util.child_env())

    def read_stderr():
        for line in proc.stderr:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                tail.append(line)
                del tail[:-5]
                continue
            if isinstance(d, dict) and ("percent" in d or "requests" in d):
                last.clear()
                last.update(d)
                log.info("  nuclei %s%% · %s/%s requests · %s matches · %s elapsed",
                         _stat(d, "percent") or "?", _stat(d, "requests") or "?", _stat(d, "total") or "?",
                         _stat(d, "matched") or "0", _stat(d, "duration") or "?")
    t = threading.Thread(target=read_stderr, daemon=True)
    t.start()

    status = _supervise(proc, timeout_s, "--nuclei-timeout")
    t.join(timeout=5)
    if last.get("percent") not in (None, "") and status != "completed":
        status += f" at {_stat(last, 'percent')}%"
    return status, last, tail


def nuclei(ctx) -> None:
    exe = util.which("nuclei")
    if not exe or ctx.cfg.no_nuclei:
        ctx.module_status.setdefault("external_tools", {})["nuclei"] = "not installed" if not exe else "disabled"
        return
    roots = _web_roots(ctx)
    if not roots:
        return
    host_of = {r: h for h, r in roots}
    tmp = tempfile.mkdtemp(prefix="openscore-nuclei-")
    listfile, outfile = os.path.join(tmp, "targets.txt"), os.path.join(tmp, "results.jsonl")
    with open(listfile, "w", encoding="utf-8") as f:
        f.write("\n".join(r for _, r in roots))
    timeout_min = float(getattr(ctx.cfg, "nuclei_timeout", 60) or 60)
    cmd = _launcher(exe) + [
        "-l", listfile, "-tags", NUCLEI_TAGS, "-etags", NUCLEI_EXCLUDE, "-eid", ",".join(NUCLEI_EXCLUDE_IDS),
        "-severity", "info,low,medium,high,critical", "-jsonl", "-o", outfile, "-silent", "-nc",
        "-stats", "-stats-json", "-stats-interval", str(STATS_EVERY),
        "-rl", str(ctx.cfg.nuclei_rate), "-c", str(_nuclei_concurrency(ctx.cfg.nuclei_rate)),
        "-timeout", "10", "-no-interactsh",
        "-H", f"User-Agent: {ctx.session.headers['User-Agent']}"]
    ctx.audit_log(f"nuclei tags={NUCLEI_TAGS} exclude={NUCLEI_EXCLUDE} rate={ctx.cfg.nuclei_rate}/s "
                  f"limit={timeout_min:g}min on {len(roots)} roots")
    log.info("Running nuclei on %d web roots (safe tags only, %d req/s, up to %g min). "
             "Progress every %ds; Ctrl+C stops nuclei early and keeps its findings.",
             len(roots), ctx.cfg.nuclei_rate, timeout_min, STATS_EVERY)
    t0 = time.time()
    try:
        status, _, tail = _run_nuclei(cmd, timeout_min * 60)
    except OSError as e:
        ctx.module_status.setdefault("external_tools", {})["nuclei"] = f"failed to start: {e}"
        return
    try:
        with open(outfile, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    for path in (listfile, outfile):
        try:
            os.unlink(path)
        except OSError:
            pass
    try:
        os.rmdir(tmp)
    except OSError:
        pass
    n = _ingest(ctx, lines, host_of)
    note = f"{status}; {n} findings; {round((time.time() - t0) / 60, 1)} min"
    if ctx.flags.get("nuclei_offscope"):
        note += f"; {ctx.flags['nuclei_offscope']} result(s) about third-party hosts ignored"
    if status.startswith("exited") and tail:
        note += f"; last error: {tail[-1][:200]}"
    if status != "completed":
        note += " (partial results)" if n else ""
        ctx.audit_log(f"nuclei {status}")
    ctx.module_status.setdefault("external_tools", {})["nuclei"] = note
    log.info("nuclei: %s", note)


def _ingest(ctx, results: list[str], host_of: dict) -> int:
    n = 0
    for line in results:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        info = d.get("info", {})
        tags = set(info.get("tags", []) if isinstance(info.get("tags"), list) else str(info.get("tags", "")).split(","))
        sev = SEV_MAP.get(info.get("severity", "info"), "info")
        matched = d.get("matched-at") or d.get("host", "")
        p = urlparse(matched if "://" in matched else "https://" + matched)
        asset = host_of.get(f"{p.scheme}://{p.netloc}")
        if asset is None:
            if not ctx.active_ok(p.hostname or ""):
                # a template that called a third-party service (e.g. a public tenant lookup);
                # the result is about that service, not the organization
                ctx.flags["nuclei_offscope"] = ctx.flags.get("nuclei_offscope", 0) + 1
                continue
            asset = p.hostname or matched
        cves = [c for c in (info.get("classification", {}) or {}).get("cve-id", []) or [] if c]
        for c in cves:
            ctx.record_cve(c, asset)
        factor = ("patching" if cves or "cve" in tags else "exposure" if "exposure" in tags or "panel" in tags
                  else "tls" if "ssl" in tags else "dns" if "takeover" in tags else "appsec")
        if sev == "info" and "tech" in tags:
            continue  # technology fingerprints aren't findings
        ev = f"{d.get('template-id')}: {matched}"
        if d.get("extracted-results"):
            ev += "\n" + ", ".join(map(str, d["extracted-results"][:5]))
        refs = info.get("reference") or []
        if refs:
            ev += "\nRefs: " + ", ".join(refs[:3] if isinstance(refs, list) else [str(refs)])
        lines = [[f"template : {d.get('template-id')}", None, None],
                 [f"matched  : {matched}", "bad", info.get("severity")],
                 [f"matcher  : {d.get('matcher-name', '-')}", None, None]]
        for x in (d.get("extracted-results") or [])[:6]:
            lines.append([f"extracted: {proof.mask_values(str(x))[:180]}", "bad", None])
        if d.get("curl-command"):
            lines.append([f"reproduce: {d['curl-command'][:200]}", None, None])
        ctx.add("nuclei_finding", asset, ev, severity=sev, factor=factor,
                title=f"{info.get('name', d.get('template-id'))}", source="nuclei",
                proof=proof.make("nuclei template match", f"nuclei -u {matched} -id {d.get('template-id')}", lines,
                                 verdict=info.get("name", "")))
        n += 1
    return n


def _exit_code(status: str):
    m = re.match(r"exited with code (-?\d+)", status or "")
    return int(m.group(1)) if m else None


def _testssl_launcher(exe: str) -> list[str]:
    return [exe]          # tests swap this for a fake testssl.sh


def _load_testssl_json(path: str) -> list[dict]:
    """testssl.sh writes its JSON file as it goes; a stopped run leaves an unclosed array.
    Salvage every complete row."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read().strip()
    except OSError:
        return []
    if not text:
        return []
    try:
        data = json.loads(text)
        return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
    except ValueError:
        pass
    rows, dec, i = [], json.JSONDecoder(), text.find("[") + 1
    while i:
        while i < len(text) and text[i] in " \t\r\n,":
            i += 1
        try:
            row, i = dec.raw_decode(text, i)
        except ValueError:
            break
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _testssl_targets(ctx) -> list[tuple[str, str]]:
    targets = set()
    for a in ctx.assets.values():
        for url in ctx.active_urls(a):
            p = urlparse(url)
            if p.scheme == "https":
                targets.add((a.host, f"{p.hostname}:{p.port or 443}"))
    return ctx.one_per_target(targets)


# testssl.sh rows that built-in checks already report (web.py TLS handshake: expiry, trust, hostname,
# key size, signature; dns_email: CAA), or per-protocol detail rows of a summary row testssl.sh also
# writes (BEAST_CBC_TLS1 -> BEAST). Skipped so one problem is one finding, not two or three.
TESTSSL_DUPLICATE_IDS = {"cert_expirationStatus", "cert_notAfter", "cert_notBefore", "cert_trust",
                         "cert_chain_of_trust", "cert_subjectAltName", "cert_keySize", "cert_signatureAlgorithm",
                         "DNS_CAArecord"}
TESTSSL_DETAIL_PREFIXES = ("BEAST_CBC_",)
# Best-practice notes rather than weaknesses: kept visible as info, no score impact.
TESTSSL_INFO_IDS = {"OCSP_stapling", "cert_trust_wildcard", "cert_mustStapleExtension"}


def _ingest_testssl(ctx, asset: str, tgt: str, rows: list[dict]) -> tuple[int, int]:
    """Returns (issues added, rows skipped as duplicates of built-in checks)."""
    n = dup = 0
    for row in rows:
        sev = str(row.get("severity", "")).lower()
        if sev not in ("critical", "high", "medium", "low"):
            continue
        rid = str(row.get("id", ""))
        base_id = rid.split()[0] if rid else rid       # multi-cert servers: "cert_notAfter <hostCert#1>"
        if base_id in TESTSSL_DUPLICATE_IDS or base_id.startswith(TESTSSL_DETAIL_PREFIXES):
            dup += 1
            continue
        n += 1
        if base_id in TESTSSL_INFO_IDS:
            sev = "info"
        # "potentially VULNERABLE" (BREACH, LUCKY13 ...) is testssl's own heuristic, not a confirmed issue
        conf = "tentative" if "potentially" in str(row.get("finding", "")).lower() else "firm"
        if rid in ("SSLv2", "SSLv3"):
            ctx.add("tls_sslv3", asset, f"{tgt}: {rid} {row.get('finding')}", source="testssl.sh")
        elif rid in ("TLS1", "TLS1_1"):
            ctx.add("tls_old_protocol", asset, f"{tgt}: {rid} {row.get('finding')}", source="testssl.sh")
        else:
            ctx.add("tls_testssl", asset, f"{tgt}: {rid} — {row.get('finding')}"
                    + (f" ({row.get('cve')})" if row.get("cve") else ""),
                    severity=sev, title=f"TLS: {rid}", source="testssl.sh", confidence=conf,
                    proof=proof.make("testssl.sh", f"testssl.sh {tgt}",
                                     [[f"{rid:<22} {row.get('finding')}", "bad", row.get("cve") or sev]],
                                     verdict=str(row.get("finding"))[:150]))
    return n, dup


def testssl(ctx) -> None:
    st = ctx.module_status.setdefault("external_tools", {})
    exe = util.which("testssl.sh") or util.which("testssl")
    if not exe or ctx.cfg.no_testssl:
        st["testssl"] = "not installed" if not exe else "disabled"
        return
    targets = _testssl_targets(ctx)
    if not targets:
        return
    limit_min = float(getattr(ctx.cfg, "testssl_timeout", 5) or 5)
    log.info("Running testssl.sh on %d HTTPS endpoint(s), one at a time (up to %g min each). "
             "Ctrl+C skips the rest of testssl.sh and keeps what it found.", len(targets), limit_min)
    t0 = time.monotonic()
    completed, issues, dups, problems = 0, 0, 0, []
    for i, (asset, tgt) in enumerate(targets, 1):
        h0 = time.monotonic()
        with tempfile.TemporaryDirectory() as td:
            jf = os.path.join(td, "out.json")
            cmd = _testssl_launcher(exe) + [
                "--quiet", "--warnings", "off", "--color", "0", "--connect-timeout", "10",
                "--openssl-timeout", "10", "-p", "-S", "-U", "--jsonfile", jf, tgt]
            ctx.audit_log(f"testssl.sh -p -S -U {tgt}")
            log.info("  testssl.sh %d/%d %s", i, len(targets), tgt)
            try:
                proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, env=util.child_env())
            except OSError as e:
                st["testssl"] = f"failed to start: {e}"
                return
            status = _supervise(proc, limit_min * 60, "--testssl-timeout",
                                on_tick=lambda s, t=tgt: log.info("  testssl.sh %s still running (%d min)",
                                                                  t, s // 60),
                                tick_every=TESTSSL_TICK)
            rows = _load_testssl_json(jf)
        n, dup = _ingest_testssl(ctx, asset, tgt, rows)
        issues += n
        dups += dup
        # testssl.sh's exit trap writes scanTime even when it's stopped, so a stop always wins
        finished = not status.startswith("stopped") and any(r.get("id") == "scanTime" for r in rows)
        scan_problem = next((str(r.get("finding")) for r in rows
                             if str(r.get("severity", "")).upper() == "FATAL" or r.get("id") == "scanProblem"),
                            "")
        if finished and not scan_problem:
            completed += 1
            outcome = "done"
        else:
            if status == "completed":
                status = "ended without a full result" if rows else "ended with no results"
            elif status.startswith("exited"):
                status += ", incomplete" if rows else ", no results"
            outcome = status + (f": {scan_problem[:120]}" if scan_problem else "")
            if n:
                outcome += f" ({n} partial issues kept)"
            problems.append(f"{tgt} {outcome}")
            ctx.audit_log(f"testssl.sh {tgt} {outcome}")
        log.info("  testssl.sh %d/%d %s: %s, %d issue(s), %ds", i, len(targets), tgt, outcome, n,
                 time.monotonic() - h0)
        if status == STOPPED_CTRL_C:
            rest = len(targets) - i
            if rest:
                problems.append(f"{rest} host(s) skipped (Ctrl+C)")
                ctx.audit_log(f"testssl.sh skipped {rest} remaining host(s) (Ctrl+C)")
            break
        code = _exit_code(status)
        if code in TESTSSL_ENV_ERRORS and not completed:
            rest = len(targets) - i
            why = TESTSSL_ENV_ERRORS[code] + (f" ({scan_problem[:120]})" if scan_problem else "")
            log.warning("testssl.sh can't run here: %s. Skipping it for the remaining %d host(s).", why, rest)
            st["testssl"] = (f"could not run: {why}; exit {code}; 0/{len(targets)} hosts completed; "
                             f"built-in TLS checks still ran")
            ctx.audit_log(f"testssl.sh not run on {rest} remaining host(s): {why}")
            return
    note = (f"{completed}/{len(targets)} hosts completed; {issues} issues"
            + (f" ({dups} more already reported by built-in checks)" if dups else "")
            + f"; {round((time.monotonic() - t0) / 60, 1)} min")
    if problems:
        note += "; " + "; ".join(problems[:6]) + (f"; +{len(problems) - 6} more" if len(problems) > 6 else "")
    st["testssl"] = note
    log.info("testssl.sh: %s", note)


def run(ctx) -> None:
    testssl(ctx)
    nuclei(ctx)
