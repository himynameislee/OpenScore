"""OpenScore command-line interface."""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import sys
import time

from . import __version__, report, suppress, util
from .models import ScanContext
from .modules import PIPELINE

log = logging.getLogger("openscore")

BANNER = r"""
  ___                   ___
 / _ \ _ __  ___ _ _   / __| __ ___ _ _ ___
| (_) | '_ \/ -_) ' \  \__ \/ _/ _ \ '_/ -_)
 \___/| .__/\___|_||_| |___/\__\___/_| \___|  v{v}
      |_|   external security rating — authorized use only
"""


QUICK_START = """\
examples:
  passive scan (safe on any domain):
    openscore example.com --client "Example Inc" --open

  full scan (ONLY with written permission from the owner):
    openscore example.com --ips 203.0.113.0/28 --active \\
        --authorization "SOW-114 signed J.Smith 2026-11-01" --open

  quicker active scan (skip the slowest tools):
    openscore example.com --active --authorization "..." --no-nuclei --no-testssl

  scan specific endpoints only (no subdomain discovery):
    openscore example.com --no-discovery --url https://vpn.example.com:10443/

  update OpenScore (git installs; downloads only what changed):
    openscore --update

modes:
  passive  DNS, email, certificate logs, reputation and Shodan data; no contact with the target
  light    normal-visitor web/TLS requests (always on)
  active   port scan, path probes, CORS, nuclei, testssl.sh; needs --active + --authorization
           and a typed scope confirmation, and every action is written to the audit log

API keys (optional; set as environment variables rather than flags):
  ABUSEIPDB_KEY   free at https://www.abuseipdb.com/account/api
  GREYNOISE_KEY   free community key
  HIBP_KEY        paid; your domain must be verified in Have I Been Pwned

output (./reports by default):
  <domain>-<time>.html   the report        <domain>-<time>.json   machine-readable data
  <domain>-<time>.audit.log                <domain>-<time>-evidence/   PNG exhibits + screenshots

(On Windows use .\\openscore.bat; from a source checkout: python3 -m openscore)
"""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="openscore",
        usage="openscore DOMAIN [options]\n       openscore --update\n       openscore -h",
        description="OpenScore: free, open-source external security rating and attack-surface review for "
                    "defenders, vulnerability management and authorized penetration tests. Grades a domain "
                    "A-F across 8 factors, with evidence, remediation and verify steps for every finding.",
        epilog=QUICK_START,
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=30))
    p.add_argument("domain", nargs="?", metavar="DOMAIN", help="Primary domain to rate, e.g. example.com")
    p.add_argument("--client", metavar="NAME", help="Client/organization name shown in the report")
    p.add_argument("-o", "--output", default="reports", metavar="DIR", help="Output directory (default: ./reports)")
    p.add_argument("--open", action="store_true", help="Open the HTML report in your browser when done")

    g = p.add_argument_group("scope")
    g.add_argument("--ips", nargs="*", default=[], metavar="CIDR",
                   help="Client-owned IPs/ranges to include (e.g. 203.0.113.0/28)")
    g.add_argument("--hosts", nargs="*", default=[], metavar="HOST", help="Extra hostnames/IPs to include")
    g.add_argument("--url", dest="urls", nargs="*", default=[], metavar="URL",
                   help="Extra web endpoints (e.g. https://vpn.example.com:10443)")
    g.add_argument("--exclude", nargs="*", default=[], metavar="HOST", help="Hostnames to skip")
    g.add_argument("--no-discovery", action="store_true", help="Skip subdomain discovery (apex + www + supplied hosts only)")
    g.add_argument("--max-hosts", type=int, default=60, metavar="N", help="Cap on discovered hosts (default 60)")

    a = p.add_argument_group("active checks (require written authorization)")
    a.add_argument("--active", action="store_true", help="Enable port scan, path probes, CORS, nuclei, testssl.sh")
    a.add_argument("--authorization", default="", metavar="REF",
                   help='Reference to written authorization, e.g. "SOW-114 signed J.Smith 2026-11-01"')
    a.add_argument("-y", "--yes", action="store_true", help="Don't prompt for scope confirmation")
    a.add_argument("--full-ports", action="store_true", help="Scan all 65535 TCP ports (slow)")
    a.add_argument("--scan-cdn", action="store_true", help="Also port-scan CDN/SaaS IPs (normally skipped)")
    a.add_argument("--no-nuclei", action="store_true", help="Skip nuclei (the slowest active step)")
    a.add_argument("--nuclei-rate", type=int, default=100, metavar="N",
                   help="nuclei target requests per second, shared by all sites (default 100)")
    a.add_argument("--nuclei-timeout", type=float, default=60, metavar="MIN",
                   help="Stop nuclei after MIN minutes and keep what it found (default 60)")
    a.add_argument("--no-testssl", action="store_true", help="Skip testssl.sh (about 1-2 minutes per HTTPS host)")
    a.add_argument("--testssl-timeout", type=float, default=5, metavar="MIN",
                   help="Stop testssl.sh on a host after MIN minutes and keep what it found (default 5)")
    a.add_argument("--delay", type=float, default=0.25, metavar="SEC", help="Seconds between probe requests per host (default 0.25)")

    k = p.add_argument_group("API keys (prefer the environment variables; flags end up in shell history)")
    k.add_argument("--abuseipdb-key", default=os.getenv("ABUSEIPDB_KEY", ""), metavar="KEY", help="default: $ABUSEIPDB_KEY")
    k.add_argument("--greynoise-key", default=os.getenv("GREYNOISE_KEY", ""), metavar="KEY", help="default: $GREYNOISE_KEY")
    k.add_argument("--hibp-key", default=os.getenv("HIBP_KEY", ""), metavar="KEY", help="default: $HIBP_KEY")

    o = p.add_argument_group("report and evidence")
    o.add_argument("--suppressions", metavar="FILE", help="Suppressions TOML (default: suppressions/<domain>.toml if present)")
    o.add_argument("--emit-suppressions", action="store_true",
                   help="Also write a commented suppressions template listing every open finding")
    o.add_argument("--baseline", metavar="FILE", help="Previous OpenScore JSON to compare against (default: latest in output dir)")
    o.add_argument("--no-baseline", action="store_true", help="Don't compare with a previous scan")
    o.add_argument("--no-screenshots", action="store_true", help="Skip screenshot evidence")
    o.add_argument("--max-screenshots", type=int, default=60, metavar="N", help="Cap on page screenshots per scan (default 60)")
    o.add_argument("--max-proof-images", type=int, default=250, metavar="N",
                   help="Cap on PNG evidence exhibits exported per scan (default 250)")

    x = p.add_argument_group("advanced")
    x.add_argument("--resolver", nargs="*", default=[], metavar="IP", help="DNS resolver IP(s) (default: system)")
    x.add_argument("--dkim-selectors", nargs="*", default=[], metavar="SEL", help="Extra DKIM selectors to check")
    x.add_argument("--threads", type=int, default=8, metavar="N", help="Parallel workers (default 8)")
    x.add_argument("--timeout", type=float, default=12, metavar="SEC", help="Network timeout per request (default 12)")
    x.add_argument("--user-agent", default=util.DEFAULT_UA, metavar="UA", help="HTTP User-Agent (default identifies OpenScore)")
    x.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    m = p.add_argument_group("other")
    m.add_argument("--update", action="store_true",
                   help="Update OpenScore from git (downloads only the changes) and exit; no scan")
    m.add_argument("--version", action="version", version=f"OpenScore {__version__}")
    return p


def parse_args(argv=None):
    p = _parser()
    args = p.parse_args(argv)
    if args.update:
        return args
    if not args.domain:
        print(f"OpenScore {__version__}: no domain given.\n\n{QUICK_START}\nAll options: openscore -h",
              file=sys.stderr)
        sys.exit(2)

    args.domain = args.domain.lower().strip().strip(".")
    args.domain = re.sub(r"^https?://", "", args.domain).split("/")[0]
    args.exclude = {h.lower() for h in args.exclude}
    args.ip_ranges = []
    for r in args.ips:
        try:
            args.ip_ranges.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            p.error(f"invalid IP/CIDR: {r}")
    args.hosts = [h.lower() for h in args.hosts]
    return args


def confirm_scope(cfg) -> None:
    if not cfg.active:
        return
    if not cfg.authorization:
        sys.exit("ERROR: --active requires --authorization \"<reference to written permission>\".\n"
                 "Only run active checks against systems your client has authorized in writing.")
    print(f"\nACTIVE SCAN SCOPE\n  domain + subdomains: {cfg.domain}")
    for r in cfg.ip_ranges:
        print(f"  IP range:           {r}")
    for h in cfg.hosts + cfg.urls:
        print(f"  extra:              {h}")
    print(f"  authorization:      {cfg.authorization}\n")
    if not cfg.yes:
        ans = input(f"Type the domain ({cfg.domain}) to confirm you are authorized to actively test this scope: ")
        if ans.strip().lower() != cfg.domain:
            sys.exit("Scope not confirmed — aborting.")


def assessed_factors(ctx, ran: set[str]) -> set[str]:
    a = set()
    dns_ok = not ctx.flags.get("dns_failed")
    if "dns_email" in ran and dns_ok:
        a |= {"email", "dns"}
    if "web" in ran and ctx.flags.get("web_reached"):
        a |= {"tls", "appsec", "exposure", "patching"}
        if ctx.flags.get("tls_interceptor_org") and not ctx.flags.get("tls_real"):
            a.discard("tls")     # every TLS result came from the inspection proxy: don't grade it
    if "reputation" in ran and (dns_ok or ctx.cfg.abuseipdb_key or ctx.flags.get("internetdb_ok")):
        a.add("reputation")
    if ctx.flags.get("internetdb_ok") or "ports" in ran:
        a |= {"network", "patching"}
    if "exposures" in ran:
        a.add("exposure")
    return a


def _setup_platform() -> None:
    """Windows consoles default to cp1252; force UTF-8 so banners/arrows never crash the run,
    and put a bundled ./tools directory (nuclei.exe, subfinder.exe from install_windows.ps1) on PATH."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if getattr(sys, "frozen", False):          # PyInstaller openscore.exe
        here = os.path.dirname(sys.executable)
    else:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Tools the Windows installer downloads live next to OpenScore (.\tools). Never look in the
    # current directory: running openscore from a folder with a planted tools\nmap.exe would run it.
    d = os.path.join(here, "tools")
    if os.path.isdir(d) and d not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")


def check_network(ctx) -> None:
    """Warn when this network re-signs HTTPS (corporate TLS inspection). Data-source APIs keep working
    (they trust the OS store), but TLS results for intercepted hosts would describe the proxy, not
    the target, so web.tls_check skips them and the report says so."""
    r = util.detect_tls_inspection()
    env = ctx.module_status.setdefault("environment", {})
    if r["intercepted"]:
        ctx.flags["tls_interceptor_org"] = r["issuer"]
        env["tls_inspection"] = (
            f"DETECTED: HTTPS on this network is re-signed by '{r['issuer']}'. Data sources still work "
            "(OpenScore trusts the OS certificate store for them), but certificate/protocol/cipher "
            "results for hosts behind the proxy describe the proxy, so they are skipped. "
            "Scan from a network without TLS inspection for complete TLS results.")
        log.warning("TLS inspection detected (HTTPS re-signed by '%s'). TLS results for intercepted "
                    "hosts will be skipped; scan from an uninspected network for full TLS coverage.", r["issuer"])
    elif r["intercepted"] is None and r.get("error"):
        env["tls_inspection"] = f"could not check ({r['error']})"
    else:
        env["tls_inspection"] = "not detected"


def main(argv=None) -> int:
    _setup_platform()
    cfg = parse_args(argv)
    if cfg.update:
        from . import update
        return update.run()
    logging.basicConfig(level=logging.DEBUG if cfg.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    for noisy in ("urllib3", "requests"):
        logging.getLogger(noisy).setLevel(logging.ERROR)
    print(BANNER.format(v=__version__), file=sys.stderr)
    confirm_scope(cfg)

    ctx = ScanContext(cfg.domain, cfg)
    os.makedirs(cfg.output, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    base = os.path.join(cfg.output, f"{cfg.domain}-{stamp}")
    ctx.evidence_dir = base + "-evidence"
    ctx.session = util.make_session(cfg.user_agent)
    ctx.dns = util.DNS(cfg.resolver or None)
    ctx.limiter = util.RateLimiter(cfg.delay)
    ctx.audit_log(f"scan start domain={cfg.domain} mode={'active' if cfg.active else 'passive+light'} "
                  f"authorization={cfg.authorization!r} operator={os.getenv('USER') or os.getenv('USERNAME', '?')}")
    tools = {t: bool(util.which(t)) for t in ("nmap", "nuclei", "subfinder", "testssl.sh")}
    tools["testssl.sh"] = tools["testssl.sh"] or bool(util.which("testssl"))   # Debian/Ubuntu name
    rules = []
    spath = cfg.suppressions or os.path.join("suppressions", f"{cfg.domain}.toml")
    if cfg.suppressions or os.path.exists(spath):
        try:
            rules = suppress.load(spath)
            log.info("Loaded %d suppressions from %s", len(rules), spath)
        except Exception as e:
            sys.exit(f"ERROR loading suppressions {spath}: {e}")
    ctx.module_status["tools"] = {k: ("found" if v else "not installed") for k, v in tools.items()}
    check_network(ctx)

    ran = set()
    for mod in PIPELINE:
        name = mod.__name__.split(".")[-1]
        if mod.MODE == "active" and not cfg.active:
            continue
        t0 = time.time()
        log.info("── %s (%s)", name, mod.MODE)
        try:
            mod.run(ctx)
            ran.add(name)
        except KeyboardInterrupt:
            log.warning("Interrupted during %s — writing partial report", name)
            break
        except Exception as e:
            log.exception("Module %s failed: %s", name, e)
            ctx.module_status.setdefault(name, {})["error"] = str(e)
        ctx.module_status.setdefault(name, {})["seconds"] = round(time.time() - t0, 1)
    ctx.audit_log("scan end")
    if rules:
        ctx.suppression_status = {"file": spath, **suppress.apply(ctx, rules)}

    result = report.build_result(ctx, assessed_factors(ctx, ran))

    delta = None
    if not cfg.no_baseline:
        bpath = cfg.baseline or _latest(cfg.output, cfg.domain)
        if bpath:
            try:
                with open(bpath, encoding="utf-8") as bf:
                    delta = report.diff(result, json.load(bf), bpath)
                result["baseline"] = {"path": bpath, **{k: v for k, v in delta.items() if k not in ("new", "resolved")}}
                log.info("Compared with %s", bpath)
                if delta["caveats"]:
                    log.warning("Change summary isn't like-for-like: %s.", "; ".join(delta["caveats"]))
            except Exception as e:
                log.warning("Could not load baseline %s: %s", bpath, e)
                ctx.module_status["baseline"] = f"could not load {bpath}: {e}"
        else:
            # say why there's no "Change since last scan" section (module_status is shared with result)
            ctx.module_status["baseline"] = (f"no previous {cfg.domain} scan in {os.path.abspath(cfg.output)}; "
                                             "use --baseline FILE to compare with one elsewhere")
            log.info("No previous scan of %s in %s; no change summary (use --baseline FILE).",
                     cfg.domain, cfg.output)

    report.write_json(result, base + ".json")
    report.write_html(result, base + ".html", delta)
    with open(base + ".audit.log", "w", encoding="utf-8") as f:
        f.write("\n".join(ctx.audit) + "\n")
    if cfg.emit_suppressions:
        with open(base + ".suppressions-template.toml", "w", encoding="utf-8") as f:
            f.write(suppress.template(ctx.findings, cfg.domain))

    ov = result["overall"]
    print(f"\n  {cfg.domain}: {ov['score']:.0f}/100  grade {ov['grade']}", file=sys.stderr)
    for k, v in ov["factors"].items():
        print(f"    {k:<11} {('%5.0f  %s' % (v['score'], v['grade'])) if v else '   –  not assessed'}", file=sys.stderr)
    print(f"\n  Report: {base}.html\n  Data:   {base}.json\n", file=sys.stderr)
    if cfg.open:
        import pathlib
        import webbrowser
        webbrowser.open(pathlib.Path(base + ".html").resolve().as_uri())
    return 0


def _latest(outdir, domain):
    try:
        files = sorted(f for f in os.listdir(outdir) if f.startswith(domain + "-") and f.endswith(".json"))
    except FileNotFoundError:
        return None
    return os.path.join(outdir, files[-1]) if files else None


if __name__ == "__main__":
    sys.exit(main())
