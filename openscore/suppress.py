"""Suppressions: record triaged false positives, accepted risks and compensating controls so they
stop counting against the score — with a reason, an approver and an expiry date, so nothing is
hidden forever.

File format (TOML), default location: suppressions/<domain>.toml

    [[suppress]]
    check = "http_cookie_httponly"         # check id (shown in the report); globs allowed: "net_exposed_*"
    asset = "portal.contoso.com"           # optional, glob; default "*"
    title_contains = "XSRF-TOKEN"          # optional extra match on title/evidence
    status = "false_positive"              # false_positive | accepted_risk | compensating_control
    reason = "CSRF token cookie must be readable by the SPA"
    approved_by = "J. Smith"
    expires = 2027-05-01                   # TOML date; required for accepted_risk / compensating_control
    control = "WAF rule 1234 blocks /admin from the internet"   # optional; what mitigates the risk
                                                                # (for compensating_control)
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import logging

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None

log = logging.getLogger("openscore")
STATUSES = ("false_positive", "accepted_risk", "compensating_control")


def load(path: str) -> list[dict]:
    if tomllib is None:
        raise RuntimeError("Suppressions need Python 3.11+ (tomllib)")
    with open(path, "rb") as f:
        data = tomllib.load(f)
    rules = []
    for i, r in enumerate(data.get("suppress", []), 1):
        if "check" not in r or "reason" not in r:
            raise ValueError(f"{path}: suppression #{i} needs at least 'check' and 'reason'")
        status = r.get("status", "false_positive")
        if status not in STATUSES:
            raise ValueError(f"{path}: suppression #{i} has invalid status {status!r}")
        exp = r.get("expires")
        if isinstance(exp, str):
            exp = dt.date.fromisoformat(exp)
        if status != "false_positive" and not exp:
            raise ValueError(f"{path}: suppression #{i} ({status}) must have an 'expires' date")
        rules.append({**r, "status": status, "expires": exp, "_id": i, "_hits": 0})
    return rules


def _match(rule, f) -> bool:
    if not fnmatch.fnmatch(f.check_id, rule["check"]):
        return False
    if not fnmatch.fnmatch(f.asset, rule.get("asset", "*")):
        return False
    tc = rule.get("title_contains")
    if tc and tc.lower() not in (f.title + " " + f.evidence).lower():
        return False
    return True


def apply(ctx, rules: list[dict]) -> dict:
    today = dt.date.today()
    expired_hits, applied = [], 0
    for f in ctx.findings:
        if f.severity == "pass":
            continue
        for r in rules:
            if not _match(r, f):
                continue
            exp = r.get("expires")
            if exp and exp < today:
                r["_expired"] = True
                expired_hits.append(f"#{r['_id']} {r['check']} on {f.asset} expired {exp}")
                continue
            r["_hits"] += 1
            f.suppression = {"status": r["status"], "reason": r["reason"],
                             "approved_by": r.get("approved_by", ""), "control": r.get("control", ""),
                             "expires": exp.isoformat() if exp else "", "rule": r["_id"]}
            applied += 1
            break
    unused = [f"#{r['_id']} {r['check']} ({r.get('asset', '*')})" for r in rules
              if r["_hits"] == 0 and not r.get("_expired")]
    if applied:
        log.info("Suppressions: %d findings suppressed", applied)
    return {"applied": applied, "expired": expired_hits, "unused": unused}


def template(findings, domain: str) -> str:
    """A ready-to-edit suppressions file containing every open finding, commented out."""
    out = [f"# OpenScore suppressions for {domain}",
           "# Uncomment an entry, set status/reason/approved_by (and expires for accepted risks),",
           f"# then save as suppressions/{domain}.toml and re-run the scan.\n"]
    for f in findings:
        if f.severity in ("pass",) or f.suppression:
            continue
        out += [f"# [{f.severity.upper()}] {f.title}",
                "# [[suppress]]",
                f'# check = "{f.check_id}"',
                f'# asset = "{f.asset}"',
                '# status = "false_positive"   # or accepted_risk / compensating_control',
                '# reason = ""',
                '# approved_by = ""',
                f"# expires = {(dt.date.today() + dt.timedelta(days=180)).isoformat()}", ""]
    return "\n".join(out)
