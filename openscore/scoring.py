"""Transparent scoring model.

Every point is explainable:

* Each factor starts at 100.
* Each finding deducts by severity: critical 35, high 18, medium 8, low 3, info 0.
* Repeats of the same issue (same check + title) on more assets are dampened (each extra occurrence counts half
  as much as the previous one), so one misconfiguration copied across 40 subdomains doesn't
  zero a factor — but breadth still matters.
* Tentative findings (version-based CVE matches, DKIM-not-found) count half.
* Findings on third-party SaaS-hosted assets are excluded (shown separately for dispute).
* Suppressed findings (triaged false positives, accepted risks and compensating controls, the last two with an expiry) are excluded.
* Overall = weighted average of assessed factors; any open, confirmed critical caps the overall at 79 (C).
  A critical that still needs verification (version-based match) doesn't cap the grade; the report
  says it would if confirmed.
* Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.
"""
from __future__ import annotations

from collections import defaultdict

from .kb import FACTORS

DEDUCT = {"critical": 35, "high": 18, "medium": 8, "low": 3, "info": 0, "pass": 0}
CRITICAL_CAP = 79


def grade(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def _scored(findings):
    return [f for f in findings if f.severity != "pass" and not f.third_party and not f.suppression]


def factor_scores(findings, assessed: set[str]) -> dict:
    by_factor = defaultdict(list)
    for f in _scored(findings):
        by_factor[f.factor].append(f)
    out = {}
    for fac in FACTORS:
        if fac not in assessed and not by_factor.get(fac):
            out[fac] = None
            continue
        per_check = defaultdict(list)
        for f in by_factor.get(fac, []):
            per_check[(f.check_id, f.title)].append(f)
        total = 0.0
        for check, fs in per_check.items():
            fs.sort(key=lambda f: -DEDUCT[f.severity])
            for i, f in enumerate(fs):
                d = DEDUCT[f.severity] * (0.5 ** i)
                if f.confidence == "tentative":
                    d *= 0.5
                total += d
        out[fac] = max(0.0, round(100 - total, 1))
    return out


def overall(findings, assessed: set[str]) -> dict:
    fs = factor_scores(findings, assessed)
    num = den = 0.0
    for fac, s in fs.items():
        if s is None:
            continue
        w = FACTORS[fac]["weight"]
        num += s * w
        den += w
    score = round(num / den, 1) if den else 0.0
    crits = [f for f in _scored(findings) if f.severity == "critical"]
    capped = cap_pending = False
    if score > CRITICAL_CAP:
        if any(f.confidence != "tentative" for f in crits):
            score, capped = CRITICAL_CAP, True
        elif crits:
            cap_pending = True      # would be capped if a tentative critical is confirmed
    return {"score": score, "grade": grade(score), "capped": capped, "cap_pending": cap_pending,
            "factors": {k: ({"score": v, "grade": grade(v)} if v is not None else None) for k, v in fs.items()}}


def quick_wins(findings, assessed: set[str], limit: int = 12) -> list[dict]:
    """For each issue (check + title, the same grouping the score uses), how many overall points
    do we gain if it's fixed everywhere?"""
    base = overall(findings, assessed)["score"]
    groups = defaultdict(list)
    for f in _scored(findings):
        groups[(f.check_id, f.title, f.factor)].append(f)
    wins = []
    for (check, title, fac), fs in groups.items():
        remaining = [f for f in findings if not (f.check_id == check and f.title == title and f.factor == fac)]
        gain = round(overall(remaining, assessed)["score"] - base, 1)
        if gain <= 0:
            continue
        worst = min(fs, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity))
        wins.append({"check_id": check, "factor": fac, "title": title,
                     "severity": worst.severity, "assets": sorted({f.asset for f in fs}), "gain": gain})
    wins.sort(key=lambda w: -w["gain"])
    return wins[:limit]
