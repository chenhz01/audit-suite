#!/usr/bin/env python3
"""audit_suite.opp_scorer — T12 Contribution Opportunity Scorer.

Scores open issues of a repo by *your existing capability*, not by issue
importance (github-issue-triage-picker, productized). Heuristic scoring on
title/body keywords; output is a ranked shortlist with per-dimension scores.

Usage:
    python -m audit_suite.opp_scorer score <owner/repo> [--limit 30]
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from .receipt import make_receipt

# capability profile: what WE can already do (score bonus when an issue matches)
CAPABILITY = [
    ("repro| reproduce|复现|verify|verification|acceptance|three-state|artifact", "命中", 3),
    (r"test|pytest|coverage|ci\b", "可用", 2),
    (r"python|cli|json|schema|packaging|pyproject", "迁移", 2),
    (r"docs|documentation|readme|rfc|spec|standard", "完成", 2),
    (r"windows|\bllm\b|agent|prompt", "迁移", 1),
]

PAIN = re.compile(r"silent|not work|doesn't work|fails|bug|regress|broken|crash|hang", re.I)


def fetch_issues(repo: str, limit: int) -> list[dict]:
    r = subprocess.run(["gh", "api", f"repos/{repo}/issues?state=open&per_page={limit}"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:300])
    out = []
    for it in json.loads(r.stdout):
        if "pull_request" in it:  # skip PRs
            continue
        out.append({"number": it["number"], "title": it["title"],
                    "body": (it.get("body") or "")[:1500],
                    "comments": it.get("comments", 0),
                    "labels": [l["name"] for l in it.get("labels", [])]})
    return out


def score_issue(it: dict) -> dict:
    text = f"{it['title']}\n{it['body']}"
    dims: dict[str, int] = {}
    for pat, dim, pts in CAPABILITY:
        if re.search(pat, text, re.I):
            dims[dim] = dims.get(dim, 0) + pts
    if PAIN.search(text):
        dims["命中"] = dims.get("命中", 0) + 2
    dims["竞争"] = 2 if it["comments"] == 0 else (1 if it["comments"] <= 3 else 0)
    if any("good first issue" in l.lower() or "help wanted" in l.lower() for l in it["labels"]):
        dims["完成"] = dims.get("完成", 0) + 2
    total = sum(dims.values())
    return {"number": it["number"], "title": it["title"][:80], "total": total, "dims": dims,
            "url": f"https://github.com/{'REPO'}/issues/{it['number']}"}


def run(repo: str, limit: int) -> dict:
    try:
        issues = fetch_issues(repo, limit)
    except RuntimeError as e:
        return make_receipt("opp-scorer", execution_status="USAGE_ERROR",
                            inputs={"repo": repo},
                            findings=[{"id": "fetch", "severity": "critical", "message": str(e)}])
    ranked = sorted((score_issue(i) for i in issues), key=lambda x: -x["total"])
    for r_ in ranked:
        r_["url"] = f"https://github.com/{repo}/issues/{r_['number']}"
    return make_receipt("opp-scorer", verdict="PASS",
                        inputs={"repo": repo, "issues": len(issues)},
                        outputs={"top10": ranked[:10]},
                        caveats=["keyword heuristic; five-dim weights follow triage-picker skill, tune with real hits"])


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("score"); s1.add_argument("repo"); s1.add_argument("--limit", type=int, default=30)
    a = ap.parse_args()
    r = run(a.repo, a.limit)
    out = r["outputs"]["top10"]
    print(json.dumps(r, indent=2, ensure_ascii=False))
    for x in out[:10]:
        print(f"  #{x['number']:>5} [{x['total']:>2}] {x['title']}")
    sys.exit(0 if r["verdict"] == "PASS" else 12)
