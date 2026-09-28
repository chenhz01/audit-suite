#!/usr/bin/env python3
"""audit_suite.egress_classify — T11 Egress Endpoint Classifier.

Upgrades wb-egress-audit.py from "domain counting" to endpoint
classification: every external endpoint found in logs is graded
UPLOAD_RISK / TELEMETRY / READ_DOWNLOAD / MODEL_API / UNKNOWN, with the
evidence line kept so a human can verify in seconds. Advisory output —
direction (GET vs PUT/POST) decides, not domain reputation.

Usage:
    python -m audit_suite.egress_classify scan <logs-dir> [--days N]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from .receipt import make_receipt

URL_RE = re.compile(r"https?://[a-zA-Z0-9._\-]+")
METHOD_RE = re.compile(r"\b(PUT|POST|PATCH)\b")

RULES = [  # (category, pattern) — first match wins
    ("OBJSTORE", re.compile(r"(aliyuncs|myqcloud|cos\.|oss-cn|obs\.|s3\.|blob\.core|storage\.googleapis)", re.I)),
    ("TELEMETRY", re.compile(r"(telemetry|analytics|galileo|metrics|sentry|umeng|track)", re.I)),
    ("READ_DOWNLOAD", re.compile(r"(client-pkg|threat|database|download|static|cdn|registry|pypi|npmjs)", re.I)),
    ("MODEL_API", re.compile(r"(openai|anthropic|deepseek|moonshot|bigmodel|dashscope|api\.)", re.I)),
]
PRIVATE_RE = re.compile(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost|\[::1\])")


def classify(domain: str, context: str) -> str:
    """OBJSTORE is direction-sensitive: PUT/POST = upload risk, else read.
    A bare PUT/POST on a normal API domain is routine interaction, not an
    exfiltration channel — reported as API_WRITE (info), never as risk."""
    if PRIVATE_RE.match(domain):
        return "SKIP_PRIVATE"
    if METHOD_RE.search(context):
        for cat, pat in RULES:
            if pat.search(domain):
                if cat == "OBJSTORE":
                    return "UPLOAD_RISK"
                break
        return "API_WRITE"
    for cat, pat in RULES:
        if pat.search(domain):
            return "READ_DOWNLOAD" if cat == "OBJSTORE" else cat
    return "UNKNOWN"


def scan(logs_dir: Path, days: int = 3) -> dict:
    if not logs_dir.is_dir():
        return make_receipt("egress-classify", execution_status="USAGE_ERROR",
                            inputs={"dir": str(logs_dir)},
                            findings=[{"id": "dir", "severity": "critical", "message": "not a directory"}])
    domains: dict[str, dict] = {}
    log_files = sorted(logs_dir.rglob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:days * 60]
    for f in log_files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in URL_RE.finditer(text):
            d = m.group(0).split("//", 1)[1].lower()
            ctx = text[max(0, m.start() - 120):m.end() + 120].replace("\n", " ")
            entry = domains.setdefault(d, {"count": 0, "category": None, "sample_context": ""})
            entry["count"] += 1
            if entry["category"] in (None, "UNKNOWN"):
                entry["category"] = classify(d, ctx)
            entry["sample_context"] = entry["sample_context"] or ctx[:200]
    risky = {d: e for d, e in domains.items() if e["category"] == "UPLOAD_RISK"}
    findings = [{"id": f"egress-{d}", "severity": "critical",
                 "message": f"possible upload channel: {d} ({e['count']} hits) — verify direction manually",
                 "location": e["sample_context"][:120], "reproducible": False}
                for d, e in sorted(risky.items(), key=lambda kv: -kv[1]["count"])]
    cats = ("UPLOAD_RISK", "TELEMETRY", "READ_DOWNLOAD", "MODEL_API", "API_WRITE", "UNKNOWN", "SKIP_PRIVATE")
    verdict = "FAIL" if risky else ("PASS-WITH-CAVEAT" if any(e["category"] == "UNKNOWN" for e in domains.values()) else "PASS")
    return make_receipt("egress-classify", verdict=verdict,
                        inputs={"dir": str(logs_dir), "days": days},
                        outputs={"domains": len(domains),
                                 "by_category": {c: sum(1 for e in domains.values() if e["category"] == c)
                                                  for c in cats}},
                        findings=findings,
                        caveats=["log-level only; packet-level verification is a separate instrument"])


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("scan"); s1.add_argument("dir"); s1.add_argument("--days", type=int, default=3)
    a = ap.parse_args()
    r = scan(Path(a.dir), a.days)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["verdict"] == "PASS" else (11 if r["verdict"] == "PASS-WITH-CAVEAT" else 12))
