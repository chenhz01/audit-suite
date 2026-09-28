#!/usr/bin/env python3
"""audit_suite.coverage_honesty — T04 Coverage Honesty Checker.

Catches "sampling masquerading as full enumeration": a report claiming to
examine N of M items must actually enumerate N items, must not exceed M,
and must say what happened to the M-N unexamined ones.

Extracted and generalized from ARA audit.py gate_coverage / gate_unjudged.

Usage:
    python -m audit_suite.coverage_honesty check <report.json>
    python -m audit_suite.coverage_honesty selftest
Input (minimal): {"coverage": {"examined": int, "total": int},
                  "enumerated": ["id", ...], "source_of_set": {"method": str}}
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .receipt import make_receipt, sha256_file

BIASED_SET_METHODS = {"html-page", "editor-pick", "featured-list", "curated"}


def check_coverage(report: dict) -> tuple[str, list[dict]]:
    """Return (verdict, findings)."""
    findings: list[dict] = []
    cov = report.get("coverage")
    if not isinstance(cov, dict) or "examined" not in cov or "total" not in cov:
        return "FAIL", [{"id": "cov-missing", "severity": "critical",
                         "message": "missing coverage {examined, total} — cannot be judged"}]
    examined, total = cov["examined"], cov["total"]
    if not (isinstance(examined, int) and isinstance(total, int)) or total < 1 or examined < 0:
        return "FAIL", [{"id": "cov-malformed", "severity": "critical",
                         "message": f"coverage malformed: examined={examined!r} total={total!r}"}]

    # Gate 1: examined <= total (sampling cannot exceed the set)
    if examined > total:
        findings.append({"id": "cov-exceeds", "severity": "critical",
                         "message": f"examined {examined} > total {total} — arithmetic impossibility",
                         "location": "coverage"})
    # Gate 2: declared examined must equal actual enumeration length
    enum = report.get("enumerated")
    if isinstance(enum, list):
        if len(enum) != examined:
            findings.append({"id": "cov-enum-mismatch", "severity": "major",
                             "message": f"declared examined={examined} but enumerated {len(enum)} items",
                             "location": "enumerated", "reproducible": True})
    else:
        findings.append({"id": "cov-enum-absent", "severity": "major",
                         "message": "no enumerated list — examined count is uncorroborated"})
    # Gate 3: unexamined remainder must be acknowledged, not hidden
    unjudged = total - examined
    if unjudged > 0 and "unjudged" not in json.dumps(report).lower() and examined < total:
        findings.append({"id": "cov-unjudged-silent", "severity": "minor",
                         "message": f"{unjudged}/{total} unexamined items never acknowledged — "
                                    f"partial coverage presented as if complete",
                         "location": "coverage"})
    # Gate 4: where did the full set come from? A curated subset combined with
    # partial coverage is the classic "sampling masquerading as full" pattern.
    src = str((report.get("source_of_set") or {}).get("method", "")).lower()
    if src in BIASED_SET_METHODS:
        sev = "critical" if examined < total else "major"
        findings.append({"id": "cov-biased-set", "severity": sev,
                         "message": f"full set came from '{src}' and only {examined}/{total} examined — "
                                    f"curated subsets are biased; enumerate via api/script/filesystem",
                         "location": "source_of_set.method", "reproducible": True})
    if src == "":
        findings.append({"id": "cov-set-unsourced", "severity": "minor",
                         "message": "source_of_set.method missing — the denominator's origin is unstated"})

    critical = [f for f in findings if f["severity"] == "critical"]
    major = [f for f in findings if f["severity"] == "major"]
    if critical:
        return "FAIL", findings
    if findings:
        return ("FAIL" if len(major) >= 2 else "PASS-WITH-CAVEAT"), findings
    return "PASS", findings


def run(path: Path) -> dict:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return make_receipt("coverage-honesty", execution_status="USAGE_ERROR",
                            inputs={"file": str(path)},
                            findings=[{"id": "input", "severity": "critical", "message": str(e)}])
    verdict, findings = check_coverage(report)
    return make_receipt("coverage-honesty", verdict=verdict,
                        inputs={"file": str(path), "sha256": sha256_file(path)},
                        outputs={"coverage": report.get("coverage", {})},
                        findings=findings,
                        caveats=["content-level fact-checking is a non-goal (see ARA protocol)"])


def selftest() -> int:
    full = {"coverage": {"examined": 3, "total": 3}, "enumerated": ["a", "b", "c"],
            "source_of_set": {"method": "api"}}
    fraud = {"coverage": {"examined": 11, "total": 260}, "enumerated": ["x"] * 11,
             "source_of_set": {"method": "html-page"}}
    v_ok, f_ok = check_coverage(full)
    v_bad, f_bad = check_coverage(fraud)
    assert v_ok == "PASS" and not f_ok, f"clean sample must PASS, got {v_ok} {f_ok}"
    assert v_bad == "FAIL" and len(f_bad) >= 2, f"fraud sample must FAIL, got {v_bad} / {f_bad}"
    # 1 major only => PASS-WITH-CAVEAT
    v_mid, _ = check_coverage({"coverage": {"examined": 2, "total": 5}, "enumerated": ["a", "b"],
                               "source_of_set": {"method": "api"}})
    assert v_mid == "PASS-WITH-CAVEAT", f"partial-but-honest should be caveat, got {v_mid}"
    print(json.dumps(make_receipt("coverage-honesty", verdict="PASS", outputs={"selftest": "passed"}), ensure_ascii=False))
    print("coverage_honesty selftest: 3/3 PASS")
    return 0


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("check"); s1.add_argument("file")
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "selftest":
        sys.exit(selftest())
    r = run(Path(a.file))
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["verdict"] == "PASS" else (11 if r["verdict"] == "PASS-WITH-CAVEAT" else 12))
