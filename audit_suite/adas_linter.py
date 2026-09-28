#!/usr/bin/env python3
"""audit_suite.adas_linter — T01 ADAS v0.9 Conformance Linter.

Checks an agent-run evidence manifest against the six clauses of the ADAS
v0.9 public draft (standards/ADAS-v0.9-draft.md in the ARA repo):

  R1 three-state reporting   R2 artifact rule      R3 independent verifier
  R4 advisory-not-verdict    R5 identity lineage   R6 coverage honesty

Only machine-checkable aspects are enforced; content quality is a non-goal.
A failing clause is a finding, not a moral judgment (R4 applies to us too).

Usage:
    python -m audit_suite.adas_linter check <manifest.json>
    python -m audit_suite.adas_linter selftest
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .receipt import make_receipt, sha256_file

STATES = {"PASS", "FAIL", "NOT_RUN"}


def check_manifest(m: dict, base_dir: Path | None = None) -> tuple[str, list[dict]]:
    findings: list[dict] = []

    def add(cid: str, clause: str, sev: str, msg: str) -> None:
        findings.append({"id": cid, "severity": sev, "message": f"[{clause}] {msg}"})

    # R1 three-state reporting: every step declares PASS/FAIL/NOT_RUN
    results = m.get("results") or []
    if not results:
        add("adas-r1-empty", "R1", "major", "no per-step results declared — three states impossible")
    else:
        bad = [r.get("step", "?") for r in results if r.get("state") not in STATES]
        if bad:
            add("adas-r1-state", "R1", "major", f"steps without a valid three-state value {sorted(STATES)}: {bad}")
        states_seen = {r.get("state") for r in results}
        if states_seen == {"PASS"}:
            add("adas-r1-all-pass", "R1", "minor",
                "every step PASS — statistically suspicious; NOT_RUN/FAIL are legal states, use them")

    # R2 artifact rule: claimed artifacts must exist on disk
    for a in m.get("artifacts") or []:
        p = Path(a.get("path", ""))
        ok = p.is_file() if base_dir is None else (base_dir / p).is_file() or p.is_file()
        if not ok:
            add("adas-r2-missing", "R2", "critical", f"artifact not found on disk: {p}")
        elif a.get("sha256") and a["sha256"] != sha256_file(p if p.is_file() else base_dir / p):
            add("adas-r2-hash", "R2", "critical", f"artifact hash mismatch: {p}")

    # R3 independent verifier
    v = m.get("verifier") or {}
    if not v.get("independent"):
        add("adas-r3-independent", "R3", "major",
            "no independent verifier declared — generator grading its own output is self-certification")
    elif not v.get("evidence"):
        add("adas-r3-evidence", "R3", "minor", "independent verifier declared but no evidence pointer")

    # R4 advisory-not-verdict: the caveats field must EXIST (may be empty)
    if "caveats" not in m and "warnings" not in m:
        add("adas-r4-caveats", "R4", "minor",
            "no caveats/warnings field — clause R4 requires the slot to exist, even when empty")

    # R5 identity lineage
    ident = m.get("identity") or {}
    missing = [k for k in ("author", "email", "commit") if not ident.get(k)]
    if missing:
        add("adas-r5-identity", "R5", "minor", f"identity lineage incomplete: missing {missing}")

    # R6 coverage honesty
    cov = m.get("coverage") or {}
    if not isinstance(cov.get("examined"), int) or not isinstance(cov.get("total"), int):
        add("adas-r6-coverage", "R6", "minor", "coverage {examined,total} not declared")
    elif cov["examined"] > cov["total"]:
        add("adas-r6-exceeds", "R6", "critical", f"examined {cov['examined']} > total {cov['total']}")

    critical = [f for f in findings if f["severity"] == "critical"]
    major = [f for f in findings if f["severity"] == "major"]
    if critical:
        verdict = "FAIL"
    elif major:
        verdict = "FAIL" if len(major) >= 2 else "PASS-WITH-CAVEAT"
    elif findings:
        verdict = "PASS-WITH-CAVEAT"
    else:
        verdict = "PASS"
    return verdict, findings


def run(path: Path) -> dict:
    try:
        m = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return make_receipt("adas-linter", execution_status="USAGE_ERROR",
                            inputs={"file": str(path)},
                            findings=[{"id": "input", "severity": "critical", "message": str(e)}])
    base = path.parent
    verdict, findings = check_manifest(m, base)
    return make_receipt("adas-linter", verdict=verdict,
                        inputs={"file": str(path), "sha256": sha256_file(path), "spec": "ADAS v0.9"},
                        findings=findings)


def selftest() -> int:
    good = {"task": "t", "results": [{"step": "s1", "state": "PASS"}, {"step": "s2", "state": "NOT_RUN"}],
            "verifier": {"independent": True, "evidence": "ci.log"}, "caveats": [],
            "identity": {"author": "z", "email": "z@x", "commit": "abc"},
            "coverage": {"examined": 2, "total": 3}}
    v, f = check_manifest(good)
    assert v == "PASS" and not f, f"good manifest must PASS, got {v} {f}"

    lazy = {"task": "t", "results": [{"step": "s1", "state": "PASS"}], "verifier": {"independent": False}}
    v2, f2 = check_manifest(lazy)
    ids = {x["id"] for x in f2}
    assert v2 in ("FAIL", "PASS-WITH-CAVEAT") and "adas-r3-independent" in ids and "adas-r4-caveats" in ids, \
        f"lazy manifest must flag R3/R4, got {v2} {ids}"

    fraud = {"task": "t", "results": [{"step": "s", "state": "DONE"}],
             "artifacts": [{"path": "nope/ghost.bin"}], "verifier": {"independent": False},
             "coverage": {"examined": 9, "total": 3}}
    v3, f3 = check_manifest(fraud)
    assert v3 == "FAIL", f"fraud manifest must FAIL, got {v3} {f3}"
    print(json.dumps(make_receipt("adas-linter", verdict="PASS", outputs={"selftest": "passed"}), ensure_ascii=False))
    print("adas_linter selftest: 3/3 PASS")
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
