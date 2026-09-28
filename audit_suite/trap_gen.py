#!/usr/bin/env python3
"""audit_suite.trap_gen — T05 Falsifiable Trap Generator.

Generates test cases designed to separate weak success heuristics from
correct gates. Every trap declares, up front, who it SHOULD deceive and who
it SHOULD block — that declaration is what makes it falsifiable (EXP-001
pattern, born from the superpowers #2332 audit).

Built-in judges (two reference implementations):
  naive    — reads the last non-empty output line, PASS iff it contains "pass"
  exitgate — PASS iff the process exit code is 0 (correct behavior)

Usage:
    python -m audit_suite.trap_gen run       # generate traps, run both judges, verify expectations
    python -m audit_suite.trap_gen list
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .receipt import make_receipt

# Each trap: id, python body, expectation per judge.
TRAPS = [
    {"id": "last-line-success", "body":
         "print('WARNING: 1 test failed: auth_edge_case')\n"
         "print('All tests passed (34/34)')\nraise SystemExit(1)",
     "expect": {"naive": "PASS", "exitgate": "FAIL"}},
    {"id": "exit-zero-failure-text", "body":
         "print('FAILURE: suite collapsed')\nraise SystemExit(0)",
     "expect": {"naive": "FAIL", "exitgate": "PASS"}},  # naive misses soft-pass with scary text
    {"id": "silent-success", "body": "raise SystemExit(0)",
     "expect": {"naive": "FAIL", "exitgate": "PASS"}},  # no output at all
    {"id": "unicode-lookalike", "body":
         "print('all tests \u03c1assed (5/5)')\nraise SystemExit(1)",  # Greek rho, not 'p'
     "expect": {"naive": "FAIL", "exitgate": "FAIL"}},  # both block: honest but sneaky
    {"id": "passed-then-crash", "body":
         "print('tests passed (9/9)')\nimport os; os.write(2, b'segfault during teardown')\nraise SystemExit(139)",
     "expect": {"naive": "PASS", "exitgate": "FAIL"}},
]


def judge_naive(stdout: str, exit_code: int) -> str:
    lines = [l for l in stdout.splitlines() if l.strip()]
    last = lines[-1].lower() if lines else ""
    return "PASS" if "pass" in last else "FAIL"


def judge_exitgate(stdout: str, exit_code: int) -> str:
    return "PASS" if exit_code == 0 else "FAIL"


def run_traps() -> dict:
    findings, matched, mismatches = [], 0, []
    for t in TRAPS:
        proc = subprocess.run([sys.executable, "-c", t["body"]], capture_output=True, text=True)
        got = {"naive": judge_naive(proc.stdout, proc.returncode),
               "exitgate": judge_exitgate(proc.stdout, proc.returncode)}
        for judge, expected in t["expect"].items():
            if got[judge] == expected:
                matched += 1
            else:
                mismatches.append(f"{t['id']}/{judge}: expected {expected}, got {got[judge]}")
                findings.append({"id": f"trap-{t['id']}", "severity": "critical",
                                 "message": f"judge '{judge}' behaved unexpectedly on '{t['id']}'",
                                 "reproducible": True})
    verdict = "PASS" if not mismatches else "FAIL"
    return make_receipt(
        "trap-gen", verdict=verdict,
        inputs={"traps": len(TRAPS), "judges": ["naive", "exitgate"]},
        outputs={"expectations_checked": len(TRAPS) * 2, "matched": matched},
        findings=findings,
        caveats=["trap set is a starter kit; every future audit finding should become a new trap"],
    )


def selftest() -> int:
    assert judge_naive("x\nAll tests passed (34/34)", 1) == "PASS"   # deceived, as designed
    assert judge_exitgate("x\nAll tests passed (34/34)", 1) == "FAIL"  # not deceived
    r = run_traps()
    assert r["verdict"] == "PASS", f"all 10 expectations must match: {r['findings']}"
    print(f"trap_gen selftest: {r['outputs']['matched']}/{r['outputs']['expectations_checked']} expectations matched")
    return 0


if __name__ == "__main__":
    r = run_traps()
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["verdict"] == "PASS" else 12)
