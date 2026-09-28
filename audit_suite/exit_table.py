#!/usr/bin/env python3
"""audit_suite.exit_table — T06 conformance checker for execution-status-axis v1.0.

Holds the spec table as data and verifies that a tool's exit-code mapping
conforms. The spec text lives in standards/execution-status-axis-v1.0.md;
this module makes the table executable so text and code cannot drift.

Usage:
    python -m audit_suite.exit_table selftest
    python -m audit_suite.exit_table check <tool-name>
"""
from __future__ import annotations

import sys

from .receipt import make_receipt

# (exit, execution_status, verdict-or-None, degraded)
SPEC_TABLE: dict[int, tuple[str, str | None, bool]] = {
    0:  ("SUCCESS", "PASS", False),
    10: ("SUCCESS", "PASS", True),
    11: ("SUCCESS", "PASS-WITH-CAVEAT", False),
    12: ("SUCCESS", "FAIL", False),
    13: ("SUCCESS", "FAIL", True),
    2:  ("EXPLICIT_FAILURE", None, False),
    3:  ("SILENT_TIMEOUT", None, False),
    4:  ("USAGE_ERROR", None, False),
    5:  ("POLICY_DENIED", None, False),
}


def exit_for(execution_status: str, verdict: str | None, degraded: bool = False) -> int:
    """Canonical mapping used by every tool in the suite (first match wins)."""
    if execution_status == "SUCCESS" and verdict == "PASS":
        return 10 if degraded else 0
    if execution_status == "SUCCESS" and verdict == "PASS-WITH-CAVEAT":
        return 11
    if execution_status == "SUCCESS" and verdict == "FAIL":
        return 13 if degraded else 12
    if execution_status == "EXPLICIT_FAILURE":
        return 2
    if execution_status == "SILENT_TIMEOUT":
        return 3
    if execution_status == "USAGE_ERROR":
        return 4
    if execution_status == "POLICY_DENIED":
        return 5
    raise ValueError(f"unmapped terminal state: {execution_status}/{verdict}")


def conformance_receipt() -> dict:
    """Verify the canonical mapping row by row against the spec table."""
    bad: list[str] = []
    for exit_code, (status, verdict, degraded) in sorted(SPEC_TABLE.items()):
        got = exit_for(status, verdict, degraded)
        if got != exit_code:
            bad.append(f"table row exit {exit_code}: mapping returned {got}")
    # invariant: no-artifact states never carry a verdict
    for status in ("SILENT_TIMEOUT", "USAGE_ERROR", "POLICY_DENIED"):
        try:
            make_receipt("exit-table", verdict="PASS", execution_status=status)
            bad.append(f"{status}: verdict accepted but no artifact can exist")
        except ValueError:
            pass
    ok = not bad
    return make_receipt(
        "execution-status-axis-conformance", verdict="PASS" if ok else "FAIL",
        inputs={"spec": "execution-status-axis-v1.0"},
        outputs={"rows_checked": len(SPEC_TABLE)},
        findings=[{"id": "row-mismatch", "severity": "critical", "message": m} for m in bad],
    )


if __name__ == "__main__":
    r = conformance_receipt()
    import json
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["verdict"] == "PASS" else 12)
