#!/usr/bin/env python3
"""audit_suite.suite — T13 Audit Family Unified Runtime.

One entry point for every tool in the suite. Each run:
  - executes the tool in a subprocess (isolation, no shared state)
  - captures its audit-receipt-v1 envelope
  - validates the receipt against the schema (T02)
  - stores it under receipts/
`suite report` aggregates all stored receipts and maps the aggregate onto
the execution-status-axis exit table (T06) — the same table every tool
already follows, applied to the suite itself.

Usage:
    python -m audit_suite.suite run <tool> [tool args...]
    python -m audit_suite.suite report
Tools: receipt | coverage_honesty | adas_linter | pkg_linter | trap_gen |
       drift_check | trust_analyzer | canon_vectors | egress_classify |
       opp_scorer | exit_table
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .receipt import check_receipt, make_receipt, now

SUITE_ROOT = Path(__file__).resolve().parent.parent
RECEIPTS_DIR = SUITE_ROOT / "receipts"

TOOLS = {
    "receipt": "receipt",
    "coverage_honesty": "coverage_honesty",
    "adas_linter": "adas_linter",
    "pkg_linter": "pkg_linter",
    "trap_gen": "trap_gen",
    "drift_check": "drift_check",
    "trust_analyzer": "trust_analyzer",
    "canon_vectors": "canon_vectors",
    "egress_classify": "egress_classify",
    "opp_scorer": "opp_scorer",
    "exit_table": "exit_table",
    "redirect_conformance": "redirect_conformance",
}

# per-tool default args so `suite run <tool>` works bare (self-use mode)
DEFAULT_ARGS = {
    "trap_gen": ["selftest"],
    "exit_table": [],
    "canon_vectors": ["verify"],
    "pkg_linter": ["selftest"],
    "coverage_honesty": ["selftest"],
    "adas_linter": ["selftest"],
    "trust_analyzer": ["selftest"],
    "receipt": ["selftest"],
    "redirect_conformance": ["selftest"],
}


def run_tool(tool: str, args: list[str]) -> dict:
    if tool not in TOOLS:
        return make_receipt("suite", execution_status="USAGE_ERROR",
                            inputs={"tool": tool},
                            findings=[{"id": "unknown-tool", "severity": "critical",
                                       "message": f"unknown tool {tool!r}; known: {sorted(TOOLS)}"}])
    cmd = [sys.executable, "-W", "ignore", "-m", f"audit_suite.{TOOLS[tool]}", *(args or DEFAULT_ARGS.get(tool, []))]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SUITE_ROOT), timeout=300)
    stdout = proc.stdout
    try:
        # tool stdout may be receipt-json followed by a human table; take the first JSON object
        decoder = json.JSONDecoder()
        obj, idx = decoder.raw_decode(stdout.strip())
        if isinstance(obj, dict) and obj.get("schema") == "audit-receipt-v1":
            receipt = obj
        else:
            raise ValueError("no receipt envelope in stdout")
    except ValueError:
        return make_receipt("suite", execution_status="EXPLICIT_FAILURE",
                            inputs={"tool": tool, "args": args},
                            findings=[{"id": "no-receipt", "severity": "critical",
                                       "message": f"tool did not emit a receipt (exit {proc.returncode})",
                                       "location": (proc.stderr.strip()[-300:] or "no stderr")}])
    errs = check_receipt(receipt)
    if errs:
        receipt["degraded"] = True
        receipt["caveats"] = receipt.get("caveats", []) + [f"receipt schema violations: {errs}"]
    RECEIPTS_DIR.mkdir(exist_ok=True)
    art = RECEIPTS_DIR / f"{tool}-{receipt['trace_id'][:8]}.json"
    art.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    receipt["suite_exit_code"] = proc.returncode
    return receipt


def report() -> dict:
    receipts = []
    for f in sorted(RECEIPTS_DIR.glob("*.json")):
        try:
            receipts.append(json.loads(f.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    by_tool: dict[str, dict] = {}
    for r in receipts:
        t = r.get("engine", "?")
        by_tool.setdefault(t, {"runs": 0, "last_verdict": None, "degraded": False})
        by_tool[t]["runs"] += 1
        by_tool[t]["last_verdict"] = r.get("verdict")
        by_tool[t]["degraded"] = by_tool[t]["degraded"] or r.get("degraded", False)
    any_fail = any(v["last_verdict"] == "FAIL" for v in by_tool.values())
    verdict = "FAIL" if any_fail else "PASS"
    return make_receipt("suite", verdict=verdict,
                        inputs={"receipts_dir": str(RECEIPTS_DIR)},
                        outputs={"tools_seen": by_tool, "receipts_total": len(receipts)},
                        caveats=["aggregate verdict = whether ANY tool's last run was FAIL"])


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "report":
        r = report()
        print(json.dumps(r, indent=2, ensure_ascii=False))
        sys.exit(0 if r["verdict"] == "PASS" else 12)
    if len(sys.argv) >= 2 and sys.argv[1] == "run":
        r = run_tool(sys.argv[2], sys.argv[3:])
        print(json.dumps(r, indent=2, ensure_ascii=False))
        # the suite propagates the tool's own verdict through the axis table
        from .exit_table import exit_for
        v = r.get("verdict")
        sys.exit(exit_for("SUCCESS", v, r.get("degraded", False)) if v else 3)
    print("USAGE_ERROR: need 'run <tool> [args]' or 'report'", file=sys.stderr)
    sys.exit(4)
