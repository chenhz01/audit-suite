#!/usr/bin/env python3
"""audit_suite.receipt — T02 Audit Receipt Format Schema (v1) + zero-dep validator.

One envelope for every tool in the suite. Downstream consumers (CI, other
agents) read receipts, not prose. The envelope extends the ARA output
contract with the execution-status axis (T06).

Usage:
    python -m audit_suite.receipt make   --engine demo --verdict PASS
    python -m audit_suite.receipt check  <receipt.json>
    python -m audit_suite.receipt selftest
Exit codes follow standards/execution-status-axis-v1.0.md (T06).
"""
from __future__ import annotations

import json
import sys
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "audit-receipt-v1.schema.json"
ENGINE = "audit-suite"
VERSION = "0.1.0"

# T06 execution-status axis (orthogonal to the verdict)
EXECUTION_STATUSES = ("SUCCESS", "EXPLICIT_FAILURE", "SILENT_TIMEOUT", "USAGE_ERROR", "POLICY_DENIED")
VERDICTS = ("PASS", "PASS-WITH-CAVEAT", "FAIL")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(p: Path) -> str | None:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None


def make_receipt(engine: str, *, verdict: str | None = None, execution_status: str = "SUCCESS",
                 degraded: bool = False, confidence: float = 1.0, inputs: dict | None = None,
                 outputs: dict | None = None, findings: list | None = None,
                 artifacts: list | None = None, caveats: list | None = None,
                 trace_id: str | None = None) -> dict:
    """Build a receipt. verdict=None is only legal when execution_status is not SUCCESS."""
    if verdict is None and execution_status == "SUCCESS":
        raise ValueError("a SUCCESS run must carry a verdict (or be SILENT_TIMEOUT)")
    if verdict is not None and execution_status not in ("SUCCESS", "EXPLICIT_FAILURE"):
        raise ValueError(f"verdict forbidden under {execution_status}")
    return {
        "engine": engine, "suite_version": VERSION,
        "inputs": inputs or {"type": "unspecified"},
        "outputs": outputs or {"type": "unspecified"},
        "execution_status": execution_status,
        "verdict": verdict,
        "confidence": confidence, "degraded": degraded,
        "caveats": caveats or [], "findings": findings or [],
        "artifacts": artifacts or [],
        "started_at": now(), "finished_at": now(),
        "trace_id": trace_id or str(uuid.uuid4()),
        "schema": "audit-receipt-v1",
    }


# ---------------------------------------------------------------- T02 validator
# Zero-dependency subset of JSON Schema draft-07: type/required/enum/properties/items.

def _type_ok(v, t) -> bool:
    m = {"object": dict, "array": list, "string": str, "number": (int, float),
         "integer": int, "boolean": bool, "null": type(None)}
    if t not in m:
        return False
    if t == "integer" and isinstance(v, bool):
        return False
    return isinstance(v, m[t])


def _validate(v, schema: dict, path="$", errs: list | None = None) -> list:
    errs = errs if errs is not None else []
    if "type" in schema and not _type_ok(v, schema["type"]):
        errs.append(f"{path}: expected {schema['type']}, got {type(v).__name__}")
        return errs
    if "enum" in schema and v not in schema["enum"]:
        errs.append(f"{path}: {v!r} not in enum {schema['enum']}")
    if isinstance(v, dict):
        for k in schema.get("required", []):
            if k not in v:
                errs.append(f"{path}: missing required '{k}'")
        for k, sub in schema.get("properties", {}).items():
            if k in v:
                _validate(v[k], sub, f"{path}.{k}", errs)
    if isinstance(v, list) and "items" in schema:
        for i, item in enumerate(v):
            _validate(item, schema["items"], f"{path}[{i}]", errs)
    return errs


def check_receipt(obj: dict) -> list[str]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return _validate(obj, schema)


def _cmd_make(a):
    r = make_receipt(a.engine or ENGINE,
                     verdict=a.verdict, execution_status=a.status,
                     findings=[{"id": "demo", "severity": "info", "message": "synthetic receipt"}])
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0


def _cmd_check(a):
    try:
        obj = json.loads(Path(a.file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"USAGE_ERROR: {e}", file=sys.stderr)
        return 4
    errs = check_receipt(obj)
    if errs:
        for e in errs:
            print("FAIL " + e, file=sys.stderr)
        return 12
    print(f"PASS {a.file} ({obj.get('engine')} / {obj.get('verdict')})")
    return 0


def selftest() -> int:
    ok = make_receipt("selftest", verdict="PASS")
    assert not check_receipt(ok), "valid receipt must validate"
    bad = make_receipt("selftest", verdict="PASS"); bad["verdict"] = "MAYBE"
    assert check_receipt(bad), "bad enum must be rejected"
    try:
        make_receipt("selftest", verdict=None)  # SUCCESS without verdict must raise
        raise AssertionError("SUCCESS without verdict did not raise")
    except ValueError:
        pass
    errs = check_receipt({"schema": "audit-receipt-v1"})
    assert errs, "missing required fields must be rejected"
    print(json.dumps(make_receipt("receipt", verdict="PASS", outputs={"selftest": "passed"}), ensure_ascii=False))
    print("receipt selftest: 3/3 PASS")
    return 0


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("make"); s1.add_argument("--engine"); s1.add_argument("--verdict"); s1.add_argument("--status")
    s2 = sub.add_parser("check"); s2.add_argument("file")
    s3 = sub.add_parser("selftest")
    a = ap.parse_args()
    sys.exit({"make": _cmd_make, "check": _cmd_check, "selftest": lambda _: selftest()}[a.cmd](a))
