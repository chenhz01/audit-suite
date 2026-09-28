#!/usr/bin/env python3
"""audit_suite.oob_run — T08 Out-of-Band QA Recorder.

Wraps ANY command and records an acceptance-evidence artifact OUTSIDE the
workspace being audited — so a failed run also leaves a trace. This is the
pluggable patch for the gap identified in obra/superpowers #2332: "a failing
run records nothing" + "delete this plan's workspace" means acceptance
evidence never survives the workflow. No changes to the host tool required.

Usage:
    python -m audit_suite.oob_run --out <dir> -- <command...>
    python -m audit_suite.oob_run selftest

Receipt conforms to audit-receipt-v1; exit codes follow execution-status-axis v1.0.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .receipt import make_receipt, now, sha256_file, VERSION

DEFAULT_OUT = Path.home() / ".audit-suite" / "qa-artifacts"


def record(cmd: list[str], out_dir: Path, timeout: float = 600.0) -> dict:
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        exit_code, stdout, stderr = proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]
    except FileNotFoundError as e:
        return make_receipt("oob-run", execution_status="USAGE_ERROR",
                            inputs={"cmd": cmd},
                            findings=[{"id": "cmd-not-found", "severity": "critical", "message": str(e)}])
    except subprocess.TimeoutExpired:
        return make_receipt("oob-run", execution_status="EXPLICIT_FAILURE",
                            inputs={"cmd": cmd},
                            findings=[{"id": "timeout", "severity": "major",
                                       "message": f"timed out after {timeout}s"}])
    duration_ms = int((time.monotonic() - t0) * 1000)

    # The whole point: a FAILED run still gets a durable artifact.
    execution_status = "SUCCESS" if exit_code == 0 else "EXPLICIT_FAILURE"
    receipt = make_receipt(
        "oob-run",
        verdict="PASS" if exit_code == 0 else None,  # business verdict = wrapped command outcome
        execution_status=execution_status,
        inputs={"cmd": cmd, "cwd": str(Path.cwd())},
        outputs={"exit_code": exit_code, "stdout_tail": stdout, "stderr_tail": stderr},
        trace_id=str(uuid.uuid4()),
        findings=[] if exit_code == 0 else
        [{"id": "nonzero-exit", "severity": "major",
          "message": f"command exited {exit_code} — recorded out-of-band so the failure survives cleanup"}],
    )
    receipt["duration_ms"] = duration_ms

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    art = out_dir / f"qa-{stamp}-{receipt['trace_id'][:8]}.json"
    art.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    receipt["artifacts"] = [{"path": str(art), "sha256": sha256_file(art)}]
    art.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(receipt, indent=2, ensure_ascii=False))
    print(f"[oob-run] evidence persisted: {art}", file=sys.stderr)
    # T08's own exit reflects the wrapped command, mapped through the axis table
    from .exit_table import exit_for
    return_code = 0 if exit_code == 0 else 2
    return receipt | {"_rc": return_code}


def selftest() -> int:
    tmp = Path.home() / ".audit-suite" / "selftest-tmp"
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    # failing command MUST leave a durable artifact (the #2332 patch)
    r1 = record([sys.executable, "-c", "print('All tests passed (9/9)'); raise SystemExit(1)"], tmp)
    arts = list(tmp.glob("qa-*.json"))
    assert r1["execution_status"] == "EXPLICIT_FAILURE", "must be EXPLICIT_FAILURE"
    assert arts, "failed run must persist an artifact — that IS the patch"
    saved = json.loads(arts[-1].read_text(encoding="utf-8"))
    assert saved["outputs"]["exit_code"] == 1, "exit code must be recorded"
    assert "All tests passed" in saved["outputs"]["stdout_tail"], "deceiving output preserved as evidence"
    # passing command
    r2 = record([sys.executable, "-c", "print('ok')"], tmp)
    assert r2["execution_status"] == "SUCCESS"
    shutil.rmtree(tmp, ignore_errors=True)
    print("oob_run selftest: 2/2 PASS (failure leaves a trace — #2332 gap closed)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    args = sys.argv[1:]
    out_dir = DEFAULT_OUT
    if "--out" in args:
        i = args.index("--out")
        out_dir = Path(args[i + 1])
        args = args[:i] + args[i + 2:]
    if "--" not in args:
        print("USAGE_ERROR: need '-- <command>'", file=sys.stderr)
        sys.exit(4)
    r = record(args[args.index("--") + 1:], out_dir)
    sys.exit(r["_rc"])
