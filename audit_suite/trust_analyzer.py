#!/usr/bin/env python3
"""audit_suite.trust_analyzer — T09 Trust-Model Static Analyzer.

Detects *self-referential verification*: a module that verifies signatures
using a trust root embedded in the same code that produces signatures.
Born from the cognicore-env PR#135 audit, where the decisive manual check
was "where does the verification public key come from?" — this tool asks
that question automatically for every file.

Heuristic (AST-level, deliberately conservative — advisory, not a verdict):
  EXTERNAL        verify-key comes from caller-supplied parameters  → healthy
  EMBEDDED_SHARED sign and verify share a module-level key constant  → critical
  EMBEDDED_LOCAL  verify uses a module-level key but no signer       → warning

Usage:
    python -m audit_suite.trust_analyzer check <file.py> [file2.py ...]
    python -m audit_suite.trust_analyzer selftest
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

from .receipt import make_receipt

KEY_HINTS = ("key", "secret", "publi", "cert", "token")
VERIFY_HINTS = ("verify", "check_sig", "validate_sig")


def _is_key_name(name: str) -> bool:
    return any(h in name.lower() for h in KEY_HINTS)


def analyze_source(src: str) -> list[dict]:
    findings: list[dict] = []
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return findings
    module_consts: dict[str, tuple[int, int]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and _is_key_name(t.id) and \
                   isinstance(node.value, (ast.Constant, ast.JoinedStr)):
                    module_consts[t.id] = (node.lineno, node.end_lineno or node.lineno)

    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    verifiers = {n: f for n, f in funcs.items() if any(h in n.lower() for h in VERIFY_HINTS)}
    signers = {n: f for n, f in funcs.items() if "sign" in n.lower()}
    # module-level key constants actually *used by signer bodies*
    signer_consts: set[str] = set()
    for sf in signers.values():
        for node in ast.walk(sf):
            if isinstance(node, ast.Name) and node.id in module_consts and isinstance(node.ctx, ast.Load):
                signer_consts.add(node.id)

    for vname, fn in verifiers.items():
        used: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Name) and node.id in module_consts and isinstance(node.ctx, ast.Load):
                used.add(node.id)
        # default-parameter embedded keys
        defaults = [d for d in (fn.args.defaults + [d for d in fn.args.kw_defaults if d]) if d is not None]
        for d in defaults:
            if isinstance(d, ast.Name) and d.id in module_consts:
                used.add(d.id)
        if not used:
            findings.append({"id": f"trust-{vname}", "severity": "info",
                             "message": f"verify function '{vname}' takes keys from callers (EXTERNAL) — healthy pattern"})
            continue
        shared = used & signer_consts
        severity = "critical" if shared else "warning"
        sev_id = "SELF_REFERENTIAL" if severity == "critical" else "EMBEDDED_LOCAL"
        findings.append({"id": f"trust-{vname}", "severity": severity,
                         "message": f"{sev_id}: '{vname}' uses module-level key(s) {sorted(used)} "
                                    f"(lines {module_consts[list(used)[0]][0]})"
                                    + (" also used by signer(s) " + str(sorted(signers)) if shared and signers else ""),
                         "location": f"module-level key at line {module_consts[list(used)[0]][0]}",
                         "reproducible": True})
    return findings


def check(paths: list[Path]) -> dict:
    findings: list[dict] = []
    for p in paths:
        try:
            src = p.read_text(encoding="utf-8")
        except OSError as e:
            findings.append({"id": "read", "severity": "critical", "message": f"{p}: {e}"})
            continue
        for f in analyze_source(src):
            f["location"] = f"{p}:{f.get('location', '')}"
            findings.append(f)
    critical = [f for f in findings if f["severity"] == "critical"]
    verdict = "FAIL" if critical else ("PASS-WITH-CAVEAT" if any(f["severity"] == "warning" for f in findings) else "PASS")
    return make_receipt("trust-analyzer", verdict=verdict,
                        inputs={"files": [str(p) for p in paths]}, findings=findings,
                        caveats=["heuristic; advisory only — maintainer's call, always"])


SELF_REF = '''
SIGNING_KEY = "pk_test_0123456789abcdef"
def sign(payload): return SIGNING_KEY + payload
def verify(payload, sig): return sig.startswith(SIGNING_KEY)
'''
EXTERNAL = '''
def sign(payload, key): return key + payload
def verify(payload, sig, trusted_keys): return any(sig.startswith(k) for k in trusted_keys)
'''


def selftest() -> int:
    f_self = analyze_source(SELF_REF)
    assert any(f["severity"] == "critical" for f in f_self), f"self-ref must be critical: {f_self}"
    f_ext = analyze_source(EXTERNAL)
    assert any(f["severity"] == "info" for f in f_ext), f"external must be info: {f_ext}"
    print(json.dumps(make_receipt("trust-analyzer", verdict="PASS", outputs={"selftest": "passed"}), ensure_ascii=False))
    print("trust_analyzer selftest: 2/2 PASS (self-referential flagged, caller-keyed clean)")
    return 0


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("check"); s1.add_argument("files", nargs="+")
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "selftest":
        sys.exit(selftest())
    r = check([Path(f) for f in a.files])
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["verdict"] == "PASS" else (11 if r["verdict"] == "PASS-WITH-CAVEAT" else 12))
