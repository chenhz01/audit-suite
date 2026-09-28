#!/usr/bin/env python3
"""audit_suite.canon_vectors — T10 Canonicalization Conformance Vectors.

Turns the canonical-JSON advisory (cognicore PR#135: cross-language float
serialization breaks signature interoperability) into an executable spec:
a vector file of (input -> canonical bytes -> sha256). Any implementation —
any language — that claims to interoperate MUST reproduce every vector.

Semantics pinned by this vector set (deliberately minimal, not RFC 8785):
  - keys sorted by Unicode code point
  - compact separators (",", ":")
  - strings: JSON escaping, non-ASCII kept literal (UTF-8)
  - integers: exact
  - floats: Python repr(float) — THE boundary case this set exists to pin

Usage:
    python -m audit_suite.canon_vectors generate [--out vectors.json]
    python -m audit_suite.canon_vectors verify [vectors.json]
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path

from .receipt import make_receipt

DEFAULT_OUT = Path(__file__).resolve().parent.parent / "schemas" / "canon-vectors-v1.json"

# Inputs chosen so that every serialization edge that could bite a
# cross-language implementation appears at least once.
SAMPLE_INPUTS = [
    {"name": "float-0.1", "obj": {"amount": 0.1}},
    {"name": "float-neg-zero", "obj": {"x": -0.0}},
    {"name": "float-1e20", "obj": {"big": 1e20}},
    {"name": "float-tiny", "obj": {"tiny": 1e-7}},
    {"name": "float-precision", "obj": {"p": 0.30000000000000004}},
    {"name": "int-exact", "obj": {"n": 2 ** 53, "m": -42}},
    {"name": "key-order", "obj": {"zebra": 1, "alpha": 2, "Unicode键": 3}},
    {"name": "unicode-literal", "obj": {"msg": "记忆→memory ✓"}},
    {"name": "nested", "obj": {"b": [{"z": 1.5, "a": None}], "a": True}},
    {"name": "empty", "obj": {}},
]


def canonicalize(obj) -> bytes:
    """The reference canonicalizer. Floats go through repr(float)."""

    def enc(v) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if v is None:
            return "null"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            if math.isnan(v) or math.isinf(v):
                raise ValueError(f"non-finite float not canonicalizable: {v!r}")
            return repr(v)
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False)
        if isinstance(v, list):
            return "[" + ",".join(enc(x) for x in v) + "]"
        if isinstance(v, dict):
            items = sorted(v.items(), key=lambda kv: kv[0])
            return "{" + ",".join(f"{json.dumps(k, ensure_ascii=False)}:{enc(x)}" for k, x in items) + "}"
        raise TypeError(f"unsupported type: {type(v).__name__}")

    return enc(obj).encode("utf-8")


def generate(out: Path = DEFAULT_OUT) -> dict:
    vectors = []
    for s in SAMPLE_INPUTS:
        canon = canonicalize(s["obj"])
        vectors.append({"name": s["name"], "input": s["obj"],
                        "canonical_utf8": canon.decode("utf-8"),
                        "sha256": hashlib.sha256(canon).hexdigest()})
    out.write_text(json.dumps({"spec": "audit-suite-canon-v1", "vectors": vectors},
                              indent=2, ensure_ascii=False), encoding="utf-8")
    return make_receipt("canon-vectors", verdict="PASS",
                        inputs={"samples": len(SAMPLE_INPUTS)}, outputs={"file": str(out), "vectors": len(vectors)})


def verify(path: Path = DEFAULT_OUT) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for v in data["vectors"]:
        canon = canonicalize(v["input"])
        got = hashlib.sha256(canon).hexdigest()
        if canon.decode("utf-8") != v["canonical_utf8"] or got != v["sha256"]:
            findings.append({"id": f"vector-{v['name']}", "severity": "critical",
                             "message": "reproduction mismatch — implementation is NOT conformant",
                             "reproducible": True})
    return make_receipt("canon-vectors", verdict="PASS" if not findings else "FAIL",
                        inputs={"file": str(path)}, outputs={"vectors": len(data["vectors"])},
                        findings=findings)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    arg = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUT
    r = generate(arg) if cmd == "generate" else verify(arg)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["verdict"] == "PASS" else 12)
