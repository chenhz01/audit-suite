#!/usr/bin/env python3
"""audit_suite.drift_check — T07 Audit Target Drift Detector.

An audit report pins its target (commit SHA + key paths). Before the report
is published or cited, this tool re-checks: if the target moved under the
audited paths, the report is DRIFTED and must be re-validated or re-dated.
Born from the superpowers #2332 audit: the upstream rewrote executing-plans
(429-line diff) one day after the issue was filed — the audit target moved
and only manual vigilance caught it.

Usage:
    python -m audit_suite.drift_check check --pin pin.json
    python -m audit_suite.drift_check pin --repo <local-git-repo> --paths p1,p2 [--sha <sha>]
Pin format: {"repo": "<path>", "sha": "<commit>", "paths": ["a/", "b.md"]}
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .receipt import make_receipt, sha256_file


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def check(pin_path: Path) -> dict:
    try:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return make_receipt("drift-check", execution_status="USAGE_ERROR",
                            inputs={"pin": str(pin_path)},
                            findings=[{"id": "pin", "severity": "critical", "message": str(e)}])
    repo, sha, paths = Path(pin["repo"]), pin["sha"], pin["paths"]
    if not (repo / ".git").exists():
        return make_receipt("drift-check", execution_status="USAGE_ERROR",
                            inputs=pin, findings=[{"id": "repo", "severity": "critical",
                                                   "message": f"not a git repo: {repo}"}])
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    findings: list[dict] = []
    if head == sha:
        drift_paths: list[str] = []
    else:
        changed = _git(repo, "diff", "--name-only", sha, "HEAD", "--", *paths)
        drift_paths = [l for l in changed.stdout.splitlines() if l.strip()]
    if head != sha:
        findings.append({"id": "drift-commit", "severity": "minor",
                         "message": f"HEAD moved since pin: {sha[:10]} → {head[:10]}"})
    if drift_paths:
        findings.append({"id": "drift-paths", "severity": "critical",
                         "message": f"audited paths changed since pin ({len(drift_paths)} files): "
                                    f"{drift_paths[:8]}{'…' if len(drift_paths) > 8 else ''}",
                         "location": "audited paths", "reproducible": True})
        verdict = "FAIL"
    elif findings:
        verdict = "PASS-WITH-CAVEAT"  # HEAD moved but audited paths untouched
    else:
        verdict = "PASS"
    return make_receipt("drift-check", verdict=verdict,
                        inputs={"pin": str(pin_path), "sha256": sha256_file(pin_path)},
                        outputs={"pinned_sha": sha, "head_sha": head, "drifted_files": drift_paths},
                        findings=findings)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("check"); s1.add_argument("--pin", required=True)
    s2 = sub.add_parser("pin")
    s2.add_argument("--repo", required=True)
    s2.add_argument("--paths", required=True)
    s2.add_argument("--sha")
    a = ap.parse_args()
    if a.cmd == "pin":
        repo = Path(a.repo)
        sha = a.sha or _git(repo, "rev-parse", "HEAD").stdout.strip()
        pin = {"repo": str(repo), "sha": sha, "paths": a.paths.split(",")}
        out = Path("audit-pin.json")
        out.write_text(json.dumps(pin, indent=2), encoding="utf-8")
        print(json.dumps(pin, indent=2), "\n-> written", out)
        sys.exit(0)
    r = check(Path(a.pin))
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["verdict"] == "PASS" else (11 if r["verdict"] == "PASS-WITH-CAVEAT" else 12))
