#!/usr/bin/env python3
"""audit_suite.pkg_linter — T03 Packaging Consistency Linter.

Cross-checks four sources of truth for a Python package and flags any
"declared vs documented vs installable" mismatch:

  1. [project.optional-dependencies] extras        (pyproject.toml)
  2. extras mentioned in README install blocks     (README.md)
  3. the convenience `[all]` group                  (pyproject.toml)
  4. top-level package dirs vs extras module hints

Born from a real audit (cognicore-env PR#135, 2026-09-28): `[all]` shipped
without the `mem0` extra and the README's Optional Extras block omitted
`[mem0]` while a later section assumed it — both reproducible, both
machine-detectable.

Usage:
    python -m audit_suite.pkg_linter check --pyproject P [--readme R]
    python -m audit_suite.pkg_linter selftest
"""
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

from .receipt import make_receipt

INSTALL_RE = re.compile(r"(?:pip|uv) install[^\n`]*?\[([a-zA-Z0-9_,\-]+)\]", re.I)
EXTRA_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")
# Convention: [all] is the full *runtime* feature set; developer tooling
# groups are excluded from the all-completeness check to avoid false positives.
STANDARD_DEV_GROUPS = {"dev", "test", "tests", "docs", "lint", "ci", "build", "benchmark"}


def lint(project: dict, readme_text: str | None) -> tuple[str, list[dict]]:
    findings: list[dict] = []
    extras: dict[str, list[str]] = (project.get("project", {}).get("optional-dependencies")) or {}

    for name in extras:
        if not EXTRA_NAME_RE.match(name):
            findings.append({"id": "pkg-name", "severity": "major",
                             "message": f"extra name {name!r} is not a valid extra identifier",
                             "location": "pyproject.toml"})

    if extras and "all" in extras:
        others = {e for e in extras if e != "all" and e not in STANDARD_DEV_GROUPS}
        missing = {dep for e in others for dep in extras[e]} - set(extras["all"])
        # group-level check (dep strings may carry version specifiers)
        missing_names = set()
        norm = lambda d: re.split(r"[<>=!;\[]", d.strip(), 1)[0].strip().lower()
        all_norm = {norm(d) for d in extras["all"]}
        for e in others:
            for dep in extras[e]:
                if norm(dep) not in all_norm:
                    missing_names.add(f"{e}:{norm(dep)}")
        missing = missing_names
        if missing:
            findings.append({"id": "pkg-all-incomplete", "severity": "major",
                             "message": f"'[all]' (advertised as 'everything') is missing: {sorted(missing)} — "
                                        f"pip install <pkg>[all] will not install the full feature set",
                             "location": "project.optional-dependencies.all", "reproducible": True})

    if readme_text:
        claimed: set[str] = set()
        for m in INSTALL_RE.finditer(readme_text):
            claimed.update(x.strip() for x in m.group(1).split(",") if x.strip())
        for name in claimed:
            if extras and name not in extras:
                findings.append({"id": "pkg-readme-ghost", "severity": "major",
                                 "message": f"README tells users to install extra '[{name}]' "
                                            f"but pyproject.toml does not define it — ImportError on arrival",
                                 "location": "README.md", "reproducible": True})
        if extras:
            undocumented = {e for e in extras if e not in claimed and e not in ("all", "dev")} - claimed
            # only flag when README has an install section at all
            if INSTALL_RE.search(readme_text) and undocumented:
                findings.append({"id": "pkg-readme-missing", "severity": "minor",
                                 "message": f"extras defined but absent from README install blocks: {sorted(undocumented)}",
                                 "location": "README.md"})

    major = [f for f in findings if f["severity"] == "major"]
    if major:
        verdict = "FAIL" if len(major) >= 2 else "PASS-WITH-CAVEAT"
    elif findings:
        verdict = "PASS-WITH-CAVEAT"
    else:
        verdict = "PASS"
    return verdict, findings


def run(pyproject: Path, readme: Path | None) -> dict:
    try:
        project = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        return make_receipt("pkg-linter", execution_status="USAGE_ERROR",
                            inputs={"pyproject": str(pyproject)},
                            findings=[{"id": "input", "severity": "critical", "message": str(e)}])
    readme_text = None
    if readme and readme.is_file():
        readme_text = readme.read_text(encoding="utf-8", errors="ignore")
    verdict, findings = lint(project, readme_text)
    return make_receipt("pkg-linter", verdict=verdict,
                        inputs={"pyproject": str(pyproject), "readme": str(readme) if readme else None},
                        findings=findings)


def selftest() -> int:
    # replicate the two real cognicore findings
    bad_project = {"project": {"optional-dependencies": {
        "mem0": ["cryptography>=43.0", "mem0ai>=2.0"],
        "all": ["cryptography>=43.0"]}}}
    bad_readme = "Install everything: pip install pkg\nOr: pip install pkg[all]\nAlso try pip install pkg[ghost]"
    v, f = lint(bad_project, bad_readme)
    ids = {x["id"] for x in f}
    assert v == "FAIL" and "pkg-all-incomplete" in ids and "pkg-readme-ghost" in ids, f"{v} {ids}"
    clean = {"project": {"optional-dependencies": {"mem0": ["cryptography"], "all": ["cryptography", "mem0ai"]}}}
    clean_readme = "pip install pkg[mem0]\npip install pkg[all]"
    v2, f2 = lint(clean, clean_readme)
    assert v2 == "PASS" and not f2, f"{v2} {f2}"
    print(json.dumps(make_receipt("pkg-linter", verdict="PASS", outputs={"selftest": "passed"}), ensure_ascii=False))
    print("pkg_linter selftest: 2/2 PASS")
    return 0


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("check")
    s1.add_argument("--pyproject", required=True)
    s1.add_argument("--readme")
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "selftest":
        sys.exit(selftest())
    r = run(Path(a.pyproject), Path(a.readme) if a.readme else None)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    sys.exit(0 if r["verdict"] == "PASS" else (11 if r["verdict"] == "PASS-WITH-CAVEAT" else 12))
