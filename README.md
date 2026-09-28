# audit-suite

**13 tools that turn audit replies into reusable technical assets.**
Every tool: zero dependencies, machine-readable receipt (`audit-receipt-v1`),
deterministic exit codes (`execution-status-axis v1.0`), self-test built in.

> Status: **local-only v0.1.0**. Self-verified via the unified runtime.
> External release (PyPI / GitHub public / RFC) awaits explicit approval.

## The idea

An audit reply is advisory work: one-shot, lives in someone else's repo,
sinks in the comment thread. A tool is an asset: re-runnable, owned,
composable into other people's CI. This suite productizes every audit
pattern used in real audits (superpowers #2332, cognicore-env PR#135,
ZCode egress forensics) so the *next* audit runs the tool instead of
re-deriving the checklist by hand.

## Tools

| ID | Tool | What it does | Born from |
|----|------|--------------|-----------|
| T01 | `adas_linter` | Checks an agent-run evidence manifest against ADAS v0.9's six clauses | ADAS draft + #2332 audit |
| T02 | `receipt` + `schemas/` | The audit receipt envelope every tool emits; zero-dep JSON-Schema validator | ARA output contract |
| T03 | `pkg_linter` | Cross-checks pyproject extras × README × `[all]` completeness | cognicore PR#135 audit |
| T04 | `coverage_honesty` | Catches "sampling masquerading as full enumeration" | ADAS R6 + ARA gates |
| T05 | `trap_gen` | Falsifiable traps that separate weak success heuristics from real gates | EXP-001 controlled experiment |
| T06 | `exit_table` + `standards/` | Two orthogonal axes: execution status ≠ verdict; executable spec table | ARA protocol × #2332 gap |
| T07 | `drift_check` | Detects "the audit target moved" before a report goes stale | #2332: upstream rewrote the code 1 day after filing |
| T08 | `oob_run` | Wraps any command; **failed runs also leave a durable artifact**, outside the workspace | the #2332 patch itself |
| T09 | `trust_analyzer` | Detects self-referential signature verification (sign and verify sharing an embedded key) | PR#135: "where does the verify key come from?" |
| T10 | `canon_vectors` | Canonicalization conformance vectors pinning float serialization semantics | PR#135 canonical-JSON advisory |
| T11 | `egress_classify` | Grades log endpoints: upload-risk / telemetry / read-download, direction-aware | ZCode egress forensics |
| T12 | `opp_scorer` | Scores open issues by *your capability*, not their importance | triage-picker × caveman 130-item triage |
| T13 | `suite` | Unified runtime: run any tool, collect receipts, aggregate report | the glue layer |

## Self-use (the acceptance bar)

```bash
python -m audit_suite.suite run <tool>     # run one tool, store receipt
python -m audit_suite.suite report         # aggregate all receipts
python -m audit_suite.<tool> selftest      # per-tool self-test
```

Real self-use runs (2026-09-28):

- `pkg_linter` reproduced the two real cognicore packaging findings on the
  live repo — plus one the manual audit missed (`[all]` missing `crewai`).
- `trust_analyzer` returned PASS (non-self-referential) on the exact file
  the manual PR#135 audit cleared — tool agrees with human verdict.
- `drift_check` on this suite's sibling repo: pinned to the first commit →
  FAIL with 4 drifted files; pinned to HEAD → PASS.
- `trap_gen`: 10/10 judge expectations matched (naive line-reader deceived
  exactly where designed; exit-code gate blocked exactly where designed).
- `egress_classify` on live logs: matches the manual forensic conclusions
  (object-storage endpoint = read-only download; loopback skipped).

## Design invariants

1. **Zero dependencies.** Python 3.11+ standard library only.
2. **No artifact, no verdict.** A run without a receipt is never a judgment.
3. **Three-state honesty.** PASS / FAIL / NOT_RUN are all legal and reportable.
4. **Advisory, not adjudication.** Findings locate evidence (`file:line`,
   reproducible flag) so a human verifies in seconds; maintainers decide.
5. **Local-only until approved.** Every external step is a separate,
   explicitly authorized action.

## Layout

```
audit-suite/
├── audit_suite/          # 13 tools (one module each) + suite.py runtime
├── schemas/              # audit-receipt-v1.schema.json, canon-vectors-v1.json
├── standards/            # execution-status-axis-v1.0.md
├── receipts/             # stored receipts from suite runs (machine-readable history)
└── pyproject.toml
```
