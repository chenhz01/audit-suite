# Execution-Status Axis Specification v1.0

> **Origin**: extracted from the ARA audit-protocol (v1.1) exit-code table and
> generalized. Independent motivation: obra/superpowers issue #2332 — a lost
> agent session cannot distinguish "never ran" from "ran and failed", because
> the workflow defines no machine-checkable terminal state and deletes its
> workspace after a clean review. This spec closes that gap for any tool chain.

## 1. The problem

Most tools collapse two unrelated questions into one exit code:

1. **How did the run terminate?** (execution)
2. **What did the run conclude?** (judgment)

When collapsed, three distinct situations become indistinguishable:
"the check passed", "the check never ran", and "the check ran and found a
failure". Consumers (CI, humans, other agents) then silently misread
failures as successes or as outages.

## 2. The rule: two orthogonal axes

**Axis A — execution status** (how the run terminated):

| Status | Meaning |
|---|---|
| `SUCCESS` | Completed and emitted a valid receipt. The receipt may itself carry a business `FAIL`. |
| `EXPLICIT_FAILURE` | Terminated with a named reason; the reason is carried in the receipt. |
| `SILENT_TIMEOUT` | Ended without a receipt. Never reported as a verdict. |
| `USAGE_ERROR` | Malformed input; no judgment attempted. |
| `POLICY_DENIED` | A refusal could not be recorded; fail closed. |

**Axis B — verdict** (what the receipt says, only exists under `SUCCESS` /
`EXPLICIT_FAILURE`): `PASS` / `PASS-WITH-CAVEAT` / `FAIL` / `null`.

**Core invariant**: *no artifact, no verdict.* A run that produced no
receipt (`SILENT_TIMEOUT`, `USAGE_ERROR`, `POLICY_DENIED`) must never be
reported as a business judgment.

## 3. Deterministic exit codes (first match wins)

| Exit | Execution status | Verdict | Reading |
|---|---|---|---|
| 0  | SUCCESS          | PASS             | clean pass |
| 10 | SUCCESS          | PASS (degraded)  | pass, evidence partial |
| 11 | SUCCESS          | PASS-WITH-CAVEAT | pass with named caveats |
| 12 | SUCCESS          | FAIL            | business FAIL, receipt present |
| 13 | SUCCESS          | FAIL (degraded) | business FAIL + partial evidence |
| 2  | EXPLICIT_FAILURE | —               | named failure, reason carried |
| 3  | SILENT_TIMEOUT   | —               | no receipt → not a verdict |
| 4  | USAGE_ERROR      | —               | malformed input |
| 5  | POLICY_DENIED    | —               | refusal not recordable |

Three corollaries:

- A completed run with a receipt can still be a business `FAIL`. Exit 12
  exists so "the audit ran fine and found a failure" is never confused with
  "the audit failed to run" (exit 3).
- `degraded` never upgrades or downgrades a `FAIL`.
- Exit 2 is reserved for "named failure that still carries a receipt" — a
  rare path; the number is reserved rather than reassigned so the table
  cannot drift by accident.

## 4. Conformance requirements

A tool claims conformance to this spec when all of the following hold:

1. Every terminal path of the tool maps to exactly one row of §3.
2. The tool emits a machine-readable receipt (e.g. `audit-receipt-v1`) on
   every `SUCCESS` / `EXPLICIT_FAILURE` path, including business `FAIL`.
3. Failed runs **leave an artifact** — a lost session must be able to
   distinguish "never ran" from "ran and failed" *after the fact*.
4. `degraded: true` is set whenever the evidence behind the verdict was
   itself partial (e.g. unverified sources).

## 5. Non-goals

- Defining what a *business* FAIL means per tool (that is the tool's own
  contract, e.g. ADAS for agent acceptance evidence).
- Retention policy for artifacts (workplace-specific).

## Changelog

- v1.0 (2026-09-28): extracted from ARA audit-protocol v1.1; generalized;
  conformance requirements added.
