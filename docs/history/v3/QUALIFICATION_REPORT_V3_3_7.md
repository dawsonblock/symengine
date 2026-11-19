# SIS v3.3.7 Qualification Report

Status: `ENGINEERING_VERIFIED` / `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
This release connects a verified real-agent episode to a qualified
procedure that a sibling task can actually retrieve. It does not
establish that SIS improves a real coding agent, and it does not qualify
a production sandbox.

## What changed

| Item | Scope | Evidence |
| --- | --- | --- |
| V337-01 | Learned procedures are keyed to a **failure class**, not the dev task's own signature. `experience_to_record` converts one verified pass into a candidate and refuses to relabel a record whose `failure_category` differs. | `src/sis/v3/learning/records.py`, `tests/v3/test_learning_loop.py` |
| V337-02 | The failure class is **registered with the evaluator's task**, bound into the task commitment, persisted, and signed into outcome receipts as an optional field. Receipts omit the field when absent, so historical receipts keep their exact digests and signatures. | `src/sis/v3/verifier.py`, `src/sis/v3/contracts.py`, `tests/v3/test_receipt_signatures.py` |
| V337-03 | Scope grants **default to strict evidence**: every transfer witness must carry the procedure's failure class or be cited by the qualified revision. Mismatched classes fail with `evidence_class_mismatch`; uncited legacy witnesses with `evidence_not_cited_by_procedure`. | `src/sis/v3/scope_grants.py`, `tests/v3/test_scope_grants.py` |
| V337-04 | `tools/learn_recommend_cycle.py` runs one complete cycle with a real Codex agent: two verified same-class dev tasks → candidate → signed qualification → scoped `recommend` on a sibling holdout → cross-class abstain control. | `evidence/qualification/LEARN_CYCLE.md`, `evidence/qualification/learn_cycle_live.json` |

## Why V337-01 matters

Before this release, every real campaign seeded a procedure with
`failure_signatures=("sig-money",)` while holdout requests carried
`money2`/`slug2`. Exact-signature matching meant the qualified arm never
fired: in the deterministic campaign it solved 0/2, and in the shipped
live campaign both holdout tasks abstained. The wins came from
unqualified candidate composition, not from a qualified skill.

## First complete cycle

Live run (`codex exec`, Codex CLI 0.156.1, model `gpt-6-astra`):

- dev `task-money` and `task-money2`: both pass, both receipts carry
  `convention_unknown:money`;
- procedure `exp-exp-money`: qualified, cites both receipts;
- holdout `task-money3`: `recommend`, procedure named;
- control `task-slug2`: `abstain`, `precondition_failed`;
- holdout without guidance: `fail`, `no_action: true`;
- holdout with guidance: `pass`, `no_action: false`.

The baseline declined to guess; the served run implemented
`ROUND_HALF_UP`. This is one paired observation, not an efficacy result.

## Test result

Environment: Python 3.12.0 on macOS arm64, pinned `pytest==8.4.2`,
`z3-solver==4.16.0`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`,
`PYTHONNOUSERSITE=1`, `PYTHONPATH=src`.

- **1330 passed, 14 skipped, 0 failed.**
- Skips: 8 PostgreSQL (`SIS_POSTGRES_DSN` not configured), 2 Windows ACL,
  1 missing `cryptography`, 1 cgroup v2, 1 pinned Git baseline, 1 missing
  vskill corpus.

## What remains unqualified

- **Efficacy is not established.** n = 1 per condition; a powered,
  repository-disjoint, preregistered study is still required.
- The lesson is supervised capture, not inference: the dev task's
  statement carries the convention.
- The failure class is declared by the fixture at task registration. The
  receipt binds the declaration; it does not infer or validate it.
- Strict grants bind class and citation, not causal relevance: the
  witnesses are agent outcomes on same-class tasks, not executions of the
  procedure itself.
- Isolation remains `unverified_local`; the production sandbox gate is
  unchanged.
- Provenance is unsigned unless an externally trusted release key is
  supplied; see `release/release_manifest.json`.
