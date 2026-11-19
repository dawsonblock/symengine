# v2.1 local verification report

Date: 2026-10-21

- Pre-packaging Python 3 unittest suite: 251 tests passed (33–35 seconds in this environment).
- Includes 18 new `test_v210.py` tests for trace reconstruction, per-step consistency, strict types, forward-reference and schema rejection, forbidding candidate injection/validation trace leakage, failed-trace corrections, no-default promotion, ambiguity rejection, CLI end-to-end promotion, and skill prediction.
- Synthetic CLI smoke: `trace-study examples/trace_study.json` returned `locally_validated`, 3/3 validation examples, with `promotion.status=active` for a two-step, two-input arithmetic trace.
- No GPU finetuning, real model traffic, independent held-out task-family experiments, or external security audit was performed.
- Source bundle is deterministic and hash-bound through `SOURCE_SHA256.json`, which provides bit-level archival integrity checking, **not** publisher authentication.
