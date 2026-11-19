# v1.2.0 upgrade: defensible promotion and audit checkpoints

## Baseline retained

The v1.1 source and zero-dependency Python runtime are preserved. Its CLI, REST
API, AST interpreter, active-learning query, optional Z3, SQLite database schema,
feedback suspension, retirement, benchmarking, and LLM read-only tool bridge remain
available. v1.1 databases with consistent projected audit events remain readable.

## Changes

1. **Promotion boundary:** The registry no longer accepts a user-provided
   `locally_validated` dictionary by itself. Callers must provide the raw train and
   validation examples and induction search parameters; the registry reproduces
   the entire result, including digests, candidate fit, ambiguity decision, and
   pass counts. `Service.study` supplies these inputs automatically. This costs
   extra CPU on every promoted study, intentionally.
2. **Audit anchoring:** `sis anchor-export checkpoint.json` creates a new
   filesystem checkpoint with a deterministic audit prefix and an optional HMAC.
   `sis anchor-verify checkpoint.json` compares the authenticated checkpoint
   against the current verified SQLite audit, accepting legitimate suffixes but
   rejecting missing/rewritten prefixes. Preserve the trusted checkpoint outside
   the database trust domain. An unchecked file alongside a compromised DB
   is not independent evidence.
3. **Batch prediction:** `Service.predict_batch`, `sis predict-batch`,
   and `POST /v1/predict-batch` support up to 64 records and individual abstentions.
4. **Redirect hardening:** The built-in OpenAI-compatible HTTP client rejects
   redirects rather than risk forwarding examples, model requests or API tokens.
5. **Tests:** Includes new regression tests for forged promotion receipts,
   mismatched labels, HMAC tampering, DB history rollback, batch limits, and
   valid audit suffixes.

## Compatibility and migration

- No SQLite schema migration is required for sound v1.1 databases.
- **Breaking change for direct `Registry.promote` Python callers:** supply
  `train=`, `validation=`, `max_candidates=`, `proposals=`, and `use_z3=`
  consistent with the original induction. Prefer `Service.study` as the stable API.
- No native Gemini/Claude client exists. Integrate via application callbacks
  or an OpenAI-compatible adapter; tool definitions are an interface, not
  proof of provider-specific integration.
- A checkpoint reflects the verified local state, NOT independent holdout
  evidence, external verification, or cryptographic signing by a third party.
- Checkpoints are manual and fail closed on rollback. An old checkpoint remains
  valid after legitimate new events, and `new_events_after_anchor` reports count.
- External audits, authenticated ground-truth labels, arbitrary-program synthesis,
  runtime sandboxing, and neural weight updates remain out of scope.

## Commands

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
sis --db knowledge.sqlite3 train examples/arithmetic_study.json
sis --db knowledge.sqlite3 predict-batch examples/predict_batch.json
sis --db knowledge.sqlite3 anchor-export checkpoint-001.json
sis --db knowledge.sqlite3 anchor-verify checkpoint-001.json
python3 tools/evaluate_fixtures.py
python3 tools/smoke_integration.py
python3 tools/build_release.py
python3 tools/verify_release.py ../symbolic-induction-engine-v1.2.0.zip
```
