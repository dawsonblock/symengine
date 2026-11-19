# Symbolic Induction Engine v1.4.0 — local verification

**Date:** 2026-10-20. **Environment:** container Linux, Python 3.13. **Claims are limited to local tests and fixtures.**

## Checks and outcomes

- 81 legacy v1.3 automated tests: PASS before modification.
- 108 full automated tests (legacy plus 27 v1.4 checks): PASS after modification.
- v1.4 test suite covers HMAC-bound public studies, tampering, hidden-test commitment mismatch, one-use scoring, concurrent attempts, private-score replay, task input duplication, split validation, no-private-test public output, and end-to-end evaluator CLI workflow.
- Existing independent-authenticated HTTP integration smoke: PASS (local only).
- Archive SHA-256 verifier and clean extracted-source smoke: see command output generated during packaging. The manifest authenticates distribution **integrity only**, not software supply-chain provenance or trusted code execution.

## Evidence limitations

These tests use a deterministic synthetic function (`y = x + 2`) and synthetic local holdout inputs. The tested shifted inputs are a different input *range* of the **same task family**. This does not demonstrate new task-family abstraction, formal correctness outside bounded grammar, independent benchmark improvement versus an LLM, or third-party evaluator control.

The evaluator vault provides a separated custody interface, but a user who controls the vault, signing secret and public task can still inspect data or roll the vault back. Any claim of independent qualification requires different humans/systems controlling protected fresh test data and external recordkeeping.

## Reproduce

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 tools/smoke_integration.py
python3 tools/generate_eval_demo.py /tmp/sis-eval-demo
export SIS_EVAL_HMAC_KEY='replace-with-at-least-32-random-bytes'
sis eval-seal /tmp/sis-eval-demo/dataset.json /tmp/sis-eval-demo/public.json --vault /tmp/sis-eval-demo/vault.sqlite3
sis eval-candidate /tmp/sis-eval-demo/public.json /tmp/sis-eval-demo/submission.json
sis eval-score /tmp/sis-eval-demo/public.json /tmp/sis-eval-demo/submission.json --vault /tmp/sis-eval-demo/vault.sqlite3 --receipt /tmp/sis-eval-demo/receipt.json
sis eval-verify /tmp/sis-eval-demo/public.json /tmp/sis-eval-demo/receipt.json --vault /tmp/sis-eval-demo/vault.sqlite3
python3 tools/build_release.py
python3 tools/verify_release.py ../symbolic-induction-engine-v1.4.0.zip
```
