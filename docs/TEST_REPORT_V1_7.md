# SIS v1.7 — local verification report

Execution environment: local Linux, CPython 3.13, Python standard library only for
core runtime. The project declares Python 3.10+ but this invocation did **not**
independently exercise every supported Python version.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

**Result:** 174 tests passed (22.398 seconds). This includes all 153
pre-existing v1.6 regression tests and 21 new tests covering the interpreted
procedural AST, bounded fold, conditionals, unknown ops, overflow, ambiguity,
operator-controlled promotion, catalog audit/rollback projection tampering,
read-only model bridge, suspension/retirement, dependency invalidation,
experience correction requirements, benchmark nonpromotion, CLI and DB reopen.
A legacy tool-name expectation was updated to include the added read-only
`sis_skill_predict` function.

## HTTP smoke

A local server launched with independent API and admin keys. Confirmed health
status 200, blocked unauthorized promotion HTTP 403, accepted authorized
promotion HTTP 200, and verified the resulting skill audit chain. The server
was bound to loopback only.

## Packaging checks

ZIP builder writes a deterministic sorted file archive and SHA-256 manifest;
`tools/verify_release.py` checks every packaged source file against the manifest.
A clean extraction and regression rerun is required for final release.

## Scope limitations

These are **local development tests** using deterministic fixtures, not an
independent security audit, formal proof, independent evaluator-owned holdout,
or evidence of LLM performance improvements. Existing v1.4 sealed evaluation
is not yet wired to the procedural skill engine. Skill audit authenticity
against a full DB rewrite is not guaranteed without external anchoring.
