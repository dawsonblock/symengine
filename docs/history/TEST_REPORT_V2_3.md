# SIS v2.3.0 — Local qualification record

Date: 2026-10-21

## Reproduced results

- `PYTHONPATH=src python3 -m unittest discover -s tests -q`: **299 tests, passed** (exit 0).
- The 299 include existing v1.0–v2.2 regressions and 16 new v2.3 tests (15 unit and 1 local HTTP auth/integration).
- `PYTHONPATH=src python3 tools/demo_tabular_workflow.py --write-examples`: 4 training captures, 3 validation outputs correct, accepted and persisted, new-input prediction 26, catalog audit valid.
- CLI end-to-end exercise: `workflow-study`, `workflow-predict`, and `workflow-audit` with a fresh local database completed successfully.
- New security regression: ordinary API key cannot promote/retire; independently configured operator key can promote; read-only prediction works with ordinary key.

The tests emitted **ResourceWarning** messages for unclosed SQLite connections in legacy tests. No test assertions failed. Resource warnings should be addressed before claiming leak-free operation.

## Boundaries

- Local deterministic replay is NOT proof of external outcome correctness, authenticated tool execution, or task-family generalization.
- Hash-linked event and database logs have no independent custody; privileged actors could rewrite evidence and hashes.
- Some tests exercise mock models. No real-model neural improvement, GPU LoRA training, or third-party holdout evaluation was performed for this release.
- New workflow interpreter is strictly in-memory and pure: no arbitrary shell/filesystem/browser tool execution.

## Reproduction

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -q
python3 tools/demo_tabular_workflow.py
python3 tools/check_source_manifest.py
```
