# SIS v1.6.0 — local qualification / smoke report

Test environment: Python 3.13 in the current build environment; source supports Python >=3.10 but cross-version support is **not** independently tested here. No actual hosted or local LLM weights were loaded, and the synthetic demonstration does **not** indicate real-world gains.

Commands:

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
PYTHONPATH=src python tools/smoke_integration.py
PYTHONPATH=src python tools/demo_paired_offline.py
python tools/build_release.py
python tools/verify_release.py ../symbolic-induction-engine-v1.6.0.zip
```

Verified locally:

- 153 automated tests passed, including old v1.0–v1.5 regression suites.
- HTTP integration smoke passes with existing authorization and audit guardrail checks.
- The new CLI paired evaluation was exercised end-to-end against an **in-process fake HTTP completion server** (no real LLM; expected 4 calls for 2 cases).
- Two-step network opt-in, no-overwrite result behavior, data-shape validation, provider errors, and rule-registry drift were tested.
- Fake-model A/B illustration outputs are explicitly synthetic and not real gains.
- Archive manifest and clean extraction to be verified in final package build.

Not verified:

- Any real LLM accuracy improvement, hardware throughput, cloud-provider price, or production security compliance.
- Independence or secrecy of external holdouts, externally verified evaluator control, or model token-accounting accuracy.
- Model-provider APIs other than standard OpenAI-compatible chat completions.
- OS/Python-version compatibility beyond this test environment.
