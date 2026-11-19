# v1.8 release qualification record

This document is a **local testing record**; it is not independently reproduced evidence.

Validation sequence used by the release maintainer:

1. Extract unmodified v1.7.0 archive and reproduce baseline regressions.
2. Implement frozen procedural skill snapshot / closure validation, private HMAC holdout scoring, replay, one-use enforcement, and conditional pseudo-label export.
3. Execute `PYTHONPATH=src python -m unittest discover -s tests -q` and synthetic end-to-end CLI exercise.
4. Rebuild a deterministic SHA-256-manifest ZIP, verify every recorded source digest, extract into a clean directory, and rerun tests.

Do not claim production certification, independent evaluator custody, improvements in LLM benchmark performance, or successful neural fine-tuning based on this record. See `docs/V1_8_PROCEDURAL_HOLDOUT_AND_DISTILLATION.md`.
