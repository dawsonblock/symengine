# SIS v1.9.0 local qualification notes

The source package was checked using Python 3.13 with `PYTHONPATH=src` and the standard-library unittest runner. All **213 automated tests passed** in the build workspace, including 196 inherited v1.0–v1.8 tests and 17 new v1.9 tests.

The new tests exercise HMAC and checksum verification, strict signed-export parsing, canonical format requirements, duplicate checks, CLI preflight without model loading, configuration bounds, prompt-token loss masking, tokenizer prefix mismatch rejection, input overlap/schema protection, strict model-output parsing, three-/four-arm mocked comparisons and failure invalidation. The local demo uses simulated model clients only.

Not verified: installation of optional PyTorch/Transformers/PEFT training extras in this runtime, actual `Trainer.train()` on a real model checkpoint, saved adapter evaluation, independent dataset custody, portability beyond the tested runtime, statistically meaningful performance gains, or hardening of external model-serving endpoints. The LoRA path exists and runs if optional dependencies, compatible model weights and hardware are provided; it should be integration-tested on an operator-owned setup before use.

Archive integrity: `tools/build_release.py` deterministically packages all source files with SHA-256 manifest. `tools/verify_release.py` verifies the archive. SHA-256 is tamper detection for a known authentic archive, not a cryptographic publisher signature.
