# SIS v1.5.0 — local release verification report

**Date:** 2026-10-20. **Status:** Local research build; no independent model benchmark or security certification.

## Checked baseline and upgrades

- v1.4.0 release ZIP extracted; source preserved as the upgrade baseline.
- 138 Python `unittest` checks pass on the working tree (108 previous tests plus 30 new tests).
- New regression coverage: typed field mappings, list type ordering, partial mapping and alias rejection, active/retired rule boundaries, hash-audit tampering refusal, read-only behavior, bounded batch requests, fixed pre-score policy, minimum sample sizes, false/tampered receipts, signature replay, legacy-vault behavior, Wilson calculations, CLI end-to-end qualification.
- Loopback HTTP smoke test passes for authenticated predictions, schema-transfer endpoint, operator-only mutations, and external audit anchor verification.
- Manifest / clean extraction checks are performed by `tools/build_release.py` and `tools/verify_release.py` with commands below.

## Explicit non-claims

- Cross-schema transfer does **not** demonstrate cross-domain accuracy. It is an operator-chosen structural rename of a validated symbolic expression.
- Passing a sealed qualification threshold on local synthetic arithmetic data does **not** establish independent test custody, intellectual transfer to new domains, or a better LLM.
- HMAC is shared-secret authentication, not independently verifiable public signatures. Current vault storage and audit anchor custody are operator-dependent.
- Testing did not include penetration testing, external reproducibility, or statistically matched language-model comparisons.

## Reproduction

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 tools/smoke_integration.py
python3 tools/build_release.py
python3 tools/verify_release.py ../symbolic-induction-engine-v1.5.0.zip
```

For evaluator qualification examples see `docs/V1_5_TRANSFER_AND_QUALIFICATION.md`.
