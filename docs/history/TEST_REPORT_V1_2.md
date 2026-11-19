# v1.2.0 local verification report

**Date:** 2026-10-20. These results were produced in a local container. They
are not independent third-party verification, not a real-world benchmark, and
not measured improvement to an LLM.

## Automated tests

Run command:

```bash
python3 -m unittest discover -s tests -v
```

Result: **72 passed**. Includes existing v1.0/v1.1 regression suites and new
v1.2 cases (direct forged-result rejection, recomputation with correct and
altered labels/search budgets, batch size/schema checks, audit prefix anchors,
HMAC validation, rollback to a consistent empty database, and redirect refusal).

## Controlled synthetic fixture evaluations

Command: `python3 tools/evaluate_fixtures.py`

- Arithmetic: locally_validated, 3/3 supplied validation matches, promoted.
- Sequence first item: locally_validated, 2/2 supplied validation matches, promoted.
- Ambiguity: ambiguous, promotion refused.

These are hand-authored examples, not blinded test-set performance.

## Integration smoke

Command: `python3 tools/smoke_integration.py`

- CLI study returned active rule promotion.
- CLI batch predictions returned 3/3 local expected arithmetic values.
- Offline audit checkpoint export and verification succeeded.
- Local loopback HTTP batch prediction returned 3 predictions.
- HTTP route without the configured API key returned **401**.

An offline installation succeeded with `python3 -m pip install --no-build-isolation -e .`
using preinstalled setuptools. The isolated install path attempted to contact the
package index and could not reach it in this environment; do not claim that
isolated installation was tested.

## Not established

No independent evidence of general intelligence, formal task correctness,
third-party audited cryptographic trust, ground-truth label provenance,
remote TLS/auth deployment hardening, or relative performance vs baseline LLMs.
The HMAC checkpoint only adds meaningful rollback detection when the key and
checkpoint are managed in a separate trust domain from the database writer.
