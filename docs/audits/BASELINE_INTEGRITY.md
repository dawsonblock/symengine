# Baseline Integrity Audit — SIS v3.3 implementation baseline

## Verdict: TRUSTED

Baseline revision: `07a9174b55c1cf21a5873bd7962b2227cd545c96`
Branch: `origin/codex/sis-v3.2-authority-integrity` (pushed, authored
traceably: dawsonblock + Devin co-author trailers).

## Extraction

Reference sources live as sibling checkouts, not embedded zips on this
host: `skills/reasoning-bank-main`, `skills/EvoSkill-main`,
`skills/vskill-main 2` (read-only integration references), and this
repository as the primary codebase. No archive extraction was required;
all four reported "discrepancies" were investigated at the git-history
level against the embedded `RELEASE_SHA256.json` (263 entries).

## Findings (see evidence/baseline/integrity_findings.json)

| File | Finding | Disposition |
|---|---|---|
| `src/sis/v3/verifier.py` | hash mismatch | Changed by `07a9174` — `statement_digest` registration + enforcement. Legitimate. |
| `tests/v3/test_receipt_signatures.py` | hash mismatch | Changed by `07a9174` — statement-binding tests. Legitimate. |
| `tools/live_study.py` | hash mismatch | Changed by `5c89128`, `d56616c`, `07a9174` — v3.2 capture/kill/metering + review fixes. Legitimate. |
| `docs/v3/V32_GAP_MAP.md` | unlisted | Added by `51feebc`, updated `07a9174` — new doc absent from stale manifest. Legitimate. |
| `RELEASE_SHA256.json` | unlisted | Self-exclusion — manifest does not list itself. Expected. |

All five differences trace to pushed commits `51feebc`, `d56616c`,
`5c89128`, `07a9174` on the baseline branch. The manifest is *stale*
(predates the v3.2 delta commits), not the source tampered. The manifest
was **not** regenerated — original evidence preserved in
`evidence/baseline/`.

## Baseline tests

`PYTHONPATH=src:. python3 -m pytest -q` → **662 passed, 2 skipped, 0 failed**
(see `evidence/baseline/baseline_tests.json`).

## Baseline selected for v3.3

`codex/sis-v3.3-governed-learning` branches from `07a9174`. Provenance is
established; production promotion is permitted under the v3 authority
model.
