# SIS v3.3.5 Qualification Report

Status: `ENGINEERING_VERIFIED` / `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
This release repairs two resource/trust-boundary defects and completes the
memory-membership check left open by the v3.3.4 audit. It does not
establish that SIS improves a real coding agent, and it does not qualify
a production sandbox.

## Baseline

- v3.3.4 release: `ENGINEERING_VERIFIED`, 402-file archive, suite
  1255 passed / 13 skipped / 0 failed on Python 3.12.0 (macOS arm64).
- This branch starts from that release commit and adds V335-01 through
  V335-04. The v3.3.4 archive and its provenance remain immutable
  historical evidence.

## Repairs

| Item | Scope | Evidence |
| --- | --- | --- |
| V335-01 | Memory-budget lifecycle: the cap applies whoever owns the tracer, a caller tracer survives, and a lost or restarted tracer fails closed | `src/sis/induction.py`, 12 regressions in `tests/v3/test_v335_memory_budget.py` |
| V335-02 | Production verdict trust boundary: no caller-forged positive isolation verdict can reach TASK_PASS; revoked signers are rejected | `src/sis/v3/evaluation_runtime.py`, `src/sis/v3/isolation.py`, `src/sis/v3/verifier.py`, `tests/v3/test_v334_isolation.py` |
| V335-03 | Explicit per-record memory chain membership for trusted reads | `src/sis/v3/memory.py`, 4 regressions in `tests/v3/test_v335_chain_membership.py` |
| V335-04 | Version bump, pinned suite, regenerated manifest, resealed release | `RELEASE_SHA256.json`, `release/`, this report |

## Test result

Environment: fresh virtual environment containing only `pytest==8.4.2`,
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONNOUSERSITE=1`,
`PYTHONPATH=src`. No plugins, no user site-packages, no PostgreSQL driver.

- Pre-seal: 1271 passed, 14 skipped, 2 failed. Both failures are release
  seal checks: `test_release_inventory_matches_current_manifest` (the
  `release/` inventory still describes v3.3.4) and
  `test_release_commit_covers_current_source` (the manifest still names
  the v3.3.4 commit). Both are resolved by the seal, which regenerates
  the out-of-band `release/` bundle.
- Post-seal: recorded in `release/release_manifest.json`. The seal commit
  changes no manifest-covered file, so the suite result carries over
  unchanged.

The system interpreter with `psycopg` installed runs the same tree as
1272 passed, 13 skipped, 2 pre-seal failures: the extra skip is the
PostgreSQL control-plane test that the clean environment cannot import.

The sealed archive is re-verified from a fresh extraction, including the
repair regressions and the audit reproductions, in
`evidence/v335/V335_ARTIFACT_VERIFICATION.md`.

## What the repairs do and do not prove

- The memory cap is an incremental soft budget over Python allocations
  observed through `tracemalloc`. It is not an OS RSS limit, cannot see
  native-extension allocations, and samples at resource-check points. A
  hard bound still belongs to the subprocess/cgroup/microVM layer.
- Fail-closed on tracer loss means a search whose measurement disappears
  reports `resource_exhausted`. It cannot distinguish a hostile stop from
  an operator tool that resets `tracemalloc`, and it deliberately treats
  both as unverified.
- Chain membership proves a record is present in the store's signed
  chain. It is not provenance: the record signature and the
  experience → outcome → execution → registered-task lineage still decide
  whether a member is trusted.
- The isolation repair rejects forged verdicts and revoked signers. It
  does not qualify a sandbox; production execution stays closed without a
  qualified worker host or microVM.

## Known limitations

See `docs/v3/V33_LIMITATIONS.md`. Material for this release:

- No qualified production sandbox exists. The Linux worker probe
  validates a bubblewrap configuration on a privileged container, not a
  production host or microVM.
- The isolator is trusted; policy verifies its claims, not the OS.
- Symbolic search still truncates on wide fields at the default budget;
  scaling work is separate from this repair.
- Efficacy is not established.

## Reproduce

```bash
python3 -m venv /tmp/sis-venv
/tmp/sis-venv/bin/python -m pip install pytest==8.4.2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 \
PYTHONPATH=src /tmp/sis-venv/bin/python -m pytest -q
python3 tools/check_release_ci.py --mode release
python3 tools/verify_release.py --compile .
PYTHONPATH=src python3 tools/smoke_integration.py
```
