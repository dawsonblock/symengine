# SIS v3.3.6 Qualification Report

Status: `ENGINEERING_VERIFIED` / `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
This release repairs three defects reproduced against v3.3.5 and makes the
release evidence explicit about what remains unqualified. It does not
establish that SIS improves a real coding agent, and it does not qualify
a production sandbox.

## Baseline

- Branch base: `b4d7446`, the sealed v3.3.5 release commit.
- v3.3.5 remained the historical baseline: its archive and provenance are
  unchanged by this release.
- Three defects were reproduced before repair:
  1. `MemoryTrustProfile(name="production", ...all flags false)` built a
     store with no trust roots, and `trust_status` reported an unsigned
     legacy `ExperienceRecordV1` as `trusted`.
  2. The v3.3.5 tracer checks fail closed on a stopped or restarted
     `tracemalloc`, but in-process measurement still cannot prove a hard
     memory bound; no process-level enforcement path existed.
  3. `tools/benchmark_induction.py` reported
     `rule_recovered = rule is not None`. On the default non-negative
     domain the search returns `absdiff(x[n-2] * x[n-1], -2)`, which
     matches every generated example but is a different function that the
     same result reports as `ambiguous`.

## Repairs

| Item | Scope | Evidence |
| --- | --- | --- |
| V336-01 | `MemoryTrustProfile` is a closed enumeration; production must enable every control; development must enable none; `trust_status` requires the store to hold the controls it claims; a verifier without `registered_task` fails construction | `src/sis/v3/memory.py`, 18 regressions in `tests/v3/test_v336_trust_profile.py`, `evidence/v336/trust_profile_bypass_repro.json` |
| V336-02 | New `sis.enforced_induction` runs `induce` in a separate POSIX process capped by `RLIMIT_AS`; a hard-budget claim requires a valid receipt with matching observed limits, a completed child and no memory kill | `src/sis/enforced_induction.py`, 18 regressions in `tests/v3/test_v336_memory_enforcement.py`, `evidence/v336/memory_enforcement_receipt.json` |
| V336-03 | Benchmark reports candidate existence, intended structure, bounded equivalence, holdout accuracy and search completion separately; only `exact_recovery_verified` claims the intended rule | `tools/benchmark_induction.py`, 9 regressions in `tests/v3/test_v336_benchmark_semantics.py`, `evidence/v336/benchmark_default.json`, `evidence/v336/benchmark_negative_z3.json` |
| V336-04 | Version 3.3.6, pinned suite, regenerated manifest, packaged archive and independent verification | `RELEASE_SHA256.json`, `release/`, `evidence/v336/ARTIFACT_VERIFICATION.md` |

### V336-01 — the exact audit bypass

Pre-repair reproduction (v3.3.5 checkout):

```json
{
  "profile": {
    "name": "production",
    "require_signed_records": false,
    "require_evaluator_evidence": false,
    "require_chain_signature": false,
    "require_witness": false,
    "require_registered_task": false
  },
  "trust_status": "trusted",
  "is_trusted": true
}
```

Post-repair, the same profile fails construction with
`production_profile_requires_every_trust_control`; a profile object
renamed or flag-forged after construction still reports
`untrusted:development_profile` or
`untrusted:trust_controls_not_configured`. The regression that pins the
audit case is
`tests/v3/test_v336_trust_profile.py::ProfileConstructionTests::test_audit_bypass_profile_is_rejected`;
it fails before the repair and passes after it.

### V336-02 — two memory levels, kept separate

- The in-process `SearchBudget.max_memory_bytes` remains an incremental
  soft budget over Python allocations. The v3.3.5 fail-closed tracer
  tests remain in `tests/v3/test_v335_memory_budget.py` and were not
  weakened.
- `run_induction_enforced` applies `RLIMIT_AS` in the child before the
  interpreter starts. `MemoryEnforcementReceipt.valid` is derived, not
  caller-asserted: it requires the child to have observed exactly the
  requested soft and hard limit. `EnforcedInduction.hard_memory_verified`
  additionally requires a completed child and no memory kill.
- A forged report with a completed result but a different observed limit,
  a missing enforcement block, a timeout, or a signal death never
  reports hard success.
- macOS refuses `RLIMIT_AS` below the interpreter's current address
  space (hundreds of GiB for a forked Python process). The enforced path
  refuses such a limit as unavailable. The meaningful-cap qualification
  belongs to the Linux worker gate and is not claimed here.

### V336-03 — candidate is not recovery

Default non-negative run, fields 2:

- `candidate_found`: `true`
- `target_structure_recovered`: `false`
- `holdout_accuracy`: `1.0`
- `ambiguous`: `true`
- `exact_recovery_verified`: `false`

With `--input-min -9`, the training data contains negative products and
the intended structure is recovered. With `--equivalence z3`, the run
also verifies equivalence over the declared `-9..9` box:

- `target_structure_recovered`: `true`
- `equivalence_verified`: `true`
- `equivalence_scope`: `z3_box:-9..9:all_features`
- `ambiguous`: `false`
- `exact_recovery_verified`: `true`

`equivalence_verified` is a bounded-box result, not a proof over all
integers. An ambiguous candidate is never reported as a proved rule.

## Test result

Environment: Python 3.12.0 on macOS arm64, pinned `pytest==8.4.2`,
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONNOUSERSITE=1`,
`PYTHONPATH=src`.

- System interpreter with psycopg, cryptography and z3 4.15.4: **1319
  passed, 13 skipped, 0 failed** in 91.13s.
- Fresh venv with `pytest==8.4.2` and optional `z3-solver==4.16.0`, no
  PostgreSQL driver and no `cryptography`: **1318 passed, 14 skipped, 0
  failed** in 235.21s. The single extra skip is the Ed25519 cross-check
  in `tests/v3/test_receipt_signatures.py`, which skips when
  `cryptography` is absent. The PostgreSQL control-plane tests skip in
  both environments because `SIS_POSTGRES_DSN` is unset, not because of
  a missing driver.
- The same fresh venv without z3 skips the three z3-gated tests (two
  bounded-equivalence cases and one counterexample case): **1315
  passed, 17 skipped, 0 failed**.
- New repair regressions: 18 trust-profile, 18 memory-enforcement, 9
  benchmark-semantics tests. All 45 run in every configuration that has
  z3; without z3 the three z3-gated tests skip rather than inferring
  equivalence from matching examples.
- The remaining skips are platform/dependency gates (Linux worker and
  cgroup, PostgreSQL control plane without `SIS_POSTGRES_DSN`, Windows
  ACL paths, absent optional packages), not skipped repair regressions.

The counts above were re-confirmed on the final sealed tree after the
evidence corrections in this commit (`1319 passed, 13 skipped, 0
failed`); only the wall-clock time varies with host load. The recorded
run outputs remain in `evidence/v336/test_summary*.txt`.

## Release integrity

- The archive is built by `tools/package_release.py` from a clean source
  commit. `release/release_manifest.json` and
  `release/verification.json` record the exact ZIP SHA-256, source
  commit, fresh-extraction inventory, `compileall` result and extracted
  smoke test.
- `tools/verify_release.py` re-verifies the ZIP in streaming mode without
  extraction, and `tools/check_release_ci.py --mode release` re-checks the
  extracted inventory.
- Provenance signing requires an externally trusted release key. This
  bundle is **unsigned** unless such a key was supplied at packaging
  time; `release/release_manifest.json` records the actual state. An
  unsigned bundle is qualification evidence, not an authentic release
  seal, and must not be described as one.

## What this proves and does not prove

Proved by this release:

- The reproduced profile-name bypass cannot construct a store or return
  `trusted` under the tested construction paths.
- A production store cannot be built with a missing signer key, chain
  key, witness, verifier or registered-task verifier.
- A hard-memory claim requires a valid OS-limit receipt; forged,
  mismatched, timed-out or memory-killed runs do not qualify.
- The benchmark no longer reports a merely fitting candidate as an
  exactly recovered rule.

Not proved:

- A production sandbox or hostile-code containment on any host.
- A meaningful `RLIMIT_AS` qualification on Linux or a microVM.
- Real-agent efficacy, negative transfer, time or cost benefits.
- That a principal controlling both the enforcing parent and the child
  cannot forge a consistent enforcement receipt. Production still needs
  a separately qualified worker and an externally signed attestation.
- Universal equivalence of any induced rule. Equivalence is bounded to
  the declared input box and requires z3.

## Known limitations

See `docs/v3/V33_LIMITATIONS.md`. Material for this release:

- The soft memory budget cannot see native-extension allocations and
  samples at resource-check points.
- macOS cannot demonstrate a meaningful hard `RLIMIT_AS` cap; the Linux
  worker/microVM gate remains open.
- z3 is optional; without it, `equivalence_verified` is reported as not
  requested or unavailable rather than inferred from examples.
- No external signing identity was available, so the release bundle is
  not an authentic seal.

## Reproduce

```bash
python3 -m venv /tmp/sis-venv
/tmp/sis-venv/bin/python -m pip install pytest==8.4.2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 \
PYTHONPATH=src /tmp/sis-venv/bin/python -m pytest -q
python3 tools/verify_release.py --compile .
python3 tools/verify_release.py release/SIS-v3.3.6.zip
python3 tools/check_release_ci.py --mode release
PYTHONPATH=src python3 tools/smoke_integration.py
```
