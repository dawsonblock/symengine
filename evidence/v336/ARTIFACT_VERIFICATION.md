# V336 artifact verification — sealed archive

Purpose: verify the shipped `release/SIS-v3.3.6.zip`, not the working
tree. A repair that passes only in a checkout is not a repaired release.

Method: extract the archive into a fresh directory, then run from the
extracted copy with an interpreter whose only added package is the pinned
test runner. Nothing is imported from the checkout.

```bash
python3 -m venv /tmp/sis-venv
/tmp/sis-venv/bin/python -m pip install pytest==8.4.2
unzip -q release/SIS-v3.3.6.zip -d /tmp/sis-v336-extract
cd /tmp/sis-v336-extract/SIS-v3.3.6
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 PYTHONPATH=src \
  /tmp/sis-venv/bin/python -m pytest -q \
  tests/v3/test_v336_trust_profile.py \
  tests/v3/test_v336_memory_enforcement.py \
  tests/v3/test_v336_benchmark_semantics.py
```

The extracted copy reports `sis.__version__ == "3.3.6"`.

## Regressions in the archive

43 passed — the 18 trust-profile, 18 memory-enforcement and 7
benchmark-semantics tests ship inside the archive and pass from it.

The v3.3.5 tracer-restart counterexamples remain in
`tests/v3/test_v335_memory_budget.py` and are not weakened.

## Audit reproductions against the archive

| Scenario | Observed |
| --- | --- |
| `MemoryTrustProfile(name="production", all flags false)` | `ContractError: production_profile_requires_every_trust_control` |
| Unsigned `ExperienceRecordV1` in a development store | `untrusted:development_profile`, never `trusted` |
| Renamed/flag-forged profile on an unconfigured store | `untrusted:development_profile` or `untrusted:trust_controls_not_configured` |
| `run_induction_enforced` with a matching observed limit | valid receipt, `hard_memory_verified == true` |
| Forged child report with a different limit | invalid receipt, `hard_memory_verified == false` |
| Default benchmark, fields 2 | `candidate_found == true`, `target_structure_recovered == false`, `exact_recovery_verified == false` |
| Negative-domain benchmark with z3, fields 2–16 | `target_structure_recovered == true`, `equivalence_verified == true`, `exact_recovery_verified == true` |

## What this does not establish

The archive contains no independently qualified production sandbox, no
meaningful Linux `RLIMIT_AS` qualification, and no real-agent efficacy
evidence. Archive identity and provenance are recorded in
`release/verification.json` and `release/release_manifest.json`; this
report deliberately does not repeat a digest that a re-seal would change.
