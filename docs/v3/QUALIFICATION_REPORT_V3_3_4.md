# SIS v3.3.4 Qualification Report

Status: `ENGINEERING_VERIFIED` / `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
This release hardens trust boundaries; it does not establish that SIS
improves a real coding agent.

## Baseline

- Pristine v3.3.3 at `8515147`: 1122 passed, 12 skipped, 0 failed
  (Python 3.12.0, macOS 26.2 arm64).
- Release checks in a clean worktree: 384 files, all SHA-256 matched,
  compile passed; integration smoke passed.
- Recorded in `evidence/baseline/v334_baseline.json`.

## Gates

| Gate | Scope | Evidence |
| --- | --- | --- |
| G1 | Receipt identity: a receipt reference resolves to exactly one authenticated artifact; journal entries are bound to persisted receipts | `src/sis/v3/verifier.py`, 13 regressions in `tests/v3/test_v333_trust_boundary.py::ReceiptIdentityTests` |
| G3 | Memory trust: explicit development/production profiles, external rollback witness, registered-task lineage, retrieval trust gate | `src/sis/v3/memory.py`, `src/sis/v3/memory_witness.py`, 34 regressions in `tests/v3/test_v334_memory_trust.py` |
| G4 | Symbolic induction: development-guided early stopping, explicit computation budget, counterexample refinement, scalability matrix | `src/sis/induction.py`, 19 regressions in `tests/v3/test_v334_induction.py`, `evidence/benchmark/v334_induction_scalability.json` |
| G2 | Production isolation: mandatory policy, typed verification, V2 receipts, isolator issuance, rootless Linux worker, cgroups, seccomp, probe | `src/sis/v3/isolation.py`, `src/sis/v3/linux_worker.py`, `src/sis/v3/cgroups.py`, `src/sis/v3/seccomp_exec.py`, 44 + 21 regressions, `evidence/sandbox/v334_linux_worker_probe.json` |

## Test result

Pre-seal suite: 1251 passed, 13 skipped, 2 failed — both are release
seal checks (`ReleaseIdentityTests.test_release_commit_covers_current_source`
and `test_release_inventory_matches_current_manifest`). Both are
resolved by this release seal. The post-seal result is recorded in
`release/release_manifest.json`.

## Isolation evidence

- `tools/linux_worker_probe.py`: 13/13 on Debian 12, bubblewrap 0.8.0,
  Python 3.11.2, LinuxKit 7.0.14, with a host-mounted cgroup v2
  hierarchy and the inner seccomp filter.
- `Seccomp: 2`; `unshare`/`mount` return `EPERM`; cgroup
  `pids.max`/`memory.max`; read-only `/etc`; network namespace;
  process-group kill; environment scrubbing.
- The validation container was **privileged** because that kernel denied
  unprivileged user namespaces. This validates the bubblewrap
  configuration, not the container's own containment.
- Not validated: a production non-privileged host, a microVM, image/kernel
  digest binding, independent isolator custody. See
  `docs/v3/WORKER_VALIDATION_PLAN.md`.

## Known limitations

See `docs/v3/V33_LIMITATIONS.md`. The material ones for this release:

- The local subprocess executor can never qualify; production execution
  stays closed without a qualified worker host or microVM.
- The isolator is trusted; the policy verifies its claims, not the OS.
- The seccomp filter is a denylist, not an allowlist.
- V1 outcome receipts cannot prove attempt identity; production uses V2.
- The 64-field induction stress case truncates at the default budget.
- Efficacy is not established.

## Reproduce

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 \
PYTHONPATH=src python3 -m pytest -q
python3 tools/check_release_ci.py --mode release
python3 tools/verify_release.py --compile .
PYTHONPATH=src python3 tools/smoke_integration.py
```

The Linux worker probe must be run on the target host; it exits 2 off
Linux:

```bash
PYTHONPATH=src python3 tools/linux_worker_probe.py --json probe.json
```
