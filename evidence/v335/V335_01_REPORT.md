# V335-01 — Memory-budget lifecycle repair

Status: implemented on `repair/v335-resource-security`. Scope limited to
`src/sis/induction.py`, its regressions, the benchmark reporter, and this
evidence directory. No production-isolation, receipt, control-plane, or
unrelated module changes.

## Defect

`SearchState` only checked `max_memory_bytes` when it had started
`tracemalloc` itself (`tracing_started`). A caller that had already
started tracing bypassed the cap and could report `completed` with a
traced peak above the limit. The audit reproduced 3,336,592 bytes against
a 1,048,576-byte cap.

## Red evidence (before the fix)

`tests/v3/test_v335_memory_budget.py` failed:

- `test_cap_applies_with_caller_started_tracer`: `completed` instead of
  `resource_exhausted` with a 1 MiB cap and an external tracer.
- `test_sequential_searches_reset_baseline`: both searches reported
  `completed`.
- `test_search_state_ownership`: no `start()`/`close()` lifecycle.
- `test_signature_count_never_exceeds_cap`: reported 11 checks against a
  cap of 10.

## Fix

- `SearchState.start()` enables memory checking whenever a cap is set,
  records a baseline from a caller-owned tracer, or starts its own and
  remembers ownership. `close()` stops only a tracer it started.
- The cap is an incremental soft budget over Python allocations:
  `growth = current - baseline`, sampled at every resource-check point;
  `observed_peak_bytes` records the largest sampled growth. It is not an
  OS RSS limit and cannot see native-extension allocations. Hard caps
  belong to the subprocess/cgroup/microVM isolation layer.
- The result reports `observed_peak_bytes` and `memory_limit_source`
  (`tracemalloc_incremental` or `null`).
- `spend_signature()` checks the cap before incrementing, so the reported
  count never exceeds `max_signature_checks`.

## Green evidence

- `tests/v3/test_v335_memory_budget.py`: 7 passed.
- Focused induction/legacy suite: 73 passed.
- Full suite: 1262 passed, 13 skipped (pre-commit working tree).
- Benchmark with a caller-owned tracer and a 1 MiB cap:
  `evidence/v335/memory_budget_probe.json`
  - 8 fields: `resource_exhausted`, `max_memory_bytes`, observed peak
    1,050,369 bytes, source `tracemalloc_incremental`.
  - 16 fields: `resource_exhausted`, `max_memory_bytes`, observed peak
    1,049,020 bytes, source `tracemalloc_incremental`.
  - Both ran through `tools/benchmark_induction.py --max-memory-bytes
    1048576`, which starts tracing itself.

## Known pre-seal condition

`RELEASE_SHA256.json` remains the immutable v3.3.4 baseline. After this
commit, `ReleaseIdentityTests.test_release_commit_covers_current_source`
will fail until the v3.3.5 seal; that is expected and is not a code
regression. Do not regenerate the manifest for this ticket.

## Remaining work (not in V335-01)

V335-02 production-verdict trust boundary, V335-03 memory chain
membership/retrieval, V335-04 pinned suite and docs.
