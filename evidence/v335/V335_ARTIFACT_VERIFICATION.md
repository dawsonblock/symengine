# V335 artifact verification — sealed archive

Purpose: verify the shipped `release/SIS-v3.3.5.zip`, not the working
tree. A repair that passes only in a checkout is not a repaired release.

Method: extract the archive into a fresh directory, then run from the
extracted copy with an interpreter whose only added package is the pinned
test runner. Nothing is imported from the checkout.

```bash
python3 -m venv /tmp/sis-venv
/tmp/sis-venv/bin/python -m pip install pytest==8.4.2
unzip -q release/SIS-v3.3.5.zip -d /tmp/sis-v335-extract
cd /tmp/sis-v335-extract/SIS-v3.3.5
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 PYTHONPATH=src \
  /tmp/sis-venv/bin/python -m pytest -q \
  tests/v3/test_v335_memory_budget.py tests/v3/test_v335_chain_membership.py
```

The extracted copy reports `sis.__version__ == "3.3.5"`.

## Regressions in the archive

16 passed — the 12 budget tests and 4 membership tests ship inside the
archive and pass from it.

## Audit reproductions against the archive

| Scenario | Observed |
| --- | --- |
| 16 fields, 1 MiB cap, `tracemalloc` already running | `resource_exhausted`, `limits_hit == ["max_memory_bytes"]`, caller's tracer still active afterwards |
| 16 fields, 1 MiB cap, engine-owned tracer | `resource_exhausted`, engine stops only its own tracer |
| Tracer stopped mid-search | `check_resources() == False`, `limits_hit == ["memory_tracer_lost"]`, `outcome == "resource_exhausted"` |
| Caller-forged positive isolation verdict | rejected: `classify_execution` no longer accepts `isolation_verification` (`TypeError`) |
| `classify_execution(production=True)` | `SANDBOX_FAILURE` |

The third row is the defect reported after the V335-01/V335-02 review: the
v3.3.4 check returned success with a zero-growth reading once tracing
stopped. It now fails closed.

## Benchmark in the archive

`tools/benchmark_induction.py --fields 16 --max-memory-bytes 1048576`,
run from the extracted copy:

- `search_outcome`: `resource_exhausted`
- `limits_hit`: `["max_memory_bytes"]`
- `memory_limit_source`: `tracemalloc_incremental`
- `observed_peak_bytes`: about 1.05 MB (1,049,954 in this run; the peak
  varies slightly run to run, as the earlier 1,049,020 measurement did)

## What this does not establish

The archive contains no independently qualified production sandbox and no
real-agent efficacy evidence. Archive identity and provenance are recorded
in `release/verification.json` and `release/release_manifest.json`; this
report deliberately does not repeat a digest that a re-seal would change.
