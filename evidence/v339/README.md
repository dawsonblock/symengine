# Induction scalability benchmark, re-run (v3.3.9 tree)

`evidence/v336/benchmark_default.json` and
`evidence/v336/benchmark_negative_z3.json` were generated on 2026-11-10,
before the 2026-11-14 search-ordering change (`fdda0d1`, residual-variance
ranking and constant-offset completion) and before learner v2
(`a9c7620`, 2026-11-19, `sis-induce-2`, typed bottom-up enumeration). The
two files here repeat those runs with the same settings on the current
engine. The v336 records are left as they were.

## Runs

- Commit: `d0be0fe` (the induction engine, `src/sis/synthesis.py`, and
  `tools/benchmark_induction.py` last changed in `a9c7620` and `b7eb120`).
- Engine: `sis-induce-2`, grammar `sis-grammar-2`.
- Host: Linux x86_64 container, CPython 3.13.18; `z3-solver==4.16.0.0` for
  the z3 run. The v336 records came from macOS arm64, CPython 3.12.0, so
  `runtime_seconds` is not comparable between the two; candidates and
  signature checks are.
- Settings are those recorded in the v336 files: target
  `x[n-2] * x[n-1] + 2`, partition 6/3/3, `max_candidates` 50,000,
  `max_signature_checks` 500,000, `max_wall_seconds` 30,
  `max_expression_depth` 5, no memory cap. The v336 files do not record the
  seed; the tool's default, 0, is used.
- Wall time: 21.9 s for the default run, 14.0 s for the z3 run. No case hit
  the wall-clock budget.

```bash
PYTHONPATH=src python3 tools/benchmark_induction.py \
  --fields 2,4,8,16,32,64 --seed 0 --train 6 --dev 3 --holdout 3 \
  --input-min 0 --input-max 9 --max-candidates 50000 \
  --max-signature-checks 500000 --max-wall-seconds 30 \
  --max-expression-depth 5 --equivalence none \
  --output evidence/v339/benchmark_default.json

PYTHONPATH=src python3 tools/benchmark_induction.py \
  --fields 2,4,8,16,32 --seed 0 --train 6 --dev 3 --holdout 3 \
  --input-min -9 --input-max 9 --max-candidates 50000 \
  --max-signature-checks 500000 --max-wall-seconds 30 \
  --max-expression-depth 5 --equivalence z3 \
  --output evidence/v339/benchmark_negative_z3.json
```

## Default domain (0..9, no equivalence check)

| Fields | v336 candidates | v339 candidates | v336 signature checks | v339 signature checks | v336 verdict | v339 verdict |
| ---: | ---: | ---: | ---: | ---: | --- | --- |
| 2 | 61 | 9 | 2,801 | 50 | ambiguous, rival structure | ambiguous, intended structure |
| 4 | 144 | 17 | 8,355 | 161 | ambiguous, rival structure | ambiguous, intended structure |
| 8 | 398 | 29 | 32,051 | 607 | ambiguous, rival structure | ambiguous, intended structure |
| 16 | 1,251 | 53 | 160,707 | 1,121 | ambiguous, rival structure | ambiguous, intended structure |
| 32 | 4,267 | 101 | 500,000 (truncated) | 1,217 | search_incomplete, rival structure | ambiguous, intended structure |
| 64 | 15,687 | 2,197 | 500,000 (truncated) | 500,000 (truncated) | search_incomplete, intended structure | search_incomplete, **no candidate** |

On the non-negative domain the rival `absdiff(x[n-2] * x[n-1], -2)` is
observationally equivalent to the target, so "ambiguous" is the correct
verdict whichever of the two is returned; holdout accuracy is 1.0 in every
row except v339 at 64 fields (0.0, nothing returned).

## Negative domain (-9..9, z3 equivalence over the box)

| Fields | v336 candidates | v339 candidates | v336 signature checks | v339 signature checks | v336 verdict | v339 verdict |
| ---: | ---: | ---: | ---: | ---: | --- | --- |
| 2 | 80 | 9 | 3,760 | 50 | exact recovery verified | exact recovery verified |
| 4 | 186 | 17 | 10,994 | 161 | exact recovery verified | exact recovery verified |
| 8 | 474 | 33 | 38,938 | 607 | exact recovery verified | exact recovery verified |
| 16 | 1,418 | 1,422 | 184,466 | 116,352 | exact recovery verified | exact recovery verified |
| 32 | 4,599 | 129 | 500,000 (truncated) | 1,217 | search_incomplete (equivalent, not exact) | exact recovery verified |

## Findings

- From 2 to 32 fields the current engine evaluates one to two orders of
  magnitude fewer candidates and signature checks, and 32 fields now
  completes in both settings (it was truncated in v336); with
  `--input-min -9 --equivalence z3` it is an exact recovery.
- **64 fields regressed.** The search now exhausts `max_signature_checks`
  without returning any rule. The 2026-11-14 changelog entry reported 129
  candidates and 193 signature checks for this case. Re-running
  `--fields 64` at earlier commits places the change at learner v2: its
  parent `7775db0` gives 129 candidates, 193 checks, `locally_validated`;
  `a9c7620` gives 2,197 candidates, 500,000 checks and no candidate. The
  tool's default budget (`max_candidates` 12,000) gives the same result.
- **64 fields after SIS-FIX-26 (2026-11-21).** Learner v2 completed
  each new pool program at once, hash lookups and then about 230 forward
  checks (`min`/`max`/`absdiff` against every terminal, `floordiv`/`mod`
  by 2..12). Pool level 4 starts with the 2,080 `add` pairs, so their
  forward checks used the whole signature budget before any `mul` pair
  existed. The engine now queues a stage's forward checks behind its
  lookups and keeps every fit at its original discovery position, so a
  search that completes is unchanged. `benchmark_default_deferred.json`
  and `benchmark_negative_z3_deferred.json` repeat both runs with the
  same settings: every completed row (2 to 32 fields) is identical, and
  64 fields now returns the intended rule `2 + x62 * x63` (22,110
  candidates, holdout accuracy 1.0). The signature budget still ends that
  search, so it is reported `search_incomplete`, not an exact recovery;
  completing it needs cheaper forward checks, which is induction work for
  after gate G1.
- The 16-field negative-domain run is the one case without a large
  saving: the search went to depth 4 (1,422 candidates, about the v336
  count) before returning the intended rule `2 + x14 * x15`, verified
  exact.

`RELEASE_SHA256.json` is not regenerated for these files: development mode
of `tools/check_release_ci.py` reports the inventory drift, and the
release seal is the owner's keyed step.
