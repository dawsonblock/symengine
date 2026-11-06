# SIS v1.7 — Bounded Procedural Skills and Experience Ingestion

## Actual implementation

This update extends SIS v1.6 rather than replacing its existing rule engine, audit
checkpointing, sealed evaluator, paired LLM harness, transfer bridge, or CLI.
It introduces an **additional** procedural skill subsystem (`skill_program.py`,
`skill_learning.py`, `skill_registry.py`, `experience.py`). Existing v1.6 rule
registrations remain in the same SQLite database and retain their historical
verification properties. New skill tables use separate event chains.

The new interpreter can express:

- Typed scalar input references and fixed list-element selection.
- Constants, arithmetic, comparisons, Boolean expressions, string operations.
- Conditional branches (`if`), lexical bindings (`let`), bounded folds over
  lists of 1–16 elements (`fold`), with no more than two nested folds.
- Compositional calls to existing active skills in the same namespace, identified
  by exact SHA-256 skill IDs (`call`). Calls revalidate exact argument schema
  and dependency status; retired/suspended dependencies cause abstention.

There is **no Python eval/exec**, tool execution, network activity, filesystem
access or general-purpose procedural scripting in the runtime. Limits: <=96 AST
nodes, <=12 expression depth, <=2048 total execution fuel, <=4 nested skill
calls, bounded input/return types inherited from SIS. Overflows and typing
errors fail closed. The fold operation is a **bounded reduction**, not a general
loop with side effects.

## Learning lifecycle

`Service.skill_study(request)` accepts caller-labeled, **disjoint** training and
validation examples. It searches a small deterministic candidate grammar and up
to 16 caller/LLM-proposed JSON ASTs, ranks fitting candidates by size, checks
whether alternate candidates disagree on deterministic **unlabeled** probes,
then tests the *selected* candidate on the reserved validation set. The
candidate is eligible for promotion only if search is complete, the tested
hypotheses are not probe-distinguishable, and all reserved validation cases
pass. Admission re-executes the full discovery study; hashes and claimed
accuracy submitted by a client are never promotion authority. Admission also
checks conflicts against active, same-schema skills on bounded probes.

This process is a safety/evidence gate, **not** a formal guarantee of full
semantic equivalence or independent generalization. It can fail to discover a
valid program, and it can accept a spurious but observationally equivalent one.
The default enumerator is deliberately small; it does *not* search arbitrary
combinations, recursion, loops, API calls, or complex programs. If a candidate
comes from an LLM, the caller—not the LLM—must supply its validation labels and
governed promotion authorization.

## Quick start

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
sis --db ./skills.sqlite3 skill-study examples/skill_sum_study.json
sis --db ./skills.sqlite3 skill-predict examples/skill_sum_predict.json
sis --db ./skills.sqlite3 skills --namespace list_sum
sis --db ./skills.sqlite3 skill-audit
sis --db ./skills.sqlite3 skill-benchmark examples/skill_sum_benchmark.json
```

A validation study must be manually rerun if the input schema changes (including
list length). Missing or invalid skills return `abstain`.

### API

```python
from sis.service import Service
service = Service('skills.sqlite3')
try:
    study = service.skill_study({...})  # trusted operator context
    answer = service.skill_predict({'namespace':'list_sum','inputs':{'nums':[10,20,30]}})
    print(answer)
finally:
    service.registry.close()
```

New HTTP endpoints:

- `POST /v1/skills/study` — operator authorization.
- `POST /v1/skills/experience` — operator authorization.
- `POST /v1/skills/predict` — read-only.
- `POST /v1/skills/benchmark` — read-only, caller-controlled test data.
- `POST /v1/skills/feedback` and `POST /v1/skills/retire` — operator authorization.
- `GET /v1/skills` and `GET /v1/skills/audit` — authenticated read access.

`SIS_API_KEY` is necessary on non-loopback bindings. With an API key configured,
mutations require a **different**, sufficiently long `SIS_ADMIN_KEY`.
The bundled server has no TLS or public internet hardening; use a controlled
reverse proxy and separate custodian if deploying beyond localhost.

The model-facing `ToolBridge` now exposes `sis_skill_predict`, which is
read-only. Model-facing tools still have **no promotion/feedback/retirement
permissions**.

### Labeled execution episodes

The `experience-study` command converts caller-labeled episodes into a study:

```bash
sis --db ./skills.sqlite3 experience-study examples/experience_study.json
```

Each episode includes `inputs`, `observed_output`, and `accepted`. If
`accepted=false`, it **must** also include a type-matched, different
`correct_output`; otherwise learning from that episode is refused. Optional
`trace` is a list of up to 32 short strings. Trace digests/counts are reported,
but the trace contents are **not** yet translated into symbolic programs;
learning uses only the typed labeled input/output examples. User-provided
accepted/corrected labels are NOT authenticated as ground truth.

## Database integrity and lifecycle

The `sis_skills` projection table and `sis_skill_events` append-only-by-API
hash chain are verified against one another before any skill is listed, executed,
or mutated. A mismatch fails closed. A negative feedback report suspends the
skill; dependencies that become inactive cannot be executed through calls.
Retirement is permanent for that skill ID in this database. Audit authentication
is only local and cannot stop a database owner from rewriting or truncating a
consistent history. There is no independent HMAC signer for this skill-specific
chain; it should not be described as one. The existing v1.6 rule anchor protects
**only its own** `audit` chain, not the new skill chain.

## Evaluation and limitations

The existing v1.4 sealed evaluator and v1.6 paired LLM benchmark continue to
operate on the legacy **rule** grammar, not automatically on the v1.7 skill
catalog. The new `skill-benchmark` evaluates a **caller-supplied** dataset and
reports accuracy/coverage. It does not assert independent holdout provenance,
training-data decontamination, or LLM+SIS performance improvements.

**Not implemented:** neural weight updates, automatic model distillation,
long-horizon stateful code execution, arbitrary recursive program induction,
semantic interpretation of raw trajectories, generalized causal reasoning,
independently held out skill evaluation, production multi-tenant isolation,
separate cryptographic promotion authorities for skills.

## Suggested next evaluation

1. Freeze one model, prompts, cost limits, allowed skill corpus, and test period.
2. Use a separate evaluator to hold task-family test labels and enforce one-use
   submissions; add v1.7 procedural support to the sealed evaluator.
3. Compare model-only, retrieval-only, token-matched placebo, and model+SIS
   under equivalent compute budgets.
4. Measure per-task accuracy, abstention, latency, tokens, overhead, transfer,
   and negative-transfer rate with confidence intervals.
5. Only after reproducible gains, consider verified-trace distillation with
   separate policy and weight-release gates.
