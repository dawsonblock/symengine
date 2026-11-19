# SIS v2.2 — Instrumented Experience Abstraction

## What's new

- `InstrumentedSession` captures **actual, allowlisted, pure tool invocations** and the results computed at the same boundary. It is designed to wrap the agent's tool executor, rather than trusting a generated narrative of the run.
- References carry the origin of each argument: an input, a previous tool result, or a literal. For concrete arguments, value-based provenance inference is allowed only when **exactly one** input or prior result matches. Ambiguous matches fail closed until the agent/executor supplies an explicit binding.
- `replay_capture()` independently recomputes **every recorded tool result**, verifies data-flow references, and checks a SHA-256-linked event sequence. A hash of locally controlled data is **not** an independent signature or attestation.
- `experience_induce()` generalizes successful captures into the same typed AST across multiple inputs. It refuses to mix different successful programs, rejects train/validation input overlap, and passes the proposal through the unchanged v2.1 trace replay, separate validation, and governed promotion checks.
- Incorrect but executable trajectories can supply negative examples **only with independently provided corrected labels**. They never become proposed procedures.

## Trust model

1. Observed execution results can be replayed deterministically with the existing SIS interpreter. The recorder does not execute arbitrary code, use the filesystem, or make network calls. It handles binary `add/sub/mul/min/max/eq/lt/gt/and/or/concat` operations only, with a maximum of six calls per capture.
2. A caller's `accepted=True` flag is **not independently authenticated**. Separate validation examples are provided by the evaluator/operator. Holdout evaluation remains available in v1.8/v2.0, but v2.2 does not automatically invoke a sealed evaluator.
3. Local SHA-256 event links detect accidental and partial manipulation. An actor who can replace the full capture can recompute these hashes. For untrusted remote agents, store event envelopes in evaluator-controlled, write-once storage or add a separate signed collector.
4. Captures are **not exposed as write-authorized LLM tool calls**, and this module never directly writes the trusted skill registry. Its candidate must still pass the `SkillCatalog` promotion checks.
5. The current abstraction learns repeatable typed data-flow programs from known pure tools. It does **not** automatically learn from shell, browsers, arbitrary Python, raw text transcripts, or uncontrolled agents; those need a separately sandboxed, permission-scoped workflow executor and independent outcome validators.

## Python integration — actual tool-call capture

```python
from sis.experience_events import InstrumentedSession

session = InstrumentedSession({'a': 5, 'b': -2})
intermediate = session.call('add', left=session.input('a'), right=session.input('b'), step_id='sum')
answer = session.call('mul', left=intermediate, right=session.literal(2), step_id='double')
capture = session.capture(answer)
```

For a tool that receives concrete scalar arguments, `session.call('add', left=5, right=-2)` tries to bind them to unique inputs or previous results; if multiple sources have the same value, explicit `session.input(...)`, `session.previous(...)`, or `session.literal(...)` references are required. This avoids silently mistaking coincidence for dependency.

A production agent framework should call `session.call()` from its actual tool-dispatch boundary. Do not synthesize event results from the LLM's own explanation.

## Governed experience induction

A study has this JSON shape:

```json
{
  "namespace": "example",
  "promote": false,
  "train_captures": [
    {"capture": {"...": "actual output of InstrumentedSession.capture()"}, "accepted": true}
  ],
  "validation": [
    {"inputs": {"a": 7, "b": 8}, "output": 30},
    {"inputs": {"a": -10, "b": 6}, "output": -8}
  ]
}
```

At least three successful matching captures and two separately labeled validation examples are required. All successful captures must normalize to **one exact generalized program**. Distinct programs must be separated into task families before learning. Even with `promote=true`, promotion is conditional on v2.1's full verification and ambiguity checks.

To run the integration demonstration:

```bash
python3 -m pip install -e .
python3 tools/demo_experience_capture.py
sis experience-capture examples/v2_2/plan.json
```

To use the CLI training path, save real `capture` responses from at least three training runs plus separate evaluator validation cases into a study JSON file, then run:

```bash
sis --db local-skills.sqlite3 experience-induce examples/v2_2/experience_study.json
sis --db local-skills.sqlite3 skill-predict examples/v2_2/prediction.json
sis --db local-skills.sqlite3 skill-audit
```

## Deliberate limitations / next research milestones

- The successful-program cluster criterion is exact, not semantic-equivalence-based. Different tool sequences implementing the same function are treated as different skills.
- No causal or semantic oracle is created by the capture itself; evaluator-controlled, unseen tasks are needed to establish correctness and transfer.
- No model training occurs automatically. Optional LoRA infrastructure from v1.9 remains separate and opt-in.
- Numeric identity collisions are rejected rather than heuristically resolved.
- Expand to typed external workflow tools only with allowlisted permissions, isolation, budgets, idempotence, and operator approval for side effects.
