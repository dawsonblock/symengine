# v2.1 — Typed execution trace to governed procedural skill

## What was added

`src/sis/trace_learning.py` implements a controlled `trace-study` ingestion path.
It is distinct from v1.7 `experience-study`, which treats trace text as inert
metadata. v2.1 accepts **bounded, declarative expression traces**, verifies
all claimed intermediate results by replay in the SIS interpreter, and
reconstructs a program whose output can be re-tested against labeled records.

This is **not** learning general programs from free-form logs, shell history,
chat chains-of-thought, or raw video. The caller must provide typed program
steps and externally labeled example outcomes. A successful trace is merely an
untrusted hypothesis until it passes the independent, existing study gates.

## Usage

```sh
python3 -m pip install -e .
sis --db ./trace-skill.sqlite3 trace-study examples/trace_study.json
sis --db ./trace-skill.sqlite3 skill-predict examples/trace_predict.json
sis --db ./trace-skill.sqlite3 skill-audit
```

The example is synthetic and its answer (52) is not generalization evidence.

## Request format

- `namespace`: identifier for the skill registry.
- `promote`: **boolean**; omitted defaults to false.
- `max_candidates`: 1–5000, passed to existing skill synthesis.
- `train_episodes`: each has `inputs`, `accepted` (boolean), `observed_output`, and optional `trace` string metadata. Accepted episodes may include `steps` with 1–6 typed SIS operations.
- `validation_episodes`: labeled outputs only. Typed `steps` are **forbidden** to avoid using validation traces as training hypotheses.
- Failed episodes require `correct_output`, which must differ from `observed_output` with exactly the same output type. Failed traces can be replayed but their procedures are never proposed.

Each `steps` entry is exactly:

```json
{
  "name": "total",
  "expr": {"op":"binary","fn":"add","left":{"op":"input","name":"a"},"right":{"op":"input","name":"b"}},
  "value": 5
}
```

Each step expression can reference original input fields or prior steps via
`{"op":"var","name":"total"}`. The final step defines the procedure's
output. Forward references, duplicate names, invalid intermediate values,
unsupported AST functions, and too-deep/too-large programs are rejected.

For every prefix of steps, the compiled program is executed *from scratch*
with no skill resolver, filesystem, shell, network or arbitrary code runtime.
Each computed intermediate scalar must exactly match the caller's claimed
value, including type: `true` never equals `1` for evidence checks.

The resulting program is a sequence of lexical `let` bindings (not injected
Python code). Up to 16 distinct programs from **successful training traces**
are considered as candidates. Existing deterministic synthesis may supply
other hypotheses; every candidate is checked against train labels and a
separate labeled validation set. Hypothesis disagreement may trigger
`ambiguous` and prevent promotion. Registry promotion independently replays
the entire normalized study and stores a governed skill with audit events.

## Trust and safety boundaries

- Replay demonstrates *computational internal consistency*, **not that the
  outcome is correct in the real world**. Labels and traces are caller-supplied.
- `trace-study` is an operator-side CLI/Python function. It is deliberately **not
  exposed** through the model's read-only `ToolBridge` and does not add any
  network mutation endpoint.
- No LLM is required or called by the trace learning path.
- Validation inputs are disjoint from train inputs and are not consulted to
  propose programs. Only the chosen candidate is tested on validation.
- Local validation is not independent holdout qualification. For evaluator-
  controlled skill testing, freeze the promoted skill and use the v1.8
  `skill-eval-*` commands with independently controlled secret data.
- For real-model comparisons, use the existing v2.0 family-evaluation harness
  and record actual model IDs / adapters / costs / latency. Model calls and
  GPU fine-tuning are not performed by the default tests.

## Known limits

Programs are bounded to the existing SIS interpreter's typed AST and 96-node,
12-depth, 2048-fuel limits, with at most 6 trace steps. The existing input
schema fixes list lengths. No arbitrary Python, recursion, latent-knowledge
extraction, general symbolic planning, or independently proven LLM lift is
implemented. Per-prefix re-execution is intentionally redundant for checking
intermediate claims.
