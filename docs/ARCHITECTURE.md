# Technical design

> This document describes the v1/v2 rule-induction core. The v3 governed
> learning and serving stack is documented in
> `docs/v3/ARCHITECTURE_V3_3.md`, `docs/V331_ARCHITECTURE.md` and
> `docs/V332_AUTHORITY_CONSISTENCY.md`.

## Trust and execution boundaries

Input examples (untrusted data) -> shape/type validation -> bounded grammar enumeration -> **interpreter-only** execution -> training fit -> rival disagreement probes -> untouched supplied validation -> evidence-gated `Registry.promote()` -> rule retrieval -> predictions.

LLM calls, when explicitly requested, are *proposal generators*. The model receives only the training examples (and public AST schema). Its returned JSON must pass the same AST parser and fit checks as every other candidate. It cannot determine the final evidence status or directly promote a rule.

## Components

| Module | Responsibility |
| --- | --- |
| `validation.py` | data limits, schema consistency, canonical hashes |
| `expression.py` | typed, whitelisted expression AST; interpreter; cost |
| `induction.py` | bounded induction search, candidate ranking, synthetic unlabeled probes |
| `smt.py` | **optional** Z3 counterexample search within integer bounds |
| `registry.py` | SQLite persistence, namespace isolation, abstention, feedback, audit chain |
| `model.py` | opt-in OpenAI-compatible HTTPS or localhost inference |
| `service.py` | orchestration and promotion gate; never accept client-made evidence |
| `server.py` | local JSON HTTP, auth header, size limits |
| `cli.py` | reproducible command line driver |

## Data contract

Study:

```json
{
  "namespace": "project_alpha",
  "train": [{"inputs":{"a":1,"b":4},"output":5}],
  "validation": [{"inputs":{"a":3,"b":5},"output":8}],
  "promote": true,
  "use_llm": false,
  "use_z3": false,
  "max_candidates": 12000
}
```

The above is the *shape*, **not** a valid promoted dataset: promotion requires three distinct train records and two distinct validation records. All examples must have an identical typed schema. Values are bounded and field names are identifier-only.

Rule AST example: `{ "op": "add", "args": [ {"op":"field","name":"a"}, {"op":"field","name":"b"} ] }`.

Allowed AST constructors:

- `field(name)` and `item(name,index)`.
- `const(value)`.
- `add/sub/mul/min/max/absdiff/eq(args:[AST,AST])`.
- `neg/abs/upper/lower/reverse(arg:AST)`.
- `if_eq(left,right,then,else)` (model suggestions; deterministic search does not currently enumerate conditionals).

Max 31 AST nodes, max nesting depth 5, integer and text limits enforced at input and output. No Python evaluation, imports, subprocess, file system, reflection, or network access exists in the rule interpreter.

## Induction algorithm

First enumerate depth-one hypotheses, evaluate *only* training examples, retain perfect fits, rank by AST cost and canonical JSON, then generate deterministic input perturbations. If depth-one has no perfect fit, expand arithmetic depth two up to `max_candidates`; a budget hit is reflected as `search_truncated=true`. Compare alternatives on probes, producing a distinguishing input when possible. A probe does not carry truth labels. Finally test only the selected rule against separately supplied validation cases. This is deliberately conservative and not statistically calibrated.

The optional Z3 module can find a disagreement between *two symbolic formulas* in a bounded integer region. Even a Z3 `unsat` for two formulas does **not** prove either formula correctly models the external task. Use it as a falsification tool, not an oracle for the correct hypothesis.

## Rule lifecycle

- `provisional`: training fit without required validation.
- `ambiguous`: competing training-fit candidates differ on constructed input; collect ground-truth labels and restart with new holdout.
- `validation_failed`: selected training-fit hypothesis failed supplied validation.
- `search_incomplete`: budget terminated a search.
- `no_rule`: no candidate matched within grammar.
- `locally_validated`: selected rule matched supplied validation and passed available ambiguity checks.
- `active`: promoted rule stored persistently.
- `suspended`: user reports a mismatched outcome. Human review/re-induction required; no untrusted automatic self-rewriting.

Feedback stores user-reported outcomes, does not treat them as independent ground truth, and suspends on a mismatch as a conservative risk control. On prediction, the registry abstains if zero valid rules apply or multiple rules disagree. As of v1.3, promotion rejects a new rule that disagrees with existing active rules on training, validation, or deterministic generated probes. This is bounded compatibility checking, not proof of equivalent domain behavior.

## Important future extension points

- Typed DSL for Boolean logic, relational predicates, quantifiers, time series, programs and recursion.
- Task-specific enumerators and learned DSL grammars rather than unconstrained search.
- Active learning with a separate ground-truth oracle; pre-registered untouched evaluation partitions.
- Cross-task skill reuse with causal provenance and versioned rule specialization.
- Distillation back into small local LLMs only after reproducible out-of-distribution gains.


## v1.7 procedural-skill subsystem

See [V1_7_PROCEDURAL_SKILLS.md](V1_7_PROCEDURAL_SKILLS.md) for architecture, verification boundary, threat model and explicit limitations. The procedural skill chain is local integrity evidence, not a separately anchored cryptographic attestation.

## v2.1 operator-side trace learning

Typed execution traces are replayed locally and converted into untrusted
procedural hypotheses; they are never an independent correctness oracle.
Validation traces are not accepted, and the tool bridge cannot invoke
trace studies or promote skills. See `docs/V2_1_TYPED_TRACE_LEARNING.md`.
