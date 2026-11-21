# Technical design

> This document describes the v1/v2 rule-induction core. The v3 governed
> learning and serving stack is documented in
> `docs/v3/ARCHITECTURE_V3_3.md`, `docs/V331_ARCHITECTURE.md` and
> `docs/V332_AUTHORITY_CONSISTENCY.md`.

## Trust and execution boundaries

Input examples (untrusted data) -> shape/type validation -> bounded grammar enumeration -> **interpreter-only**
execution -> training fit -> rival disagreement probes -> untouched supplied validation -> evidence-gated
`Registry.promote()` -> rule retrieval -> predictions.

LLM calls, when explicitly requested, are *proposal generators*. The model receives only the training examples (and
public AST schema). Its returned JSON must pass the same AST parser and fit checks as every other candidate. It cannot
determine the final evidence status or directly promote a rule.

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

The above is the *shape*, **not** a valid promoted dataset: promotion requires three distinct train records and two
distinct validation records. All examples must have an identical typed schema. Values are bounded and field names are
identifier-only.

Rule AST example: `{ "op": "add", "args": [ {"op":"field","name":"a"}, {"op":"field","name":"b"} ] }`.

Allowed AST constructors (grammar `sis-grammar-2`; every op is declared once in the `OpSpec` registry
`sis.expression.OPS`, which validation, evaluation, cost, the enumerator, the Z3 translation, schema transfer and the
LLM prompt all read):

- `field(name)` and `item(name,index)`.
- `const(value)`.
- Integer: `add/sub/mul/min/max/absdiff(args:[AST,AST])`, `floordiv/mod(args:[AST,AST])` (Python floor semantics; a
  zero divisor is an evaluation error on that record, never a value), `neg/abs(arg:AST)`.
- Comparisons: `eq(args)` on any equal types; `lt/le/gt(args)` on integers, returning a boolean.
- Text: `upper/lower/reverse(arg)`, `concat(args)` (result at most 128 characters), `slice_prefix/slice_suffix(args:
  [AST, const n])` with a literal length `0 <= n <= 128`, `len(arg)` (string to integer), `contains(args)` (boolean),
  `str_of_int(arg)`.
- Conditionals: `if_eq(left,right,then,else)` and `if_lt(left,right,then,else)` (integer comparison).

Max 31 AST nodes and 6 nesting levels (leaves count as level 1, as in `depth()`), integer results within +-1e9, text
within 128 characters. No Python evaluation, imports, subprocess, file system, reflection, or network access exists in
the rule interpreter. Every induction result carries `grammar_version` and `engine_version`; promotion and sealed
evaluation refuse a result or submission produced under another engine with "re-induce under the current engine".

## Induction algorithm

Learner v2 (`sis.synthesis`, engine `sis-induce-3`; `sis-induce-2` before forward completions were deferred, SIS-FIX-26) is a typed bottom-up enumeration by cost. Programs live in one pool
per result type; two programs that agree on every training and development row and on a fixed prefix of unlabeled
probes are observationally equivalent and only the cheaper is kept. The stages are:

1. leaves, small constants (-2..3) and unary ops on leaves;
2. exact small-integer affine fitting `c0 + sum(ci * xi)` over at most three integer features, then with one of the
   best-ranked depth-2 programs (residual-variance order) as an extra feature; only an exact integer solution is
   accepted;
3. pool levels up to cost 7 (pool depth 3), each new program completed goal-directed against the training outputs:
   `add/sub/mul` are inverted and the missing operand is looked up in the pool or is a constant, `min/max/absdiff` and
   `floordiv/mod` by a constant 2..12 are checked forward, and string outputs look up a prefix or suffix for `concat`.
   The lookups run as each program is added; its forward checks, about one per terminal, are queued to the end of the
   same stage, and every fit keeps the position the one-pass order would have found it at, so a search that completes
   is unchanged while a wide schema reaches its `mul` pairs before the forward work of every `add` pair;
4. when no unconditional rule fits training and development data, one-level conditionals: predicates compare leaves
   with each other or with observed constants, the training rows are split by the predicate and each branch is learned
   separately from the same pool.

Selection stops at the first stage with a rule that fits training and development data and ranks fits by development
failures, then cost. A rival scan then resumes the same enumerator to the end of its declared space (and runs the
conditional stage) under its own budget; a rival that fits every labelled row, costs at most 4 more than the selected
rule and disagrees on an unlabeled probe makes the result `ambiguous`. Probes add new-type values and data-derived
boundaries (observed integers and their neighbours, records with two equal integer fields) to the generated probes;
they never carry truth labels. `SearchBudget` limits still truncate the search explicitly
(`search_truncated=true`, `search_outcome` truncated or resource_exhausted), and a `max_expression_depth` below the
engine's own depth is reported as a limit hit. This is deliberately conservative and not statistically calibrated.

The optional Z3 module can find a disagreement between *two symbolic formulas* in a bounded integer region. Even a Z3
`unsat` for two formulas does **not** prove either formula correctly models the external task. Use it as a falsification
tool, not an oracle for the correct hypothesis.

## Rule lifecycle

- `provisional`: training fit without enough independent validation: fewer than two holdout rows, a holdout that
  carries less than 4 bits of evidence under the labelled-output distribution (three binary rows carry 3), or a
  conditional rule whose holdout does not exercise both branches.
- `ambiguous`: competing training-fit candidates differ on constructed input; collect ground-truth labels and restart
  with new holdout.
- `validation_failed`: selected training-fit hypothesis failed supplied validation.
- `search_incomplete`: budget terminated a search.
- `no_rule`: no candidate matched within grammar.
- `locally_validated`: selected rule matched supplied validation and passed available ambiguity checks.
- `active`: promoted rule stored persistently.
- `suspended`: user reports a mismatched outcome. Human review/re-induction required; no untrusted automatic
  self-rewriting.

Feedback stores user-reported outcomes, does not treat them as independent ground truth, and suspends on a mismatch as a
conservative risk control. On prediction, the registry abstains if zero valid rules apply or multiple rules disagree. As
of v1.3, promotion rejects a new rule that disagrees with existing active rules on training, validation, or
deterministic generated probes. This is bounded compatibility checking, not proof of equivalent domain behavior.

## Important future extension points

- Typed DSL for Boolean logic, relational predicates, quantifiers, time series, programs and recursion.
- Task-specific enumerators and learned DSL grammars rather than unconstrained search.
- Active learning with a separate ground-truth oracle; pre-registered untouched evaluation partitions.
- Cross-task skill reuse with causal provenance and versioned rule specialization.
- Distillation back into small local LLMs only after reproducible out-of-distribution gains.


## v1.7 procedural-skill subsystem

See [V1_7_PROCEDURAL_SKILLS.md](history/V1_7_PROCEDURAL_SKILLS.md) for architecture, verification boundary, threat model and
explicit limitations. The procedural skill chain is local integrity evidence, not a separately anchored cryptographic
attestation.

## v2.1 operator-side trace learning

Typed execution traces are replayed locally and converted into untrusted
procedural hypotheses; they are never an independent correctness oracle.
Validation traces are not accepted, and the tool bridge cannot invoke
trace studies or promote skills. See `docs/history/V2_1_TYPED_TRACE_LEARNING.md`.
