# SIS v2.0 — Family-disjoint neural qualification

## Objective

This release adds a **separate evaluator-custodied experiment** to compare a
baseline LLM, that baseline with read-only frozen procedural-skill hints, a
LoRA-adapted endpoint, and an optional placebo hint. It does not train models
on its own (v1.9 `neural-train --execute` handles that), and never promotes an
adapter, changes active SIS rules, or certifies that a model is generally smarter.

## What changed versus v1.9

- Precommitted HMAC-SHA256 protocol binds a private, labeled test dataset,
  frozen skill bundle digest, claimed baseline/adapter identifiers, family IDs,
  predeclared training/validation family names, maximum token budget and policy.
- *Family split firewall*: training, validation and test family names may not
  overlap. Known training/validation input records may not exactly overlap test
  inputs, including across families. This is **declared provenance only**, not
  external certification of pretraining or task novelty.
- One-use SQLite vault consumes an experiment identifier **before** model
  requests. Interrupting a network call does not permit reusing that ID.
- Four-arm comparisons (three without placebo), counterbalanced arm order,
  strict typed JSON answers, model-error invalidation, per-task-family results,
  micro/macro accuracy, cost/latency accounting where providers supply usage,
  exact item-paired McNemar p-values, exact family-level sign tests and Holm family-wise correction.
- Qualification policy precommits alpha, minimum accuracy gain, and a placebo
  requirement. It checks both symbolic and adapted arms and refuses success on
  model errors or within-family observed accuracy regressions.
- Outputs contain signed *aggregates* only, never private labels or individual
  predictions. HMAC authenticates the bytes to the secret holder, **not** an
  independent third-party's identity.

## Local exercise — no model download

```sh
PYTHONPATH=src python tools/demo_family_eval.py
PYTHONPATH=src python -m unittest discover -s tests -v
```

The demo uses deterministic mock clients and trivially synthesized task
families. Its policy pass **cannot be represented as an independently verified
improvement in LLM capability**.

## Live evaluator-owned workflow

Prepare a private JSON file with these exact keys:

```json
{
  "format":"sis.family_dataset.v2",
  "experiment_id":"experiment-2026-10-21-001",
  "namespace":"my-task",
  "task_description":"Describe the deterministic input-to-output task in plain language.",
  "training_families":["held-out-from-testing:train-A"],
  "validation_families":["held-out-from-testing:validation-B"],
  "excluded_inputs":[{"a":1,"b":2}],
  "test":[
    {"family_id":"unseen-task-family-C","cases":[
      {"inputs":{"a":3,"b":4},"output":7}
    ]}
  ],
  "max_tokens":128,
  "include_placebo":true
}
```

The small fragment above illustrates *shape only* and is intentionally invalid
as a full trial. **Use at least eight distinct test families, eight examples per
family, and 64 examples total for policy gating**. All test inputs must share
exactly the frozen skill's schema, and every training/validation family and
excluded input must be genuinely accounted for.
`task_description` is sent to all model arms with each unlabeled input and is
bound into the signed protocol; use a precise description of the target task.

Use an evaluator machine with private test labels and secret. Do **not** ship
private cases or HMAC secret to a candidate model developer. The evaluator
precommits before any evaluation. Shell commands:

```sh
export SIS_EVAL_HMAC_KEY='<32+ byte high entropy secret set out-of-band>'
export SIS_LLM_MODEL='<baseline model ID precommitted below>'
# configure SIS_LLM_BASE_URL and SIS_LLM_API_KEY as per existing client docs
sis family-eval-seal private.json frozen_bundle.json public_protocol.json \
  --baseline-id "$SIS_LLM_MODEL" --adapted-id 'local-adapter-id'

sis family-eval-run private.json frozen_bundle.json public_protocol.json \
  report.json --vault ./custodian-exclusive-vault.sqlite3 \
  --adapted-url 'http://127.0.0.1:8001/v1' \
  --adapted-model 'local-adapter-id' --allow-network
```

The `family-eval-run` command sends **unlabeled** inputs to model endpoints.
Only the custodian should read the labels or control the vault. Outputs fail
closed if the report already exists or network opt-in is missing. Never reuse
an experiment ID after network failure; create a new precommitted dataset and
ID instead. Model IDs and endpoint URLs are operator assertions, not weight
hash proofs.

To authenticate a stored aggregate receipt without accessing private labels:

```sh
sis family-eval-verify public_protocol.json report.json
```

This proves possession of the custodian HMAC secret and binding to the
precommitted protocol, **not** correctness of the underlying private labels.

## Limitations that matter

1. The implementation does not establish that entire task families are
   semantically novel, that pretrained LLMs have not seen similar examples,
   or that LoRA training really excluded them. Training source assertions are
   checked for **declared** overlaps only.
2. Qualification now requires eight or more designated task families and Holm-adjusted exact family-level sign tests. Even this requires independent families and representative sampling—both must be established by an external evaluator before making generalization claims. Item-level McNemar is descriptive and does not correct within-family correlation.
3. Placebo hints are structurally related but not tokenizer-token-matched.
   Token counts from an API may differ, and provider token usage is optional.
4. Model endpoints may log unlabeled inputs. No remote endpoint or checkpoint
   fingerprint can be cryptographically authenticated here.
5. A `policy_pass` is an **internal precommitted threshold result** only.
   It is not production readiness, release authority, or improved general
   intelligence. The v1.9 training runner still needs real GPU qualification.
6. Re-running with a new experiment ID over the same cases defeats one-use
   controls: keep private tests in evaluator custody, not candidate control.

## Full release regression

```sh
python3 -m unittest discover -s tests -v
python3 tools/build_release.py
python3 tools/verify_release.py ../symbolic-induction-engine-v2.0.0.zip
```
