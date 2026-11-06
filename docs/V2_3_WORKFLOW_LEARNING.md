# SIS v2.3 — Verified, read-only tabular workflow learning

## What this release actually does

SIS 2.3 extends the 2.2 arithmetic-oriented recorder with an entirely separate,
restricted workflow type: small tabular transformation and aggregation programs.
A `WorkflowSession` executes each operator on real in-memory rows and captures
observed intermediate row counts and terminal integer results. A workflow is
learned only from at least three locally replayable, successful, structurally
canonicalizable captures plus two separately supplied labeled validation
examples. The operator, NOT the LLM, controls admission. All labels are
caller-supplied and are **not independently authenticated**.

## Supported operations and bounds

- `filter_eq(field,value)` compares a typed scalar.
- `filter_gt`, `filter_lt` compare bounded integers.
- `count`, `sum(field)`, `min(field)`, `max(field)`, `distinct_count(field)` terminate a plan.
- Each record has 1–12 named scalar fields, and a data object has 1–128 records.
- Every record in a data object must have exactly the same typed field schema.
- Maximum eight operations; one terminal aggregation. Overflows and empty-set
  `min`/`max` are rejected.
- No shell, subprocess, network, file modification, general Python code or
  autonomous browser access. To support real coding agents, build a *separate*,
  permission-restricted side-effecting workflow runtime with proper isolation.

## Exact-law canonicalization

Independent row filters commute and repeating an identical filter is
idempotent. SIS sorts and deduplicates these selectors before building a
workflow fingerprint. It **does not** assume any other different programs are
equivalent merely because their outputs matched a finite set of examples.

The original captured events are replayed and retained as evidence; the
normalized program is then re-executed before admission. The original events
are not silently replaced with synthesized steps.

## Workflow JSON

`workflow-capture` takes:

```json
{"data":{"rows":[{"region":"east","amount":5},{"region":"west","amount":10}]},"plan":[{"op":"filter_eq","field":"region","value":"east"},{"op":"sum","field":"amount"}]}
```

It returns a capture with original data, operations, intermediate results,
prior hashes, final result and capture digest. A real agent should call
`WorkflowSession.call()` from the **actual controlled execution boundary**,
not narrate tool outputs in a prompt.

`workflow-study` accepts:

```json
{
  "namespace":"table_demo","promote":true,
  "train_captures":[
    {"capture":"<serialized capture object>","accepted":true,"expected_output":5},
    {"capture":"<another disjoint capture>","accepted":true,"expected_output":8},
    {"capture":"<third disjoint capture>","accepted":true,"expected_output":3}
  ],
  "validation":[
    {"data":{"rows":[{"region":"east","amount":4}]},"expected_output":4},
    {"data":{"rows":[{"region":"east","amount":7}]},"expected_output":7}
  ]
}
```

Values such as `<serialized capture object>` above illustrate structure only.
Generate real captures using the API or included demo. Training/validation
must have identical row schemas and disjoint complete datasets.

Run:

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -p test_v230_workflows.py -v
PYTHONPATH=src python3 tools/demo_tabular_workflow.py
sis --db ./workflows.sqlite3 workflow-study examples/v2_3/workflow_study.json
sis --db ./workflows.sqlite3 workflow-predict examples/v2_3/workflow_predict.json
sis --db ./workflows.sqlite3 workflow-audit
```

HTTP API: POST `/v1/workflows/capture`, `/v1/workflows/study`,
`/v1/workflows/predict`, `/v1/workflows/retire`; GET `/v1/workflows` and
`/v1/workflows/audit`. Operator-only mutation routes require the distinct
admin key when an API key is configured. A locally exposed no-key server
retains the pre-existing trusted-local behavior; do not publicly expose it.

LLM read-only tool: `sis_workflow_predict`. No LLM-facing promotion, capture,
retirement, or direct database access is exposed by `ToolBridge`.

## Security and scientific limits

- Local replay verifies **internal consistency**, not whether a tool run or its
  label represents a real-world success. An attacker controlling the entire
  record can recalculate the unkeyed hashes.
- DB hash-linked audit detects partial corruption. A privileged DB custodian
  can rewrite the entire table and local chain, so independent security
  requires separate signer/custodian and externally anchored receipts.
- Training and validation datasets may be semantically similar even if their
  exact hashes differ. Distinct record hashes do not prove new task families.
- Promotion replays the full study. Locally verified does not imply
  statistically significant or externally validated generalization.
- The new tabular workflow system is **not** compatible with arbitrary
  Python functions, file manipulation, or browsing tools.
- A trained neural adapter and its benefits are not bundled.
