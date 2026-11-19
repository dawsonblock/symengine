# v1.5: Schema transfer and precommitted qualification

## Architecture and assurance boundaries

SIS v1.5 adds two **deliberately separate** capabilities:

1. **Explicit schema-mapped transfer:** apply one active source rule under a manually supplied one-to-one field-name map. Identical source/target field types, list element types and lengths are required. A transferred prediction is labeled `unvalidated_target_hypothesis`: target generalization **is not verified** just because the source rule passed its original training/validation split. Transfer does not create or modify registry rules.
2. **Precommitted evaluator policy:** before sealing, the evaluator records its qualification thresholds in the signed public study. After one-use score, the evaluator separately replays the hidden test labels and produces a signed policy-relative qualification artifact. Source code cannot verify independent authorship or custody of the hidden data; **policy pass is not independent validation**.

No Python `eval`/`exec` of LLM text or other untrusted code has been introduced.

## Read-only transfer

First, train/promote a source rule:

```bash
sis --db ./knowledge.sqlite3 train examples/arithmetic_study.json
```

Copy the `promotion.id` SHA-256 string into `examples/transfer.json` (`rule_id`). This is explicit because choosing a wrong source rule automatically would silently cross trust boundaries.

```bash
sis --db ./knowledge.sqlite3 transfer examples/transfer.json
sis --db ./knowledge.sqlite3 transfer-batch examples/transfer_batch.json
```

Equivalent API: `Service.transfer(request)` and `Service.transfer_batch(request)`, `POST /v1/transfer`, `POST /v1/transfer-batch`; the read-only tool bridge exposes `sis_transfer`. No external model is required.

The transfer mapping is **operator supplied**; matching field *types* do not establish matching *semantics*. Never promote target rules based solely on transferred predictions. Obtain separate independently labeled target training and validation data before any target-domain rule promotion.

## Frozen evaluator qualification policy

Default policy attached at `eval-seal`:

```json
{
  "min_test": 30,
  "min_shifted": 30,
  "min_coverage": 0.95,
  "min_overall_accuracy": 0.80,
  "min_wilson_lower": 0.65,
  "min_baseline_gain": 0.05
}
```

An evaluator may supply a complete `qualification_policy` object in the **private dataset JSON**, but must fix it *before sealing*. Software refuses policies with fewer than 30 examples per test domain. `min_wilson_lower` is a two-sided 95% Wilson binomial lower bound for **overall accuracy** (counting abstentions as unsuccessful). Because accuracy and baseline share labels, `min_baseline_gain` is a *descriptive threshold*, **not** a paired significance test. Repeated selection of policies or candidate variants against a test set invalidates ordinary uncertainty interpretations. Qualified status means **only that the stated, signed thresholds were met**.

For a **synthetic demonstration only**:

```bash
python3 tools/generate_qualification_demo.py /tmp/sis-v15-demo
export SIS_EVAL_HMAC_KEY='replace-with-a-private-32-byte-minimum-random-secret'
sis eval-seal /tmp/sis-v15-demo/dataset.json /tmp/sis-v15-demo/public.json --vault /tmp/sis-v15-demo/vault.sqlite3
sis eval-candidate /tmp/sis-v15-demo/public.json /tmp/sis-v15-demo/submission.json
sis eval-score /tmp/sis-v15-demo/public.json /tmp/sis-v15-demo/submission.json --vault /tmp/sis-v15-demo/vault.sqlite3 --receipt /tmp/sis-v15-demo/receipt.json
sis eval-qualify /tmp/sis-v15-demo/public.json /tmp/sis-v15-demo/receipt.json --vault /tmp/sis-v15-demo/vault.sqlite3 --qualification /tmp/sis-v15-demo/qualification.json
sis eval-verify-qualification /tmp/sis-v15-demo/public.json /tmp/sis-v15-demo/receipt.json /tmp/sis-v15-demo/qualification.json --vault /tmp/sis-v15-demo/vault.sqlite3
```

This vault is a local SQLite file. Strong evaluator separation requires different external principals, independent task generation, blinded labels, independent secret custody, and anti-rollback controls external to SIS. HMAC uses symmetric evaluator-held secrets and **does not** provide third-party signature verification to observers without that secret. For genuine public verifiability, an external verifier with asymmetric signing is required.

## Compatibility

- Existing v1.4 SQLite rule registry files are supported without migration; `transfer` performs read-only queries.
- Existing v1.4 evaluator tasks still score/verify with their original signed public study; `eval-qualify` marks them **unqualified** because a qualification policy was not committed before scoring.
- All new v1.5 sealed public studies include `qualification_policy`, even when the default is selected.
- All procedures are locally tested, **not** independently evaluated.

## Recommended research protocol

Preregister hypotheses, budgets, candidate selection and the evaluation policy; have an external evaluator create new task families from disjoint templates. Compare source-model-only, source+SIS, and model+equivalent retrieval baselines at matched token/cost/latency budgets. Test transfer against new semantic domains and require independent human review of ambiguous labels. Only then claim generalized reasoning improvement.
