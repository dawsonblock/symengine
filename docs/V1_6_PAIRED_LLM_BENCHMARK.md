# v1.6: Controlled paired LLM comparison

## Research purpose

The new command compares the **same configured OpenAI-compatible model** in two conditions on the same structured inputs:

- **baseline:** only the typed task inputs, common fixed system prompt, temperature 0, bounded output length;
- **augmented:** identical model/settings/task, plus a **read-only** SIS prediction from a previously promoted rule (or an explicit `unavailable` status).

It makes **two requests per example**, counterbalanced AB/BA by row index. No online rule induction, registry writes, model fine-tuning, or label-derived prompt changes occur during the evaluation. It neither searches for the best prompt nor gives the baseline artificial access to extra context. Token budgets are **not** equalized: the extra SIS hint costs prompt tokens; the measured token counts help quantify this cost. If the provider does not return token usage, those metrics are null.

Input labels are processed **locally** for scoring and are never intentionally placed into outbound model messages. Some locally learned SIS predictions may coincide with the gold label, by design. The run stores no raw LLM completions or label values in the result file, but individual correctness indicators and digests can still disclose information. Treat both the dataset and the result as sensitive.

## Prerequisites

1. Run `python3 -m pip install -e .` and `python3 -m unittest discover -s tests`.
2. Promote a rule using **training and validation only**, independent of the later paired test rows:

```bash
sis --db ./study.sqlite3 train examples/arithmetic_study.json
```

3. Prepare a **new** `dataset.json` with a distinct `task_id`, the same `namespace`, and 2–256 labeled cases, all of the same typed schema, with distinct inputs. Example:

```json
{
  "task_id": "arithmetic_synthetic_only",
  "namespace": "arithmetic_demo",
  "max_tokens": 128,
  "cases": [
    {"inputs": {"a": 12, "b": 8}, "output": 20},
    {"inputs": {"a": -11, "b": 5}, "output": -6}
  ]
}
```

`examples/paired_eval_synthetic.json` contains **synthetic task rows** for exercising the workflow and is **not an independent benchmark**. Source and target task distribution overlap substantially.

## Real configured LLM call: explicit two-part opt-in

```bash
export SIS_ENABLE_LLM=1
export SIS_LLM_URL='http://127.0.0.1:1234/v1/chat/completions'
export SIS_LLM_MODEL='YOUR_MODEL_NAME'
# export SIS_LLM_API_KEY='SECRET'  # if required
sis --db ./study.sqlite3 paired-eval examples/paired_eval_synthetic.json ./paired_result.json --allow-network
```

- **No network calls occur until both** `SIS_ENABLE_LLM=1` and `--allow-network` are present.
- The program refuses to overwrite an existing result file, although remote calls may still have occurred before a local filesystem error (e.g. racing writer). Do not rerun a completed test on the same private dataset to pick a successful variant.
- Real runs may incur provider costs; the program makes exactly `2 × number of examples` model requests, unless an early error interrupts it.
- Only OpenAI-compatible `/chat/completions` responses are implemented directly. Provider-specific APIs require your own adapter implementing `complete(...)` or `complete_with_metadata(...)`.
- HTTP is permitted only for `localhost` endpoints; non-local endpoints must be HTTPS. No redirects are followed by the adapter.
- The runner is deliberately an **operator CLI** rather than a model-accessible mutation or scoring tool.

## Outcome interpretation

Reported metrics include per-arm overall exact-match accuracy, answer coverage, provider failure counts, invalid response counts, Wilson lower bounds (95%), elapsed request time, and provider-reported prompt/completion token totals when available. Paired comparison reports four outcome cells, absolute accuracy difference, and a **two-sided exact McNemar test** of the discordant paired correctness indicators. Missing answers and malformed JSON count as wrong for overall accuracy. A provider error invalidates the entire run (other scores are diagnostic only).

**McNemar assumptions and caveats:** each row pair shares the same label but rows may be correlated; significance calculations assume effectively independent rows. Neither a small nominal p-value nor a high Wilson bound proves external validity or improved general intelligence. If the dataset or prompt was tuned through repeated experiments, uncertainty intervals and nominal p-values no longer have their simple confirmatory interpretation. The output explicitly labels itself descriptive, not independently qualified.

## Highest-priority follow-up

Ask a separately controlled evaluator to preregister the exact model checkpoint, sample and generation settings, domain/task families, sample sizes, baseline choices, exclusion criteria, token-cost threshold, and primary significance criterion. The evaluator should own fresh untouched labels and separately control one-use access and signing. Add a prompt-budget-matched placebo arm and a retrieval-only arm to isolate the effect of genuinely induced rules from providing any answer as extra context. Use new tasks, not handpicked arithmetic fixtures, to measure out-of-distribution accuracy.

## API

```python
from sis.paired_eval import run_paired
from sis.service import Service
from sis.model import CompatibleLLM

with_labels = {...}  # caller-only; do not give raw dict to an LLM
service = Service('study.sqlite3')
try:
    result = run_paired(with_labels, CompatibleLLM(), service, model_label='actual-model-identifier')
finally:
    service.registry.close()
```

The output contains a `case_digest` binding the examples and `frozen_registry_digest` binding active rule metadata at runtime, but **neither is a public cryptographic attestation of genuine experimental independence**. Because the actual task labels are private, only the data custodian can replay correctness. The registry is checked before and during the run for integrity and drift; if it changes, the run aborts.
