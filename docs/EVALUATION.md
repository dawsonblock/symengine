# Reproducible evaluation and holdout discipline

> For v3 evaluation certificates, the sealed evaluator protocol and the
> real-agent gate, see `docs/EVALUATION_CERTIFICATES.md`,
> `docs/EVALUATION_PROTOCOL.md` and `docs/V332_EFFICACY_STATUS.md`.

The bundled fixture tests demonstrate code behavior only. Passing them does not show an advantage over a baseline LLM, much less human-like learning.

## Benchmark protocol (recommended)

1. Select at least three disjoint task families: symbolic sequences, arithmetic transformations, and simple conditional programs. Hold out **task templates**, not merely random values, for transfer evaluation.
2. Freeze the system build, model checkpoint, candidate grammar, prompt, random seeds, compute budget, and maximum proposals before observing test results.
3. For each task, maintain a discovery/training set, an *internal local* validation set used only to qualify the selected hypothesis, and a **separately controlled never-seen external holdout**. Do not recycle previous holdout inputs.
4. Use identical task information and inference-token/time limits across (a) base small LLM alone, (b) same LLM + retrieval only, (c) same LLM + SIS, and (d) a simple enumerative rule baseline without LLM.
5. Count abstention and wrong confident predictions separately. Record accuracy conditioned on answers, coverage, overall success, search cost, latency, API costs, sample efficiency, and calibration.
6. Run multiple independent trials, report uncertainty intervals, all selection attempts, failure categories, and data contamination checks.
7. If a rule fails externally, never tune against that same holdout. Quarantine it and collect a new independently controlled test split after revising the method.
8. For consequential use, independently reproduce results on a second machine and with externally generated test cases.

## Quantities worth reporting

- Training fit rate versus fresh holdout generalization accuracy.
- False promotion rate: promoted rules that fail independently labeled external tasks.
- Appropriate abstention: coverage-risk curves.
- Rule reuse efficacy on structurally related tasks, without leaking data across splits.
- Search candidates and LLM calls per valid discovery; wall-clock latency and cost.
- Robustness to adversarial, contradictory, poisoned, and distribution-shifted examples.

## Bundled evidence

The local unit tests assert specified behavior. `tools/evaluate_fixtures.py` reruns only bundled artificial examples and prints output explicitly labeled `local_synthetic_demo`. No external evaluator, third-party dataset, independent holdout or statistical transfer study is bundled.

## v1.1 command-line benchmark (synthetic local data only)

```bash
sis benchmark examples/benchmark.json
sis query examples/query.json
```

The evaluator checks input-level split disjointness and output type consistency. It
reports accuracy, coverage, selective accuracy, and the majority-value baseline
computed solely from training outputs. It never stores the test labels, promotes
a rule, or reveals the test split to the induction function. It **cannot** verify
that a researcher/model has not previously seen or adaptively reused the same
caller-supplied test data. An independent evaluation requires external authority.
