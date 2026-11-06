# v1.9 — Local LoRA training and controlled neural comparison

## What changed

v1.9 introduces `sis.neural_training` and `sis.neural_eval`, adds two CLI commands, and preserves v1.0–v1.8. The training implementation is opt-in and uses **PyTorch, Transformers, and PEFT**. The package installs and the default test suite run without those heavyweight dependencies. `neural-train` without `--execute` validates inputs and produces a plan but does not load weights or allocate a GPU. With `--execute`, it actually calls `Trainer.train()`, saves a PEFT adapter and tokenizer, and writes an SHA-256-based local training receipt. **This release does not bundle pretrained weights, adapters, GPUs, a model-serving stack, or external training results.** The optional training runtime is not exercised by the dependency-free regression suite; installing matching model checkpoints/hardware and completing a real training run remain operator responsibilities.

### Source and trust boundaries

- The **evaluator custodian** separately controls v1.8's vault, sealed private holdouts, HMAC key, and exported training corpus. The checksum binds the training bytes; HMAC verification authenticates the manifest only while the key is under independent custody. Sharing the evaluator secret with an untrusted training worker compromises that separation. For production, verify the export in a trusted process and pass data through a separately authorized artifact-signing channel. **HMAC is not a public-key signature.**
- Exported chat rows are strictly parsed (system/user/assistant, namespace and schema, canonical JSON, 256-unique-example bound). Malformed and tampered exports are rejected. Training data are **pseudo-labels produced by a previously frozen symbolic program**, not human-supervised ground truth. They may contain systematic mistakes.
- Neural training is a separate, explicitly approved operation: no automatic skill promotion, registry modification, adapter deployment, or inference endpoint changes. Outputs must be in a fresh directory.
- `trust_remote_code=False` and offline model loading are defaults. Set `allow_download=true` only when you expressly accept fetching weights/configuration from an external model repository. Carefully pin the underlying base model revision and independently audit downloaded model files; this code does not enforce immutable remote model revisions.
- The optimizer changes only PEFT LoRA parameters; system and user prompt tokens are masked (`-100`) in the LM loss. Unsupported tokenizer chat templates, sequences exceeding `max_length`, and mismatched chat prompt prefixes **fail closed** rather than silently truncating the target.
- The base model's inference endpoint must be configured separately from an adapted model's serving endpoint for evaluation. SIS does **not** start a server and does not silently merge the adapter into base weights.

### Requirements

Python 3.10+ and sufficient CPU/GPU/RAM for the chosen checkpoint. To enable the training runner:

```bash
pip install -e '.[training]'
```

The optional dependency versions are specified in `pyproject.toml`. Actual runtime use requires a compatible Transformers/PEFT installation and a tokenizer with a reliable chat template. Models using other module names than `q_proj` and `v_proj` require adjusting the config. Avoid treating 256 synthetic examples as sufficient to teach a robust general skill.

### Workflow

1. Follow `docs/V1_8_PROCEDURAL_HOLDOUT_AND_DISTILLATION.md` to freeze a procedural skill, seal evaluator-controlled holdouts, score once, verify, and export a **disjoint** pseudo-labeled JSONL plus its HMAC manifest.
2. Copy `examples/neural_training_config.json`, choose a **pinned local** model checkpoint, valid model-specific LoRA target modules and a fresh output folder. Run validation first:

```bash
# Only in an evaluator-controlled environment with access to the v1.8 secret:
export SIS_EVAL_HMAC_KEY='replace-with-32-plus-byte-custodian-secret'
sis neural-train /secure/labels.jsonl /secure/labels.jsonl.manifest.json \
    my-config.json
```

3. Explicitly opt in to weight updates:

```bash
sis neural-train /secure/labels.jsonl /secure/labels.jsonl.manifest.json \
    my-config.json --execute
```

Without access to the evaluator HMAC key you may use `--allow-unverified-export` only for **unauthenticated local demos**; this bypasses proof of export origin and is inappropriate for trusted training runs. Do not put evaluator secrets on shared worker nodes. Adapter output contains `adapter/`, a local training receipt and potentially training logs; a failed run leaves a `TRAINING_FAILED` marker and must not be deployed.

4. Serve the **base** model and **same-base-plus-adapter** model using two independently labeled OpenAI-compatible chat-completions endpoints. For a read-only local experiment, configure the base endpoint using `SIS_LLM_URL` and `SIS_LLM_MODEL`; pass the adapted endpoint explicitly. Use independent, untouched test examples plus all known training inputs in `excluded_inputs`:

```bash
export SIS_LLM_URL='http://127.0.0.1:8000/v1/chat/completions'
export SIS_LLM_MODEL='my-base-model'
sis neural-eval private-eval.json frozen-bundle.json neural-results.json \
    --distilled-url 'http://127.0.0.1:8001/v1/chat/completions' \
    --distilled-model 'my-adapted-model' --allow-network
```

`examples/neural_eval_template.json` is schema documentation, **not an independent holdout**. Include a plain-language `task_description` that states the deterministic transformation; it is sent with each unlabeled input so the model knows what to compute. Do not reuse the sealed holdouts to optimize the model: training decisions and hyperparameters must be fixed before final evaluation. The 4th `placebo` arm is optional; it receives an explicit `unavailable` SIS hint as an additional prompt-context control.

### What the results can and cannot mean

- Arms: `baseline` (base LLM), `symbolic` (base LLM + frozen skill prediction), `distilled` (fine-tuned LLM), and optionally `placebo` (base LLM + unavailable hint).
- The evaluator reports correct/answered/error counts, accuracy, Wilson lower bounds, latency, provider-reported tokens where present, and paired exact McNemar statistics versus baseline. Model errors invalidate the run instead of being silently scored as ordinary mistakes.
- All gold labels remain local to the evaluator process and are never put into the model prompts. Published output contains only aggregates and a commitment to the test set/order. This does not prevent external providers from logging the unlabeled inputs; use local inference when privacy matters.
- An improvement **does not prove** general intelligence or even symbolic induction causality. The augmented prompt contains extra signal and potentially extra tokens. The placebo is not exact token matched. Confirm on independently gathered task-family holdouts, prompt/token-matched retrieval baselines, fresh random seeds, and repeated different domains. Paired p-values are descriptive if cases are correlated, cherry-picked, or adaptively reused; there is no multiple-comparison correction.
- The same model weights/revision should be used in baseline and adapted conditions. Version-controlled external checkpoints, datasets, hardware, deterministic execution, and external assessor control are required for a scientifically credible result. A hash of an adapter directory is not a full reproducibility certificate.

### Local, offline verification

```bash
python -m unittest discover -s tests -v
python tools/demo_neural_comparison.py
```

The demo uses fake clients and synthetic data. It tests orchestration only. It does not download, fine-tune or benchmark a real model.
