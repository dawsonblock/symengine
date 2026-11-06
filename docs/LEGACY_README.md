# Symbolic Induction Engine (SIS) v3.3.2

**v3.3.2 — authority consistency and runtime closure (M0–M5).** SIS is a
model-independent, bounded symbolic induction service. The v3 stack adds a
governed candidate plane, signed authority checkpoints, evidence custody,
authenticated execution identities, and a durable SQLite/PostgreSQL control
plane for cross-replica serving. The core package has **zero required runtime
dependencies** (Python 3.10+).

**Status: `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.** The M0–M5 authority controls
are implemented and covered by adversarial tests. Evaluator isolation (M6) and
real-agent efficacy (M9) are **not** qualified, and no improvement in real LLM
performance is claimed. See [the efficacy status](docs/V332_EFFICACY_STATUS.md).

## What v3.3.2 adds

- **Shared control plane** (`sis.v3.control_plane`): a signed session nonce is
  consumed and the decision receipt committed in one transaction, so two
  replicas racing with the same identity produce exactly one authorization.
- **Witnessed custody**: authority checkpoints sign `revocation_head`,
  `supersession_head` and `custody_entry_count`; production serving rejects a
  restored pre-revocation custody directory or a deleted revocation log.
- **Authenticated serving boundary** (`sis.v3.serving_service`):
  bearer-authenticated `/v3/guidance` and `/v3/outcome`, with legacy `/v1`
  learning routes isolated by default (`SIS_V3_ONLY=1` forces isolation).
- **Runtime closure**: readiness reporting, exact outcome binding, signed
  dependency links, production isolation gating, and signed SLSA-shaped release
  provenance.

## Install and verify

```bash
python3 -m venv .venv
source .venv/bin/activate              # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'      # pytest 8.4.2; the runtime has no dependencies
python -m pytest tests/ -q
python tools/smoke_integration.py
```

The legacy v2 CLI remains available:

```bash
sis --version
sis --db ./knowledge.sqlite3 train examples/arithmetic_study.json
sis --db ./knowledge.sqlite3 predict examples/predict.json
sis --db ./knowledge.sqlite3 audit
```

The v3 serving boundary is constructed in application code
(`create_server(..., v3_service=...)`); the `sis serve` CLI command exposes only
the legacy `/v1` surface. See [operations](docs/V332_OPERATIONS.md) for the
wiring and deployment profiles.

## Documentation map

| Document | Contents |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | Release-by-release change history |
| [docs/V332_AUTHORITY_CONSISTENCY.md](docs/V332_AUTHORITY_CONSISTENCY.md) | v3.3.2 defects, fixes and evidence |
| [docs/V332_OPERATIONS.md](docs/V332_OPERATIONS.md) | Deployment, recovery and key rotation |
| [docs/V332_ACCEPTANCE_MATRIX.md](docs/V332_ACCEPTANCE_MATRIX.md) | Executed acceptance scenarios |
| [docs/V332_EFFICACY_STATUS.md](docs/V332_EFFICACY_STATUS.md) | What is and is not demonstrated |
| [docs/v3/ARCHITECTURE_V3_3.md](docs/v3/ARCHITECTURE_V3_3.md) | v3 subsystem design |
| [docs/SECURITY_THREAT_MODEL.md](docs/SECURITY_THREAT_MODEL.md) | Adversaries, mitigations and residual risk |

---

# Legacy v2.4.0 documentation

**v2.4.0:** Adds a narrowly scoped **pure Python coding-repair recipe learner**.
It captures proposed arithmetic-operator AST repairs, interprets before/after
behavior against caller-labeled vectors without executing arbitrary Python,
replays captures, generalizes successful single-operator transformations across
different function names, validates on distinct programs, and gates SQLite
promotion and retirement behind operator authority. Read-only agent/HTTP
clients can request an unapplied unified-diff preview. There is **no shell
execution, repository-write capability, real unit-test subprocess sandbox, or
proven improvement in real LLM performance**. See
[the v2.4 guide](docs/V2_4_CODE_REPAIR.md).

For repository updates after the v2.4.0 review, see the [upgrade guide](UPGRADE_README.md).

Run locally: `PYTHONPATH=src python3 tools/demo_code_learning.py`.

---

# Symbolic Induction Engine (SIS) v2.3.0

**v2.3.0:** Adds an independent, bounded *tabular workflow* learner and executor,
with observation-time captures, deterministic replay, conservative canonicalization
of filter reorderings/repetitions, distinct training/validation rows, operator-only
promotion, SQLite persistence, hash-linked local audit, explicit retirement, and
read-only agent/HTTP inference. **No filesystem, shell, code patching, browser or
arbitrary external action execution is permitted.** Learning labels remain
operator-supplied, and generalization to unseen task families is unproven.
See [v2.3 documentation](docs/V2_3_WORKFLOW_LEARNING.md).

Local demo: `PYTHONPATH=src python3 tools/demo_tabular_workflow.py`.

> **v2.2.0:** Introduces execution-boundary capture of allowlisted pure tool calls,
> provenance-aware data-flow reconstruction, replay-checked and hash-linked event
> captures, conservative cross-run procedural abstraction, disjoint evaluation
> inputs, and a governed `experience-induce` route. Captures do not authenticate
> operator ground truth or prove real-model skill transfer. See
> [v2.2 guide](docs/V2_2_EXPERIENCE_ABSTRACTION.md).
>
> Quick local demo: `PYTHONPATH=src python3 tools/demo_experience_capture.py`
> and `sis --db ./v22.sqlite3 experience-induce examples/v2_2/experience_study.json`.
>
> **v2.1.0:** Adds operator-side typed execution-trace learning, per-step
> replay, train-only procedural proposal reconstruction and existing
> evidence-gated promotion. Failed traces never become proposals;
> validation traces are forbidden. See [the v2.1 guide](docs/V2_1_TYPED_TRACE_LEARNING.md).
> **No real-model generalization improvement is claimed.**
>
> Quick local demo: `sis --db ./trace.sqlite3 trace-study examples/trace_study.json`.

> **v2.0.0:** Adds evaluator-controlled family-disjoint qualification of a
> baseline LLM, LLM + frozen symbolic procedures, LoRA-adapted LLM, and optional
> placebo. Signed experiment precommitment, declared split/input collision
> checks, one-use SQLite admission, Holm-adjusted item and family-level tests, and
> macro-by-family accuracy. See [v2.0 guide](docs/V2_0_FAMILY_QUALIFICATION.md).
> **No real neural training or independent task transfer claim is bundled.**
>
> Run synthetic demo: `PYTHONPATH=src python tools/demo_family_eval.py`.

> **v1.9.0:** Optional real LoRA fine-tuning of v1.8 custodian-exported, verified pseudo-labels and a controlled three/four-arm LLM comparison. Training requires separately installed PyTorch/Transformers/PEFT, model weights, and operator approval; no pretrained weights, GPU runs, or independently measured model improvement are bundled. See [v1.9 guide](docs/V1_9_LORA_AND_NEURAL_COMPARISON.md).


**Full runnable research upgrade — local automated regression suite, Python 3.10+, zero required third-party runtime packages.**

**New in v1.8:** frozen and hash-bound active procedural-skill dependency snapshots, an **evaluator-owned one-use sealed holdout** for procedural skills with HMAC-authenticated scoring and exact replay, and guarded pseudo-labeled JSONL export after policy qualification. Does **not** alter model weights or prove independent results without separate evaluator control. See [v1.8 qualification and distillation guide](docs/V1_8_PROCEDURAL_HOLDOUT_AND_DISTILLATION.md).

Local full workflow: `PYTHONPATH=src python tools/demo_skill_holdout.py` (synthetic demonstration, **not** independent evidence).

**New in v1.7:** an additional governed *procedural skill* layer with bounded typed `if`, `let`, `fold` and active-skill `call` expressions, deterministic candidate induction, local validation and abstention, a separately verified SQLite skill log, failure-aware episode ingestion, CLI/HTTP interfaces, and a read-only `sis_skill_predict` agent tool. Full details and evidence limits: [v1.7 guide](docs/V1_7_PROCEDURAL_SKILLS.md). The v1.4 sealed evaluator and v1.6 paired LLM harness have **not** been extended to qualify these procedural skills on independent holdouts. No model weights are changed.

Quick v1.7 demo:

```bash
python3 -m pip install -e .
sis --db ./skills.sqlite3 skill-study examples/skill_sum_study.json
sis --db ./skills.sqlite3 skill-predict examples/skill_sum_predict.json
sis --db ./skills.sqlite3 skill-audit
sis --db ./skills.sqlite3 skill-benchmark examples/skill_sum_benchmark.json
```

**New in v1.6:** paired live comparison of the same LLM with and without a read-only SIS hint, with no labeled target outputs sent in the LLM requests, alternating arm order, strict typed JSON response checking, per-arm model errors and token-use accounting, and exact paired McNemar statistics. No model is bundled or called during automated unit tests. Local synthetic evidence is not independent validation. See [v1.6 paired LLM guide](docs/V1_6_PAIRED_LLM_BENCHMARK.md).

**v1.5:** read-only schema transfer of previously validated source rules, opt-in cross-task predictions labeled unverified, signed precommitted holdout qualification thresholds, Wilson uncertainty bounds, and evaluator-side qualification replay. **A policy pass is not independent task provenance.** See [v1.5 guide](docs/V1_5_TRANSFER_AND_QUALIFICATION.md).

**v1.4 foundation:** a *separate evaluator-owned* one-use sealed holdout harness, HMAC-bound public train/validation manifests, secret test/shifted-test labels held only in an evaluator vault, signed aggregate scoring receipts, and independent score replay by the vault custodian. This mitigates accidental adaptive test reuse **only when the secret, vault and test labels are actually isolated from the candidate developer**. This is **not** a guarantee of independent evaluation by itself. See [v1.4 evaluator guide](docs/EVALUATOR_V1_4.md).

**New in v1.3:** the hash-linked audit verifier now checks rule event transition
semantics, rather than just the final database projection. A bounded admission
firewall refuses rules that contradict existing active rules in the same typed
namespace. Network mutation routes require an independent `SIS_ADMIN_KEY` when
`SIS_API_KEY` is configured. Rule listings fail closed on corrupt audit state,
and feedback rejects mismatched output types. Previous v1.2 controls remain.
See [v1.3 upgrade notes](docs/UPGRADE_V1_3.md).

Minimal demonstration:

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
sis query examples/query.json
sis benchmark examples/benchmark.json
sis --db ./knowledge.sqlite3 train examples/arithmetic_study.json
sis --db ./knowledge.sqlite3 predict examples/predict.json
sis --db ./knowledge.sqlite3 predict-batch examples/predict_batch.json
sis --db ./knowledge.sqlite3 audit
sis --db ./knowledge.sqlite3 anchor-export ./checkpoint-001.json
sis --db ./knowledge.sqlite3 anchor-verify ./checkpoint-001.json
sis tools
PYTHONPATH=src python examples/active_oracle_loop.py   # synthetic controlled ground-truth demo
```

## Agent integration with any LLM

The model only needs the ability to call your application's Python functions or
JSON-over-HTTP endpoints. The built-in chat/proposal convenience client targets
OpenAI-compatible `/chat/completions` APIs; other model providers can be connected
using their own client SDK and the adapter below:

```python
from sis.service import Service
from sis.bridge import ToolBridge

service = Service("knowledge.sqlite3")
bridge = ToolBridge(service)
model_tool_definitions = bridge.tools()  # provide to your model's tool-calling API
# Upon a model tool call, use its name and JSON arguments:
result = bridge.invoke("sis_predict", '{"namespace":"arithmetic_demo","inputs":{"a":7,"b":8}}')
print(result)
service.registry.close()
```

Only prediction, read-only rule transfer, and unlabeled question suggestion are available to model tool calls.
**LLMs cannot promote rules, retire them, invent accepted ground truth, or change
stored evidence through `ToolBridge`.** For controlled learning, call
`Service.study(...)` in your own trusted application code after collecting
independently labeled training and validation records. `Service.query(...)` suggests
informative experiments; obtain the labels outside the candidate system.

**Important upgrade compatibility:** existing v1.0 SQLite databases contain
insufficient audit projection information for the stronger verifier. Back up old
DBs and revalidate/retrain into a new v1.1 DB. Predictions on old unverifiable
history intentionally abstain. v1.1 databases that pass existing projection checks
remain readable in v1.2. See the upgrade notes for details.

---

An installable, **model-agnostic** symbolic reasoning service. It discovers *bounded, typed, declarative* rules from examples; looks for alternatives and counterexamples; evaluates a pre-declared validation set; stores qualifying rules in SQLite; and can reuse those rules from a Python API, HTTP API, CLI, or opt-in OpenAI-compatible LLM integration.

**This is an executable research prototype**, not a system that turns every LLM into an AGI, updates neural weights, or establishes symbolic proofs of real-world hypotheses. Its capability is intentionally limited to supported rule families. It does **not** autonomously crawl your files, run arbitrary code, trade money, or call an external LLM by default.

## 1. Setup — Python 3.10+

```bash
# From a checkout of this repository:
python3 -m venv .venv
source .venv/bin/activate              # macOS / Linux
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
```

Core runtime has **zero third-party dependencies**. Install `python -m pip install -e '.[z3]'` only if you want the optional integer-domain Z3 counterexample search. No Z3 runtime results are included in the release test claim unless you run tests with Z3 installed.

## 2. Learn a rule from examples

```bash
sis --db ./knowledge.sqlite3 train examples/arithmetic_study.json
sis --db ./knowledge.sqlite3 predict examples/predict.json
sis --db ./knowledge.sqlite3 rules --namespace arithmetic_demo
sis --db ./knowledge.sqlite3 predict-batch examples/predict_batch.json
sis --db ./knowledge.sqlite3 audit
```

Expected rule (actual acceptance depends on tests): `output = a + b`. The supplied example includes five training cases and three separately supplied validation cases. `promote: true` stores the rule only when the induction service labels it `locally_validated`, it is not ambiguous within its searched hypotheses and probes, and the search was not truncated.

Sequence-pattern example:

```bash
sis --db ./knowledge.sqlite3 train examples/sequence_study.json
```

Ambiguity rejection example:

```bash
sis --db ./knowledge.sqlite3 train examples/ambiguous_study.json
```

When `a` always equals `b`, the data do not establish which one should determine the output. SIS generates a distinguishing input and refuses promotion. Collect its **true label from the actual task**, move that *newly labeled* example to a future training set, and reserve an entirely fresh validation set. A synthetic query by itself is NOT evidence of the correct answer.

## 3. Local HTTP service

```bash
sis --db ./knowledge.sqlite3 serve --host 127.0.0.1 --port 8765
```

Endpoints: `GET /health`, `GET /v1/tools`, `GET /v1/rules`, `GET /v1/audit`, `POST /v1/induce`, `POST /v1/predict`, `POST /v1/predict-batch`, `POST /v1/transfer`, `POST /v1/transfer-batch`, `POST /v1/query`, `POST /v1/benchmark`, `POST /v1/feedback`, `POST /v1/retire`, and `POST /v1/chat`.

```bash
curl -sS -X POST http://127.0.0.1:8765/v1/induce \
  -H 'Content-Type: application/json' \
  --data-binary @examples/arithmetic_study.json
curl -sS -X POST http://127.0.0.1:8765/v1/predict \
  -H 'Content-Type: application/json' \
  --data-binary @examples/predict.json
```

By default, server binds loopback only. For non-loopback bind `SIS_API_KEY` is mandatory; any configured API key must be at least 24 UTF-8 bytes. HTTPS/TLS at an authenticated reverse proxy is **also** required for confidentiality on a real network. `X-SIS-Key` carries the read/prediction API key. When an API key is set, operator mutations (`/v1/induce`, `/v1/feedback`, `/v1/retire`, `/v1/chat`) are **disabled** unless a separate `SIS_ADMIN_KEY` (at least 24 bytes) is set and passed via `X-SIS-Admin-Key`. The two secrets must differ. On loopback with neither key configured, developer-mode mutations remain available. The included server does not implement rate limiting, tenant isolation, distributed authorization, or network TLS itself; do not expose this demonstration server to the public internet.

## 4. Add to a small or large LLM

SIS is an **external tool/service**. It works with a locally deployed LLM or any hosted model whose agent framework can call local Python or HTTPS endpoints. The bundled convenience adapter directly supports **OpenAI-compatible** `/chat/completions` URLs (e.g., model servers, compatible gateways). Other proprietary LLM APIs require a gateway or a provider-specific adapter; they are not falsely claimed as native implementations.

For a compatible local server:

```bash
export SIS_ENABLE_LLM=1
export SIS_LLM_URL='http://127.0.0.1:1234/v1/chat/completions'
export SIS_LLM_MODEL='your-installed-model'
# export SIS_LLM_API_KEY='your-secret'  # Only if required.

# Explicit LLM-assisted AST proposal: TRAINING EXAMPLES ARE SENT TO CONFIGURED ENDPOINT.
sis --db ./knowledge.sqlite3 train examples/arithmetic_study.json --use-llm

# Model explains a separately validated rule prediction (data may be sent externally).
sis --db ./knowledge.sqlite3 chat examples/chat.json
```

`SIS_LLM_URL` must be HTTPS or HTTP on localhost. SIS does not automatically transmit any data to a model without an explicit `--use-llm`, `use_llm: true`, or chat request and an enabled model integration. It never gives model suggestions permission to execute code or bypass verification.

For application integration:

```python
from sis.service import Service

service = Service('knowledge.sqlite3')
result = service.study({
    'namespace': 'my_task',
    'train': [
        {'inputs': {'x': 1, 'y': 4}, 'output': 5},
        {'inputs': {'x': 2, 'y': 7}, 'output': 9},
        {'inputs': {'x': -3, 'y': 5}, 'output': 2}
    ],
    'validation': [
        {'inputs': {'x': 4, 'y': 9}, 'output': 13},
        {'inputs': {'x': -4, 'y': -6}, 'output': -10}
    ],
    'promote': True
})
print(result['status'])
print(service.predict({'namespace':'my_task', 'inputs': {'x': 10, 'y': 12}}))
service.registry.close()
```

## 5. Evidence policy

- Induction uses only `train`. Validation is not sent to an LLM, used to select a competing rule, or consulted for re-fitting; it is evaluated on the selected hypothesis only.
- Training inputs must be unique. Validation inputs must be distinct from each other and from training inputs. At least **3 train + 2 validation** examples are necessary for promotion, but are not sufficient to establish meaningful generalization beyond them.
- Generated probes are *unlabeled hypothetical inputs*. They help find disagreement, not determine which rule is correct.
- `locally_validated` means the current rule matched provided local validation examples and survived the implemented ambiguity checks; **no external independent holdout or mathematical generalization proof** is implied.
- An incomplete search, empirical ambiguity, failed validation, or missing validation results in abstention/rejection.
- SQLite events have a hash-linked, integrity-checkable sequence. The optional **operator-held audit checkpoint** can detect rewritten/truncated history **only if its file (and HMAC key, if used) is independently protected**. Exporting and verifying a checkpoint on the same compromised computer does not establish independent cryptographic authority. See `docs/SECURITY.md`.

## 6. Test and reproduce

```bash
python -m unittest discover -s tests -v
python tools/evaluate_fixtures.py
python tools/smoke_integration.py
python tools/build_release.py
```

`tools/evaluate_fixtures.py` exercises **local synthetic demonstration tasks**, not a third-party benchmark. See `docs/EVALUATION.md` for a valid independent evaluation design and `docs/ARCHITECTURE.md` for interfaces, rule grammar, known limits and upgrades.

## 7. Paired live LLM A/B evaluation (v1.6)

Promote a rule using disjoint training and validation data before evaluating a fresh task set:

```bash
sis --db ./study.sqlite3 train examples/arithmetic_study.json
export SIS_ENABLE_LLM=1
export SIS_LLM_URL='http://127.0.0.1:1234/v1/chat/completions'
export SIS_LLM_MODEL='your-exact-model-id'
sis --db ./study.sqlite3 paired-eval examples/paired_eval_synthetic.json ./paired_result.json --allow-network
```

This makes **60 LLM calls** for the included 30-row *synthetic* example (30 baseline, 30 SIS-assisted). It will incur inference compute/provider costs; the examples are for verifying the workflow, not claiming improved intelligence. Two explicit authorization steps are required for outgoing requests. Baseline and SIS-assisted are the **same LLM** and use the same decoding settings, but SIS hints increase prompt tokens. See [the full v1.6 design and evaluation caveats](docs/V1_6_PAIRED_LLM_BENCHMARK.md).

## 8. Current boundaries

Only bounded integers, booleans, short strings, and fixed-length lists of these are accepted. The grammar supports feature references, indexed references, constants, addition, subtraction, multiplication, absolute difference, min/max, equality, negation, absolute value, case changes, string reverse, and LLM-proposed conditional equality. The deterministic search enumerates simple unary/binary rules first and bounded two-stage arithmetic rules if none of the simple ones fit. It does not learn general programs, recursive algorithms, unbounded formulas, image representations, causal mechanisms, or neural model weights.

See `docs/LIMITATIONS.md` and `docs/ROADMAP.md` before extending this to untrusted users or consequential decisions.

## 9. v1.2: Secure promotion and out-of-band audit checkpoint

`Registry.promote(result)` now refuses promotion unless the original training and
validation examples and matching induction options are passed as keyword arguments.
The registry independently reruns induction and requires *byte-equivalent canonical*
result metadata. This is deliberately redundant to prevent forged promotion results
from direct Python callers; it roughly doubles rule-induction work on promotion.
Use `Service.study(...)` for normal promotion; it supplies the records internally.
It remains your responsibility to establish ground-truth label provenance.

Export an append-only checkpoint after selecting a trusted state:

```bash
# Optional: configure a high-entropy HMAC key using your secrets manager,
# stored OUTSIDE the SQLite database and checkpoint file.
export SIS_ANCHOR_HMAC_KEY='replace-with-a-random-secret-of-at-least-32-bytes'
sis --db ./knowledge.sqlite3 anchor-export ./anchor-001.json
sis --db ./knowledge.sqlite3 anchor-verify ./anchor-001.json
```

`anchor-export` refuses to overwrite a previous checkpoint. Move the resulting
checkpoint to separately protected storage. `anchor-verify` checks the authenticated
checkpoint against the validated audit **prefix**: later legitimate audit events do
not invalidate the old checkpoint. **No automatic timestamp, remote witness,
independent signature authority, hardware security boundary, or secret protection**
is supplied by this prototype. Unkeyed anchors are only as trustworthy as their
external custody. The checkpoint file contains no raw training examples.

`predict-batch` reads 1–64 input objects from a single JSON request and preserves
per-item predictions or abstentions; invalid requests fail before evaluation.
The model tool bridge remains deliberately read-only.

## 10. v1.3: bounded admission firewall and operator key

For an authenticated loopback server:

```bash
export SIS_API_KEY='replace-with-a-prediction-token'
export SIS_ADMIN_KEY='replace-with-a-separate-operator-secret-24-bytes-or-longer'
sis --db ./knowledge.sqlite3 serve
```

Clients must send `X-SIS-Key` to query or predict; mutation calls additionally
send `X-SIS-Admin-Key`. When `SIS_API_KEY` is configured but no admin key is
configured, all operator routes return HTTP 403 by design. In the no-key local
development mode, mutation endpoints remain accessible on loopback: anyone
with local network access to the bound port may mutate its database.

The new conflict screen checks train/validation inputs and up to 256 deterministic
unlabeled probes for disagreement between a candidate and existing **active**
rules with an identical schema and namespace. It rejects the *new* promotion
on the first witness. It does not establish mathematical equivalence of admitted
rules and does not automatically reconcile task-specific domains. Retire a stale
rule under operator control before intentionally changing its meaning.

Hash-linked audit replay also checks promotion, feedback and retirement state
transitions and immutable fields. It catches some internally coherent forgeries,
**not** full-history rewriting by someone who can rewrite the database and
its independently unanchored audit. Preserve operator-held checkpoints.

## 11. v1.4: one-use evaluator-controlled holdout

For a **local synthetic demonstration**, run `python3 tools/generate_eval_demo.py /tmp/sis-eval-demo` to generate an example private dataset. Do not mistake generated
examples or locally controlled secrets for independent evaluation.

Evaluator-only terminal (the secret and vault must not be accessible to the candidate):

```bash
export SIS_EVAL_HMAC_KEY='replace-with-a-long-random-secret-from-your-secret-manager'
sis eval-seal /tmp/sis-eval-demo/dataset.json /tmp/sis-eval-demo/public.json \
  --vault /tmp/sis-eval-demo/evaluator.sqlite3
```

Candidate-only terminal (only the public task is provided):

```bash
sis eval-candidate /tmp/sis-eval-demo/public.json /tmp/sis-eval-demo/submission.json
```

Evaluator-only terminal (exactly one **valid** submission is scored):

```bash
sis eval-score /tmp/sis-eval-demo/public.json /tmp/sis-eval-demo/submission.json \
  --vault /tmp/sis-eval-demo/evaluator.sqlite3 \
  --receipt /tmp/sis-eval-demo/receipt.json
sis eval-verify /tmp/sis-eval-demo/public.json /tmp/sis-eval-demo/receipt.json \
  --vault /tmp/sis-eval-demo/evaluator.sqlite3
```

The `shifted_test` partition is optional and reports accuracy on deliberately
different input ranges separately from the ordinary holdout. These are 
**sample-level** generalization checks, not held-out task-family transfer.
A caller who owns the vault and knows the evaluator secret can reset the holdout;
separate evaluator custody, protected backups, and sealed receipts external to
the dev environment are prerequisites for credible independent qualification.
The regular `sis benchmark` command is unchanged.

## v1.5: transfer and qualification (research use)

- Transfer a rule without creating or promoting a target rule: `sis --db knowledge.sqlite3 transfer examples/transfer.json` after replacing the example's source `rule_id` with an actual promoted ID.
- Optional transfer-batch: `sis --db knowledge.sqlite3 transfer-batch examples/transfer_batch.json`. The tool bridge offers `sis_transfer`, read-only.
- Precommitted post-score qualification: `sis eval-qualify PUBLIC RECEIPT --vault VAULT --qualification OUTPUT`. Verify with `sis eval-verify-qualification PUBLIC RECEIPT OUTPUT --vault VAULT`.
- See [full guide](docs/V1_5_TRANSFER_AND_QUALIFICATION.md). Qualification is evaluator-dependent; local generated examples do not demonstrate independent generalization.
