# Prioritized technical roadmap

> The v3 gates and remaining work are tracked in `docs/v3/G1_GATE_REPORT.md`
> through `G4_GATE_REPORT.md`, `docs/v3/V32_GAP_MAP.md`,
> `docs/V332_ACCEPTANCE_MATRIX.md` and `docs/v3/V33_LIMITATIONS.md`.

## v1.5 implemented (but not externally qualified)

- Read-only, manually schema-mapped source-rule transfer across task vocabularies.
- Precommitted evaluator policy with minimum test sizes, uncertainty screening, and signed replayable local qualification.

## P0 — Experimental validity (before claims of superior intelligence)

- Build hidden-template external task generator with evaluator-controlled labels.
- Pre-register baselines and answer/abstention thresholds.
- Benchmark actual compute/time/token budgets versus small-LLM and deterministic-only baselines.
- Add external attestations for immutable training/test partition provenance.

## P1 — Larger DSL, safer induction

- Introduce explicit types, rewrite rules, full Boolean predicate search, quantified and recursive hypotheses under resource budgets.
- Add ambiguity witness generation via Z3 plus domain-specific constraints, with an independent oracle for labeling witnesses.
- Replace shallow enumeration with cost-guided, observationally deduplicated synthesis and counterexample-guided inductive synthesis (CEGIS).

## P2 — Agent integration and governance

- Standardized callable tool schema across model hosts, including native Anthropic/Gemini adapters only if required.
- Durable workflow state machine, versioned rule scopes, human approval roles beyond the HTTP operator shared-secret gate, and replayable approvals.
- Ground-truth feedback ingestion with provenance signatures and separated operator/reviewer privileges.
- Signed external audit head anchored outside the database; production IAM and API security review.

## P3 — Demonstrated learned skill reuse

- Track task families, transfer to held-out task templates, non-stationarity and drift.
- Distill demonstrably useful verified rules as synthetic training signals, then compare a LoRA-trained small model against an equivalent context-retrieval baseline under matched budgets.
- Do not promote an adaptive algorithm to autonomous authority until it passes independent holdouts and misuse tests.

## v1.6 follow-on verification gates

- Independently preregister and execute a frozen same-model comparison on novel task families; no repeated holdout tuning.
- Run an answer-length/prompt-token-matched placebo arm and a retrieval-only baseline; control for extra context.
- Verify rule transfer on truly separate domains, including adversarial negative-transfer cases.
- Test provider stability and input/schema hygiene across multiple real small language models.
- External custodian must attest all data/label custody and evaluation outcomes; a local digest is not a signature.


## After v1.7

Next release should extend the evaluator-custodian separated holdout mechanism
to procedural-skill candidates; add token-matched sham-assistance and retrieval
baselines, one-use submission authority, negative-transfer tracking and workload
budgets before attempting validated neural distillation. Continue to reject
claims of independently demonstrated general-intelligence improvements until
reproducible out-of-family evaluation exists.


## Follow-up after v1.8

- Independent evaluator-controlled, unpublished task-family holdouts and external
  baseline suites, with precommitted sampling and no iterative test reuse.
- Compare the same real LLM without SIS, with token-matched retrieved hints,
  with verified procedural skills, and with trained student weights.
- Add student training *outside* SIS using provenance-checked pseudo-labels,
  explicitly held-out task families, rollback conditions and failure audits.
- Harden skill evaluator with an OS/container/process boundary and external
  append-only receipt anchoring before handling potentially adversarial workloads.

## After v2.3

- External executor instrumentation for authorized file/coding tasks with a real sandbox and operator-controlled verifier.
- Program equivalence beyond commutative/idempotent filters, with soundness checks.
- Separate evaluator-controlled task-family holdouts and paired small-LLM studies for tabular workflows.
- Authenticated cross-process evidence and public qualification receipts.
