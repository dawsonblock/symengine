## Unreleased — review corrections

- The CLI/HTTP smoke test now reads `sis.__version__` instead of asserting
  the stale `3.3.1` string.
- SQLite `-wal`, `-shm` and `-journal` sidecars are excluded from the
  release inventory and `.gitignore`, so running the CLI in the repository
  root no longer makes `verify_release.py` fail.
- `sis --version` reports the package version.
- Release packaging derives its default archive name from the package
  version instead of a hardcoded v3.3.1 label.
- Provenance verification accepts either a 64-hex key or the shipped
  `provenance_public_key.hex` file.
- The v3 contract schemas are included in the wheel and sdist.
- Release archives use a stable archive-internal project directory
  (`SIS-v<version>-...`) instead of the local checkout directory name.
- CI enforces the exact release inventory only on release commits and
  reports development-tree drift instead of failing every post-release push.
- Documentation: README, release notes, threat model, operations wiring,
  architecture and the top-level doc cross-references now describe v3.3.2.
- Suite after the review: **986 passed, 8 skipped**; the release bundle is
  re-bound to this tree.

## 2026-10-27 — SIS v3.3.2 authority consistency (M0–M5)

- Enforced execution identity in production: a gateway constructed with
  `require_execution_identity=False` is rejected, the signed session
  carries an explicit maximum lifetime (default 3600 s), and the
  authenticated caller's requester identity is checked against it.
- Added a shared control plane (`sis.v3.control_plane`) with SQLite and
  PostgreSQL profiles. `commit_authorization` consumes the signed
  session nonce and writes the decision receipt in one transaction, so
  two replicas racing with the same identity produce exactly one
  successful authorization. Production cannot construct a gateway
  without it.
- Witnessed custody in authority checkpoints: `revocation_head`,
  `supersession_head` and `custody_entry_count` are signed, compared on
  every production serve, and advanced monotonically. Restoring a
  pre-revocation custody directory or deleting the revocation log now
  fails closed. Checkpoints without custody history remain
  byte-compatible with v3.3.1, preserving old signatures and the
  previous-digest chain.
- Serving captures a witnessed snapshot, composes against it, then
  revalidates and commits. A revocation committed while guidance is
  being prepared aborts the decision instead of delivering revoked
  evidence.
- Replaced the shared visited set in `EvidenceCustodyStore.status` with
  active-path cycle detection plus memoization and depth/node bounds.
  Diamond-shaped evidence graphs are accepted; cycles are rejected.
- Added the authenticated v3 serving boundary
  (`sis.v3.serving_service`): bearer-authenticated `/v3/guidance` and
  `/v3/outcome`, default isolation of legacy `/v1` routes (also forced by `SIS_V3_ONLY=1`),
  custody freshness enforced in `serve()`, an explicit `advisory`
  decision distinct from abstention, and durable guidance-to-outcome
  records. `create_server` exposes the configured server for deployment
  and tests.
- Added 50 permanent security regression tests and executed baseline evidence:
  five target defects open on v3.3.1, zero open on this tree. Suite:
  **981 passed, 8 skipped**. See `docs/V332_AUTHORITY_CONSISTENCY.md`.
- Added opt-in PostgreSQL qualification tests (duplicate nonce, four
  concurrent replicas -> one commit, two-replica serving, outcome
  binding, monotonic head). With a disposable PostgreSQL 14.20 cluster
  the suite is **986 passed, 3 skipped**; see
  `evidence/v332/qualification.json`.
- Custody revocations/supersessions can publish the new witnessed head
  automatically via `EvidenceCustodyStore.bind_on_change`.
- Signed dependency links: `require_signed_links=True` and
  `bind_link_signer` make certificate dependency manifests tamper-evident;
  unsigned legacy links are cross-checked against the certificate's
  declared receipt and delivery digests.
- Exact outcome binding: `/v3/outcome` accepts `authorization_id` and
  rejects a decision that does not name the committed receipt.
- Production isolation gate: `LocalSubprocessExecutor(production=True)`
  refuses to run unless `verified_isolation=True`, and
  `classify_execution(production=True)` requires `isolation:verified`.
- Readiness: `GET /health` reports authority, custody and control-plane
  checks and returns 503 when degraded.
- Key rotation: a checkpoint signer change requires a strictly higher
  `authority_epoch`; v3 API keys support `expires_at`.
- Upgrade recovery: a fresh control plane seeds `authority_head` from the
  latest verified checkpoint on first serve.
- Release provenance: signed DSSE envelope in the in-toto/SLSA shape,
  verified against the archive's exact SHA-256; `requirements-lock.txt`
  and a PostgreSQL CI job.
- Added `docs/V332_OPERATIONS.md`, `docs/V332_ACCEPTANCE_MATRIX.md` and
  `docs/V332_EFFICACY_STATUS.md`.
- Regenerated `RELEASE_SHA256.json` (375 files) and built
  `release/SIS-v3.3.2-AUTHORITY-CONSISTENCY.zip`; the ZIP and its signed
  DSSE provenance verify. The provenance key is labelled
  `qualification-only`, not a production trust root.
- Not qualified: evaluator isolation (M6), full SLSA level conformance,
  real-agent efficacy (M9), and a real multi-host PostgreSQL deployment.

## 2026-10-26 — SIS v3.3.1 authority closure

- Added external signed authority checkpoints (`sis.v3.checkpoints`):
  monotonic sequence, authority epoch, previous-digest chain, journal
  head/sequence, candidate-revision digest, compare-and-append, atomic
  file store, crash recovery, and fail-closed serving. A deleted final
  revocation, stale database restoration or journal-head substitution is
  detected against independent custody; a local-only database is not
  treated as rollback resistant.
- Added candidate-specific evaluation certificates
  (`sis.v3.evaluation_certificate`): evidence classes, qualification
  policy, harness-signed delivery attestations, protocol registry and a
  validator that re-derives sample size, conformance, statistics,
  negative transfer, revocation and scope. Two-task runs cannot satisfy
  a 29-task protocol; demonstration runs cannot serve production.
- Added authenticated execution identity (`sis.v3.execution_identity`)
  and durable evidence custody (`sis.v3.evidence_custody`): immutable
  objects, dependency links, signed revocation/supersession logs,
  offline policy, and fail-closed status checks on every qualified read.
- Hardened skill ingestion: scope-aware candidate ids, structured
  Markdown parsing (code/quotes/example commands never become steps),
  high-severity findings block automatic qualification, explicit
  discovery completeness/pagination, bounded large documents, and
  frontmatter variants.
- Added pinned evaluator runtime and outcome taxonomy
  (`sis.v3.evaluation_runtime`): 2 GiB default envelope, bootstrap probe,
  plugin policy, protected-path/network denial, and infrastructure
  failures that never count as task pass/fail.
- Added five-arm learning qualification (`sis.v3.learning_qualification`)
  with exact McNemar, Wilson/Newcombe intervals, negative transfer,
  resource overhead and a real-agent gate. The scripted demo is labelled
  demonstration. An eight-task real five-arm Codex attempt was executed
  until the Codex quota blocked four tasks; the gate is recorded as
  `BLOCKED_EXTERNAL_AGENT_QUOTA`, not as a task failure.
- Added docs/V331_ARCHITECTURE.md and the v3.3.1 authority, certificate,
  identity, custody, ingestion, evaluation, threat-model, migration and
  release documents. Suite: **926 passed, 3 skipped**.

## 2026-10-25 — Skill ingestion (M10)

- Added `sis.v3.skill_ingest` + `tools/ingest_skills.py`: real skill
  directories (`SKILL.md` frontmatter + body, optional
  `references/`/`scripts/`/`assets/`) and skill trees are parsed into
  bounded `CandidateV1` records of type `skill_bundle` and submitted by
  the `learner` role at PROPOSED. vskill-style bundles are accepted
  through the existing verified import path.
- Bounded, dependency-free parsing: frontmatter ≤ 8 KiB, body ≤ 24 KiB
  (split into contract-sized instruction chunks), ≤ 64 resources hashed
  (contents never inlined), symlinks/traversal/hidden files refused,
  UTF-8 only, control characters refused.
- Ingestion is packaging only: a claimed `qualified` status is ignored,
  no signing keys are held, and qualification still requires signed
  holdout evidence plus an operator decision. Scan findings (shell
  execution tokens in served steps, prompt-injection phrasing in the
  body) are advisory and reported, never a refusal or a qualification.
- Candidate ids are derived from name + content digest, so re-ingesting
  identical content is a no-op and changed content is a new candidate.
- Added `tools/skill_holdout.py` and the `tools/skill_holdouts.py`
  registry: worked examples (`write-skills` artifact check,
  `php2shell-check` pinned-runtime check, `write-tests` mutation-checked
  suite) that run the full ingest → holdout probe (with and without
  guidance) → evaluator evidence + operator decision → serve path. The
  registry records planned tiers and every excluded skill with a reason,
  and the tool gains `--list`, `--tier` and `--only`.
- `OutcomeVerifier` accepts an explicit `limits` envelope (default
  unchanged) so a meta-test that runs the submitted suite in a nested
  process can opt out of `RLIMIT_NPROC=64`, which blocks the nested fork
  on platforms that count every process of the user.
- Suite: **804 passed, 2 skipped**.

## 2026-10-25 — Authority/evidence binding and serving integrity hardening

- Candidate qualification no longer accepts an unrelated pass receipt.
  Added `CandidateEvidenceV1` + `CandidateEvidenceAuthority`: an
  evaluator-signed binding of receipt digests to one exact candidate
  record/content digest on the sealed holdout partition under the
  expected protocol. `CandidateRegistry.qualify` requires every cited
  receipt to be covered by an authenticated binding that names the
  candidate; a pass receipt for another task, repository or candidate
  is refused.
- Serving state is no longer a mutable column gated by a role string.
  Added `CandidateDecisionV1` + `CandidateDecisionAuthority`:
  operator-signed exact-edge decisions for `evaluating→qualified` and
  `qualified→revoked`, binding the candidate digest, edge, evidence
  handles and actor identity. Decision nonces are consumed atomically
  with the transition; replay is a conflict.
- Every registry read now folds the hash-chained transition log,
  requires the committed state column to match the projection, and
  re-authenticates the signed decision/evidence behind each qualified
  candidate. A direct SQL state flip raises `state_projection_drift`;
  the serving gateway abstains `catalog_unavailable` with an audited
  `integrity_error`. Legacy unbacked qualifications are excluded and
  revocable only under a signed decision.
- `GovernedServingGateway.record_outcome` now requires an
  authenticated receipt with the same task and outcome; a bare digest
  cannot write a `serving_outcome` row. A revocation naming the
  candidate's receipt, evidence binding **or decision** suppresses it
  (`evidence_revoked`).
- Both governed campaigns now evaluate each candidate individually on
  the holdout and issue candidate-specific evidence + decisions instead
  of reusing a collective arm receipt. The probe runs through
  `run_candidate_probe`, which enforces repository disjointness and
  records budget/sample-size conformance against the preregistered
  protocol; a candidate that composes no guidance is reported as
  `no_guidance` rather than bound to a pass.
- Qualification requires a pinned evaluation protocol
  (`expected_evaluation_protocol_digest`); without it qualification is
  refused and a serving replica cannot read the qualified catalog.
- Upgrading a v3.3 database reseals the audit chain only after the old
  chain verifies against the old digest domain; a broken pre-migration
  chain refuses to open. The reseal is recorded in
  `registry_migration` and reported by `verify()["migrations"]`.
- A serving transition whose cited decision or evidence row is missing
  is `unbacked` (`decision_missing`/`evidence_missing`): it cannot
  serve, but intake and signed takedown stay possible instead of the
  whole catalog freezing.
- Evidence/decision expiry is compared as parsed UTC instants, not
  strings, and `expires_at <= issued_at` is refused at issuance.
- Suite: **777 passed, 2 skipped**. Deterministic campaign still
  reproduces A=0/B=2/C=2/D=0/E=2 and qualifies 5 candidates.

## v3.3.0 — Governed learning (2026-10-25)

- Added a typed candidate registry (`CandidateV1`, six artifact types) with
  role-gated transitions, hash-chained audit, and receipt-authenticated
  qualification.
- Added ReasoningBank-style experience memory with JSON-only ingest,
  episode-replay rejection, evidence-bound verification, and gated retrieval
  with abstention.
- Added EvoSkill-style bounded skill evolution: pure-payload mutators,
  injected dev evaluator, hard budgets, ranked frontier, intake-only output.
- Added the five-arm governed evaluation plane (A–E) with sealed holdout
  partitions, preregistered protocol digests, sample sizing, and honest
  abstention/negative-transfer metrics.
- Added strict governed serving with registry-resolved repository identity,
  scope/revocation/applicability/counterexample gates, and audited delivery.
- Added vskill-style skill bundle export/verify/import; imports land at
  PROPOSED regardless of claimed status.
- Added deterministic and authenticated live campaigns exercising the full
  lifecycle, plus 13 failure-injection scenarios.
- Hardening: qualification requires a signature-authenticated pass receipt;
  the release archive is source-bound and cannot embed itself; the release
  build fails closed when the extracted tree does not compile or fails its
  smoke test; regression rate is relative to baseline solves; memory ingest
  and serving outcomes are evidence-bound.
- Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED** — security/correctness gates
  pass; learning efficacy on unseen repositories is not established. See
  `docs/v3/QUALIFICATION_REPORT.md` and `docs/v3/V33_LIMITATIONS.md`.

## 2026-10-24 — Signed decision recovery and authority hardening (development release)

- Write-ahead, signed promotion decisions and deterministic catalog materialization recovery.
- Fail-closed checks for unmaterialized intermediate status decisions.
- POSIX promotion writer lock and stale-controller rejection.
- Tightened torn-journal-tail handling and fault-injection recovery regressions.
- See `AUTHORITY_RECOVERY_RELEASE_NOTES.md` for limitations and validation results.

## v2.4.0 — Bounded coding-agent repair recipes (2026-10-21)

- Added pure Python AST operator-swap capture, with no arbitrary Python source execution.
- Replays every labeled input through a restricted bounded expression interpreter before promotion.
- Generalizes successful repair operators across independently supplied Python function names.
- Adds separated source-program holdouts, duplicate/overlap checks, independent promotion recomputation.
- Adds SQLite code recipe catalog, local hash-linked audit, retirement and conflict protection.
- Exposes read-only code previews through model ToolBridge; operator-only study and retirement through CLI/HTTP.
- Ships functional demo, adversarial tests, detailed security/limitations guide; v1.0–v2.3 retained.
- Does not implement sandboxed Python unit-test execution, generalized code synthesis, or real LLM qualification.

## v2.3.0 — Controlled tabular workflow learning (2026-10-21)

- Added observed-tool `WorkflowSession` with deterministic filter/aggregation operations over bounded typed records.
- Added replay and SHA-256-linked execution events. Full capture control remains an untrusted authority boundary.
- Added exact semantic canonicalization for reordered and duplicate independent filters. Does not claim unrestricted equivalence of algorithms.
- Added independent SQLite `WorkflowCatalog`, operator-gated promotions, local audit verification, retirement, and fail-closed inference.
- Added read-only LLM tool definition, CLI commands, and local HTTP routes with separated operator authorization.
- Added adversarial tests and demonstration. Existing symbolic skill, LoRA, and holdout workflows remain included unchanged.
- No independent external-task evaluation, unrestricted agent execution, or real-model training claim.

## 2.2.0 — Instrumented Experience Abstraction

- Capture actual allowlisted deterministic tool executions through `InstrumentedSession`, preserving explicit input, previous-result, and literal provenance; reject ambiguous value-only binding.
- Replay captures through the unchanged bounded SIS interpreter; verify each resolved operand, step result, strict JSON type, local event hash link, and final answer.
- Cluster verified successful training captures by their generalized data-flow AST, reject incompatible programs and duplicate/overlapping train-validation inputs; convert erroneous executions into corrected training examples only with independent correction labels.
- Submit reconstructed candidates to the existing v2.1 governed `trace_study` and `SkillCatalog` promotion sequence; model tool bridge remains read-only.
- Add CLI `experience-capture` and `experience-induce`, documented Python instrumentation API, complete runnable synthetic example fixtures, and 32 focused tests.
- Explicit non-goals: no arbitrary tool execution, raw-chat understanding, privileged external attestation, automatic LoRA execution, or independent intelligence improvements.

## v2.1.0 — Typed execution-trace induction (2026-10-21)

- Added `sis.trace_learning`: bounded declarative step programs, typed intermediate replay, and train-only proposal extraction.
- Added operator-side `Service.trace_study` and `sis trace-study` CLI, preserving the existing verification and promotion gate.
- Rejected forged intermediate values, future-variable references, invalid ASTs, type confusion, validation-derived traces and injected proposals.
- Added integration tests, sample multi-step traces, documentation, and clean source manifest packaging.
- Real task-family generalization, independent evaluator custody, and GPU finetuning are **not** established.

## v2.0.0 — Evaluator-controlled task-family comparison

- Added `sis.family_eval`: signed evaluation precommitments, explicit family
  and input collision checks, a one-use SQLite experiment vault, 3/4-arm
  paired live comparison, Holm-corrected item and family-level sign-test p-values, within-family accuracy,
  and frozen qualification-policy scoring. No mutating tool exposure.
- Added `sis family-eval-seal` and `sis family-eval-run` with opt-in networking,
  protected evaluator secret, pinned claimed model IDs and non-overwriting
  results; added `sis family-eval-verify` for signed report authenticity.
- Added synthetic, offline four-arm demonstration, adversarial tests, and
  detailed data-custody / inference limitations.
- Retained all v1.9 neural training, procedural skill, induction, and audit
  subsystems. **No real LLM fine-tuning or benchmark lift measured in this release.**

## v1.9.0 — Opt-in LoRA training and three/four-arm evaluation

- Implemented training export authenticity checks and a dependency-optional, actual PEFT/Transformers LoRA training runner with completion-only LM labels.
- Added strict config/data checks, opt-in execution, offline loading default, never-overwrite adapters and source-bound training receipt.
- Added frozen-bundle neural comparison: base LLM, base LLM with skill result, adapted LLM, optional placebo prompt, paired aggregate metrics.
- Added v1.9 fixtures, new security and experimental-design guide, and regression tests.
- Does not claim trained neural weights or independent real-LLM results; this source release tests validation, masking and orchestration using mocks.

# v1.8.0 — Frozen procedural evaluation and controlled pseudo-labels

- Hash-bound `skill-freeze` artifacts include independently checked active skill dependency closure and audit head.
- Precommitted two-split procedural-skill holdouts under evaluator-owned SQLite vault/HMAC, one-use scoring, signed aggregate receipts, strict replay and crash-safe receipt recovery.
- Sample-size, coverage, accuracy and 95% Wilson lower-bound qualification policy per split, declared exclusion records and duplicate prevention.
- Qualified skill-to-LLM JSONL *pseudo-label* export with custodian-side private-overlap rejection and signed output hash manifest; **no neural weight training**.
- Regression tests for forgery, modification, reuse, concurrent claims, distribution shift, archive/CLI integration, and failure paths.
- Honest evidence boundaries: local software verification only; independent holdout ownership is required for credible generalization claims.

# v1.7.0 — Governed bounded procedural skills

- Added strict interpreted JSON program AST: conditionals, lexical bindings, bounded list reductions and skill composition with active dependency checks.
- Added deterministic skill discovery and operator proposals, requiring disjoint caller-provided validation, ambiguity checks, and independent recomputation before promotion.
- Added separate hash-linked skill catalog with semantic transition replay, fail-closed prediction, negative-feedback suspension, and retirement.
- Added conservative episode-to-study adapter that requires external corrected outputs for failed episodes; trace strings are metadata only.
- Added skill CLI, HTTP endpoints, read-only LLM tool bridge and basic caller-controlled benchmarking.
- Preserved v1.6 rule engine, evaluator, paired LLM tests, and existing database schema; skill chain has no external anchor and is not independently qualified.

# v1.6.0 — Paired LLM evaluation (2026-10-20)

- Same-model, read-only baseline vs SIS-augmented benchmark with counterbalanced arm order.
- No reference labels included in LLM request content; fail-closed registry audit and drift checks.
- Strict typed JSON answer/abstention decoding; provider failures invalidate runs.
- Exact McNemar comparison, paired contingency table, Wilson descriptive intervals, coverage, latency, and optional provider-reported token usage.
- Two-step network opt-in CLI; refuses overwriting benchmark result artifacts.
- Added local tests, synthetic fixtures, and explicit limitations of local experiment evidence.
- No changes to prior SQLite storage schema, evidence claims, or promotion authority.

# Changelog

## 1.5.0 — October 20, 2026

- Add explicit, one-to-one schema-map transfer of active source rules with strict type/list constraints; no automatic assertion of cross-domain validity.
- Extend read-only Service, CLI, HTTP, and agent tool-bridge entrypoints for one-record and bounded batch transfer.
- Precommit a typed evaluation qualification policy into the authenticated public study at sealing time.
- Add post-score evaluator-signed qualification and replay verification, separate from source rule promotion.
- Require meaningful holdout sample counts, overall accuracy/coverage, shifted-test performance, descriptive baseline margin, and 95% Wilson lower-bound screening.
- Preserve v1.4 sealed evaluation compatibility but refuse retroactive qualification of uncommitted legacy test policies.
- Add dedicated local integration and adversarial tests; explicitly deny that synthetic datasets or signed local policy passes establish independent effectiveness.


## 1.4.0 — October 20, 2026

- Introduce a separate evaluator-side, HMAC-authenticated one-use holdout vault, isolated from model-facing public train/validation data.
- Bind submissions to a signed public task and evaluate only locally admissible AST candidates.
- Provide test and shifted-regime aggregate metrics without revealing holdout examples or labels to the candidate process.
- Reject repeated or overlapping samples across all tasks in a single vault, including concurrent duplicate scoring attempts.
- Add signed scoring receipts and evaluator-side replay verification against private test data.
- Add 27 unit/integration checks, CLI subcommands, documentation and a synthetic example generator.
- Clarify that single-vault anti-reuse and HMAC receipts do not establish independent test custody or prevent whole-vault rollback.

## 1.3.0 — October 20, 2026

- Harden event replay with semantic transition validation, immutable field checks,
  typed/counter validation, and rule-ID integrity checks.
- Add an admission firewall rejecting bounded witnesses of disagreement against
  existing active rules in the same namespace and schema.
- Add separate HTTP operator secret for mutating/trusted routes. Prediction-only
  keys cannot promote rules, send feedback, or invoke operator LLM chat.
- Fail closed when listing rules with invalid audit; reject output-type mismatches
  before feedback can suspend a rule.
- Enforce strict type equivalence for candidate fitting and benchmark scoring
  (Python `True == 1` must never count as a valid typed match).
- Add adversarial regression tests and authenticated operator integration tests.

## 1.2.0 — October 20, 2026

- Require a full independent registry re-induction from supplied examples and search options before promotion (fixes the forged-result Python boundary).
- Add opt-in, operator-held audit checkpoints with SHA-256 or HMAC-SHA256 integrity for validating a DB audit prefix across appends.
- Add bounded batch prediction to CLI, Python service, and HTTP API.
- Refuse LLM HTTP redirects to reduce bearer-token and training-data exfiltration risk.
- Add new regression suite and release documentation.

## v1.1.0 — 2026-10-20

- Implemented deterministic, bounded active query selection from multiple training-consistent rules. Questions are explicitly **unlabeled** and never automatically promoted.
- Added disjoint train/validation/test benchmark with coverage, selective accuracy, overall accuracy, and a train-majority baseline. Caller's test set is not transmitted to induction.
- Added complete rule projections to the SQLite hash-linked events. The verifier now compares replayed latest projections against each stored rule and predictions fail closed if inconsistent.
- Added rule retirement with an append-only event and explicit no-reactivation policy.
- Added portable LLM tool definitions and a narrowly allowlisted Python `ToolBridge` that exposes only prediction and query proposal.
- Extended local HTTP API, CLI, example fixtures, verification instructions and tests.
- Maintained the no-exec, bounded-AST, opt-in external-LLM baseline.
- Legacy v1.0 database events are detected as unverifiable rather than silently upgraded; see `docs/UPGRADE_V1_1.md`.

## v1.0.0 — 2026-10-20

- Initial installable Python symbolic-induction research prototype.
- Implemented bounded AST synthesis and hypothesis counterexample probing.
- Implemented optional Z3 disagreement search, opt-in LLM proposals, SQLite registry and local HTTP/CLI APIs.
- Provided local synthetic tests and a deterministic ZIP source manifest.
