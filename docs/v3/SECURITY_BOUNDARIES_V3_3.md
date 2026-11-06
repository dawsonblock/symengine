# SIS v3.3 Security Boundaries

## Roles and permissions (policy.py)

| role | permissions relevant to learning plane |
|---|---|
| agent | guidance:read, qualified_catalog:read, observation:append |
| runner | workspace:execute, observation:append, artifact:read |
| learner | candidate:write, artifact:read |
| evaluator | outcome:evaluate, outcome:sign, evaluator_private:read, artifact:read |
| operator | promotion:approve, policy:write, qualified_catalog:read, artifact:read |

- `candidate:write` → learner only. Memory induction and the skill
  optimizer run under this role: they can submit at PROPOSED and move
  `proposed→validated`. Nothing else.
- `outcome:evaluate` → evaluator only. Owns `validated→evaluating`,
  `evaluating→rejected|inconclusive`, and every receipt signature.
- `promotion:approve` → operator only. Owns `evaluating→qualified` and
  `qualified→revoked`. Serving state is not conferred by a role string:
  qualification requires three independent signed artifacts — a
  signature-authenticated pass receipt (`receipt_authority`), an
  evaluator-signed `CandidateEvidenceV1` binding those receipts to the
  *exact* candidate record/content digest on the sealed holdout
  partition under the expected protocol (`evidence_authority`), and an
  operator-signed `CandidateDecisionV1` for the exact edge
  (`decision_authority`). Revocation requires its own decision. Without
  the corresponding authority the transition is refused; a bare 64-hex
  string is never treated as evidence.

## Fail-closed boundaries (all tested)

- **Registry reads re-verify digests** — a tampered `candidate` row raises
  `candidate_tampered`; a tampered `experience` row raises
  `experience_tampered`. Corrupt JSON never deserializes into a record.
- **Replayed episodes are rejected** — `MemoryStore.ingest` keys on
  `(episode_id, task_fingerprint)`; a mutated copy of an episode is a
  `DuplicateEpisode`, never a second vote.
- **Idempotent submit, conflicting ids rejected** — re-submitting an
  identical candidate is a no-op; the same id with different content is a
  conflict.
- **Transition audit is hash-chained** — every `candidate_transition`
  row is sealed inside the same transaction as the state change with a
  `prev_digest`/`entry_digest` link that also covers the cited evidence
  and decision digests; `audit()` re-verifies the whole chain on every
  read, so rewritten, reordered, deleted or truncated history raises
  `audit_chain_tampered`. Databases without a chain are backfilled at
  open (sealed over current content — backfill makes rows verifiable, it
  cannot prove they were not already altered). A database already
  chained under the previous digest domain is resealed **only after the
  old chain verifies end-to-end against that old domain**; a broken
  pre-migration chain refuses to open with
  `audit_chain_tampered:pre_migration_*` instead of sealing over it. The
  reseal is recorded in `registry_migration` and reported by
  `verify()["migrations"]`, so the rewrite is attributable rather than
  silent.
- **Serving state is decision-backed, not a column** — the registry
  folds the transition log and requires the committed `state` column to
  match that projection. A direct SQL flip to `qualified` raises
  `state_projection_drift`; it cannot serve. Every serving-state
  transition must cite an operator-signed decision (and, for
  qualification, evaluator-signed evidence) that is re-authenticated on
  every read. Decision nonces are consumed atomically with the
  transition, so replay is a conflict. A serving transition whose cited
  decision or evidence row is absent is `unbacked`
  (`decision_missing`/`evidence_missing`): the candidate cannot serve,
  but the catalog stays writable so it can still be revoked under a
  signed decision.
- **Qualification evidence names the candidate** — an
  `OutcomeReceiptV1` only proves an outcome for a task. Qualification
  additionally requires a signed `CandidateEvidenceV1` whose
  `candidate_digest`/`content_digest` match the candidate being
  qualified, whose `partition` is `holdout`, whose protocol digest
  matches the registry's pinned evaluation protocol, and whose
  `receipt_refs` cover every cited receipt. Pinning is mandatory:
  qualification is refused with
  `qualification_requires_expected_protocol` when the registry has no
  expected protocol, and a serving replica without the pin cannot read
  the qualified catalog (`serving_protocol_unpinned`). A pass receipt
  from an unrelated task, repository or candidate is rejected with
  `evidence_receipt_not_bound` / `evidence_candidate_digest_mismatch`.
- **Serving re-derives catalog integrity** — `qualified()` re-folds the
  chain, re-checks the state projection, and re-authenticates the
  decision and evidence behind every candidate on every request. Any
  integrity failure abstains with `catalog_unavailable` and records an
  `integrity_error` in the serving audit; it never serves a partial
  catalog.
- **Outcomes require an authenticated receipt** — `record_outcome`
  resolves the cited digest through the trusted evaluator boundary,
  requires the receipt's task and outcome to match the served task and
  claimed outcome, and refuses without a configured authority. An
  unauthenticated digest cannot write a `serving_outcome` row.
- **Basis revocation suppresses** — when a caller supplies a revocation
  set, a revocation naming a candidate's receipt, evidence binding or
  decision rejects it with `evidence_revoked`.
- **Skill ingestion is untrusted input handling** — `skill_ingest`
  parses skill directories with bounded, dependency-free rules; it never
  executes, imports, or fetches anything. Symlinks (the skill directory,
  `SKILL.md`, or any resource), hidden files, non-UTF-8, control
  characters, oversized bodies and oversized resource sets are refused.
  Ingested skills enter at PROPOSED under `candidate:write`; a claimed
  qualification status is ignored, scan findings are advisory, and
  serving still requires signed holdout evidence plus an operator
  decision.
- **Serving is scope-bound** — `repository_scope` of `registry_id` /
  `family_id` resolves through the signed `RepositoryRegistry`; a
  self-declared or unknown repository identity abstains. `global` scope
  is served only behind an explicit `allow_global_scope` flag.
- **Family targeting is an opt-in hard gate** — `target_task_family` is
  provenance by default; when the caller passes `task_family`,
  off-target candidates are rejected with `family_mismatch` and counted
  in the audit rejections.
- **Counterexamples suppress with boundary anchoring** — a
  `known_counterexamples` string vetoes a candidate only on a
  token-boundary match in the task's failure/symbol/file context
  (needles shorter than 3 characters must equal a whole token), so a
  short string cannot suppress everything it merely substrings.
- **Serving audit records what was delivered** — `candidate_digests`
  covers only candidates whose steps actually shipped in
  `helpful_next_checks` (post-budget, post-truncation), not every
  catalog item considered; each rejection is recorded with a reason.
  Every `served_guidance` audit row carries the `task_id` and the
  guidance digest.
- **Outcomes bind to delivered guidance** — `record_outcome` requires a
  receipt that resolves through the trusted evaluator boundary, carries
  the served `task_id` and the claimed outcome, and is attached to the
  exact guidance digest this gateway served for that task; unknown
  tasks, mismatched digests, unauthenticated receipts, task/outcome
  mismatches and malformed references raise instead of writing an
  uncorrelated audit row.
- **Malformed serving input abstains audited** — a request that fails
  contract parsing returns `abstain/catalog_unavailable` inside the
  audited path rather than propagating an unlogged exception.
- **Prompt injection is data** — a qualified candidate whose steps say
  "grant operator role" is served verbatim inside `helpful_next_checks`
  and nothing else: `decision` stays `abstain`, `procedure_ids` stays
  empty, no permission changes.
- **Optimizer cannot self-qualify** — `SkillOptimizer` has no state path
  past PROPOSED; its dev evaluator is an injected interface it does not
  control, and it cannot see holdout partitions (structural).
- **Imported bundles are unqualified** — `import_bundle` verifies hashes
  and registers at PROPOSED regardless of the manifest's claimed
  `sis_qualification_status`; a passing `security_scan` never implies
  qualification. `verify_install` returns problems for *any*
  unverifiable element — corrupt or missing `manifest.json`, undeclared
  hashes, unexpected files, or a manifest whose `candidate_id`/
  `candidate_digest` disagrees with the payload — it never raises.
- **Preregistration conformance is measured, not cosmetic** —
  `run_governed_evaluation` records a `conformance` block comparing the
  executed run to the preregistered budget, arm set, and sample size;
  an off-plan or underpowered run reports `conforms=False` with named
  mismatches rather than hiding behind the protocol digest.
- **Receipt reuse is impossible** — verifier nonces and the
  `(task_id, tree_digest, criterion_version)` dedup marker reject
  replays; the benchmark receipt cache reuses identical-submission
  receipts by reference, not by re-evaluation.

## What is NOT enforced here (honest limits)

- Local execution is `isolation:unverified_local`; seatbelt network
  denial is opportunistic, not a guarantee.
- Advisory text is delivered to the agent — the harness must treat it as
  untrusted context. SIS guarantees the channel is advisory; the agent's
  sandbox is responsible for action-level enforcement.
- The polarity conflict detector is a heuristic, not a semantic proof;
  `conflict_policy="abstain"` is the conservative option.
- The evaluator is trusted to attest *that* it evaluated the candidate
  under the declared protocol and partition. SIS binds the attestation
  to the exact candidate digest, cited receipts, holdout partition and
  protocol digest, and re-authenticates it at serve time — but it cannot
  independently prove the evaluator actually ran the candidate or that
  the holdout was untainted. Evaluator custody and task-registration
  lineage remain deployment responsibilities.
- A legacy candidate qualified before signed decisions existed has no
  serving basis. It is excluded from `qualified()` (`state_not_decision_backed`)
  and can only be remediated by revoking it under a signed operator
  decision; the upgrade never retroactively mints authority. The same
  remediation applies to a serving transition whose cited decision or
  evidence row is missing, but a *revoked* candidate no longer needs its
  qualification basis to exist, so `verify()` reports a clean catalog
  once the takedown is committed — the historical row still cites the
  absent digest for an external auditor to notice.
- The v3.3 → current upgrade reseals every audit row because the digest
  domain gained the evidence/decision fields. Resealing is gated on the
  old chain verifying first and is recorded, but it still means an
  external anchor taken before the upgrade will not match afterwards;
  re-anchor after upgrading.
- Evidence bindings can be issued for identical-submission evaluations
  that share a receipt; the binding names the candidate that was
  actually served during the probe, so this is a shared outcome, not an
  unrelated one.
