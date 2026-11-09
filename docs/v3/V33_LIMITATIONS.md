# SIS v3.3 Limitations

## Efficacy

- **Learning efficacy is not established.** The deterministic campaign
  proves the machinery end-to-end (verified episodes → candidates →
  sealed-holdout paired eval → governed qualification → serving →
  revocation) with a scripted agent. It does not show a real model
  solves more unseen tasks. That requires a live-model campaign on a
  powered sample; until then the release is
  `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
- Holdout size in the deterministic fixture (2 tasks) is a smoke test,
  not a statistical result; `mcnemar_exact_p` is reported honestly and
  is not significant.
- The per-candidate qualification probes run after the five-arm
  evaluation on the same small holdout. They bind evidence to the
  candidate it qualifies (the integrity property this release fixes),
  but they are not an independent powered generalization measurement.
- Preregistration binds the plan, not the execution. The `conformance`
  block in each governed report records whether a run honored the
  preregistered budget/arms/sample size; it flags violations, it does
  not prevent them.

## Isolation

- Execution isolation remains `isolation:unverified_local`; the
  runner reports what it can enforce, no more. Network denial via
  seatbelt is best-effort on macOS only.
- v3.3.3 adds the `IsolationAttestationV1` contract and verifier, but no
  in-tree backend or isolator signer produces attestations — production
  execution stays closed until a qualified isolator exists, and a
  receipt's own `isolation:*` markers never qualify it.
- Usage accounting remains `reported`-grade for agent-supplied counters;
  only `UsageMeter`-instrumented paths are `verified`.

## Composition and memory

- Conflict detection is a lexical polarity heuristic — it catches
  "always X" vs "never X", not semantic contradictions. Deployments that
  cannot tolerate heuristic misses should serve with
  `conflict_policy="abstain"`.
- Memory retrieval scoring is deterministic gate-counting, not neural
  similarity. Semantic ranking across distant phrasings is out of scope
  for this release.
- Hypotheses inside memory payloads are carried for evaluation only;
  nothing upgrades them to causal truth automatically.
- Development stores still permit legacy rows and leave ingest-time
  evidence checking to the caller: `MemoryTrustProfile.development()`
  is the default, and `trust_status` always reports
  `untrusted:development_profile`. A production store
  (`MemoryTrustProfile.production()`) refuses to construct without
  signed-record keys, a custodian chain key, an external witness, and
  an evaluator verifier, and it runs the registered-task lineage check
  itself on every ingest and read. Qualification is still the hard
  serving gate — a record cannot reach trusted guidance without a
  signed pass receipt *and* an evaluator-signed evidence binding naming
  that exact candidate *and* an operator-signed decision.
- The external witness is only as independent as its key custody. A
  principal that controls both the memory database and the witness key
  can forge a consistent pair; deployments must keep the witness path
  and signing key under a different authority.
- V1 outcome receipts cannot prove *attempt* identity, so production
  memory accepts the attempt binding only when the resolved artifact
  carries `attempt_id` (`OutcomeEnvelopeV2`). V1 receipts remain
  historical evidence, not the production path.

## Evolution

- Mutators are a fixed, hand-declared set over step lists. There is no
  free-form code mutation, and no candidate code ever executes inside
  the optimizer.
- Dev-set fitness selection can overfit the development partition by
  construction; that is exactly why the sealed holdout is separate.
  Reports must never present dev fitness as generalization.
- Per-child optimizer faults (a mutator crash, a failed registry
  submit, an evaluator exception) are isolated to that child and
  recorded on `SkillOptimizer.failures`; the run continues, but callers
  should inspect `failures` — isolation means a partial search, not a
  failed one.

## Serving and packaging

- `global` candidate scope is refused unless `allow_global_scope=True`
  is set deliberately — it is a deployment decision, not a default.
- Candidate qualification requires per-candidate evidence. Both
  campaigns now run a sealed-holdout probe per candidate (guidance
  composed from that candidate alone) instead of reusing a collective
  arm receipt; the live campaign therefore makes more codex calls than
  the five-arm evaluation alone. This is the honest cost of binding
  evidence to the artifact it qualifies. The probe goes through
  `run_candidate_probe`, which enforces repository disjointness and
  records budget/sample-size conformance against the preregistered
  protocol; it is still a 2-task probe, so its conformance block
  honestly reports `sample_size … (underpowered)` — and, when the
  protocol is powered, `power_analysis:required=… ran=… (underpowered)`.
  A probe plan registered as diagnostic (`powered=False`) carries no
  power claim at all, so it conforms to its own plan and still cannot
  back a production qualification.
- The evaluator is trusted to attest that it evaluated the named
  candidate under the declared protocol/partition. SIS binds the
  attestation to the exact candidate digest, receipts, holdout
  partition and protocol, and re-authenticates it at serve time; it
  cannot independently prove evaluator custody or holdout purity.
- `baseline_outcome` in `individual_task_receipts` is bound by the
  certificate signature only — the per-task evaluator receipt covers
  `task_id` and `outcome`, not the baseline. The validator
  reconstruction therefore binds the claimed point estimate, interval
  and regression floor to the *issuer-stated* paired matrix; a
  certificate issuer is trusted for the baseline column itself.
- The strict-authority snapshot binding requires the strict gateway to
  expose `authority_fingerprint()` (`StrictGuidanceGateway` does). A
  combined gateway wired to a strict authority without it keeps the
  snapshot→commit revocation window open.
- The evaluation protocol is pinned, not optional: a registry without
  `expected_evaluation_protocol_digest` cannot qualify and cannot read a
  qualified catalog. Deployments must carry the preregistered protocol
  digest into every serving replica.
- Legacy qualified candidates (pre-signed-decision databases) have no
  serving basis. They are excluded from `qualified()` and must be
  revoked under a signed operator decision before the catalog verifies
  clean again. The same holds when a serving transition cites a decision
  or evidence row that is gone (`decision_missing`/`evidence_missing`):
  serving fails closed, but the catalog stays writable so the takedown
  is still possible.
- The candidate registry's audit chain is hash-linked but unkeyed. A
  writer who can rewrite the *entire* database can truncate history;
  signed decisions prevent minting new authority, but detecting full
  history truncation requires an external anchor. The v3.2 procedure
  authority has an anchor chain; the candidate registry does not.
- Upgrading a v3.3 database reseals the whole audit chain, because the
  digest domain gained the evidence/decision fields. The reseal is gated
  on the old chain verifying first and is recorded in
  `registry_migration`/`verify()`, but a pre-upgrade external anchor
  will no longer match; re-anchor after upgrading.
- Decision nonces are consumed atomically with the transition, so a
  normal replay is a conflict. A full-database rewrite that also rolls
  back the nonce table is the truncation case above, not a new-authority
  case.
- `target_task_family`/`target_agent` are provenance unless the caller
  supplies `task_family` to `serve()` — without it, a candidate trained
  on family A can serve advisory text on family B tasks (scope rules
  still apply). Deployments that need the hard gate must opt in.
- Counterexample suppression is lexical: a token-boundary match over
  failure/symbol/file strings. Semantically equivalent counterexamples
  phrased differently will not suppress.
- `security_scan` is a string heuristic for advisory triage only; a
  clean scan never implies qualification and a flagged bundle is not
  proof of malice.
- `record_outcome` requires a configured `receipt_authority` and a
  receipt whose task and outcome match the served task and claim. When
  a control plane is configured, the durable authorization receipt
  binds the outcome to the committed task, guidance digest, and
  requester, and only that requester may attach the outcome. Without a
  control plane the correlation is still the audit sink and a restart
  between serving and outcome recording loses the in-memory link, so
  deployments must persist and reconcile the audit stream.
- Bundle format is vskill-*style* (manifest + payload + SHA256SUMS);
  wire compatibility with an external vskill registry is not claimed.
- Skill ingestion (`tools/ingest_skills.py`) is packaging, not
  evaluation. Step extraction from `SKILL.md` is a deterministic
  heuristic (bullet/numbered lines, else short prose lines), not a
  semantic parse; the full body is retained in `instructions` for audit.
  Bodies over 24 KiB or resource sets over 64 files / 16 MiB are refused
  rather than truncated, so a large skill must be split to be ingested.
  Resource contents are recorded by digest only — a deployment that
  needs the files must ship the skill directory alongside the registry.
  Most imported skills have no holdout task in the current fixtures and
  therefore remain PROPOSED; ingestion never schedules evaluation. The two
  worked examples in `tools/skill_holdout.py` use a deterministic scripted
  agent and test-custody keys: they prove the pipeline, not that a real
  agent follows the skill. A prose skill with no observable artifact (for
  example a greeting style) has nothing a holdout test can honestly assert
  and should not be qualified.

## Not in scope (per charter)

No neural fine-tuning, no LoRA/weight adaptation, no live-registry
promotion channels, no cloud deployment. Learning is bounded to
symbolic procedures, experience memory, and text-level skill variants.
