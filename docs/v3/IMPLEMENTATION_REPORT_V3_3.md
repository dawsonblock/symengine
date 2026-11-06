# SIS v3.3 Implementation Report

Ledger of the governed-learning build, milestone by milestone, on branch
`codex/sis-v3.2-authority-integrity` (baseline commit `07a9174`).

## M0 — Baseline integrity: PASS

- The four manifest discrepancies (verifier.py, live_study.py,
  test_receipt_signatures.py, unlisted V32_GAP_MAP.md) all map to pushed
  review-fix commit `07a9174` — legitimate recorded changes, not
  unauthorized edits. Baseline = `07a9174` + this work.
- Artifacts: `docs/audits/BASELINE_INTEGRITY.md`,
  `evidence/baseline/{source_inventory,integrity_findings,baseline_tests}.json`.

## M1 — Authority/evidence hardening: PASS (verified, mostly pre-existing)

- WAL + BEGIN IMMEDIATE + append-only audit already present in
  `AuthorityDB`; `CandidateRegistry`/`MemoryStore` built to the same
  pattern.
- Evidence handles: qualification requires bound receipt digests;
  `verified` flags never cross a trust boundary.
- Trust domains: policy roles agent/runner/learner/evaluator/operator
  gate every mutation; learners and optimizers hold no signing material.

## M2 — Experience memory: PASS

- `contracts.py`: `ExperienceRecordV1` (digest-referenced trace/receipt,
  facts vs hypotheses separated).
- `memory.py`: `MemoryStore` (dedup/replay rejection, tamper-proof
  reads), `induce_candidate`, `retrieve_memories` (applicability +
  counterexample gates, budget, abstention). JSON-only ingest.

## M3 — Candidate registry: PASS

- `contracts.py`: `CandidateV1` for six types (symbolic_procedure,
  diagnostic_strategy, experience_memory, skill_instruction,
  skill_bundle, prompt_variant); domain-separated `content_digest` binds
  payload.
- `candidates.py`: role-gated transactional state machine
  PROPOSED→VALIDATED→EVALUATING→{REJECTED,INCONCLUSIVE,QUALIFIED}→REVOKED;
  operator-only qualification with mandatory receipts; append-only audit.

## M4 — Skill evolution: PASS

- `evolution.py`: pure-payload mutators (no command construction),
  injected `EvaluationClient`, hard `EvolutionBudget`, digest-deduped
  `Frontier`. Optimizer output is PROPOSED intake only.

## M5 — Composition + track unification: PASS

- `composition.py`: precedence by type, dedup, polarity-conflict
  detection, `precedence`/`abstain` policies, token/step budgets.
  Procedures, skills, memories, prompt variants merge through one choke
  point — never concatenated into a system prompt.

## M6 — Governed evaluation plane: PASS (machinery)

- `governed_eval.py`: `EvaluationPartition` + sealed-holdout check,
  `preregister` (float-safe protocol digest), `required_sample_size`,
  `compute_metrics` (abstention + negative transfer measured via
  `served_map`), `run_governed_evaluation` with 5 arms.
- `benchmark.py`: opt-in arm `E`; `report_digest` normalizes floats
  deterministically.

## M7 — Governed serving: PASS

- `serving.py`: `GovernedServingGateway` — signed-registry repo
  resolution, per-candidate rejection audit (`out_of_scope`,
  `inapplicable`, `counterexample`, `revoked`), advisory-only delivery.
  Candidate-only advice serves under an honest abstain decision.

## M8 — vskill packaging: PASS

- `skill_package.py`: manifest + payload + SHA256SUMS;
  `verify_install` fails closed on any mismatch; `import_bundle`
  registers at PROPOSED — the manifest's qualification claim is ignored.

## M9 — Deterministic campaign: PASS

- `tools/governed_campaign.py`: fixtures → verified baseline episodes →
  memory induction → skill evolution → dev selection → sealed-holdout
  paired eval (arms A–E) → operator qualification bound to real receipts
  → governed serving → revocation demo → skill bundle export +
  `campaign_evidence.json`.
- Deterministic result: A=0, B=2, C=2, D=0, E=2 on two unseen-repo
  holdouts — memory and skills transfer convention knowledge; the
  signature-bound procedure correctly abstains (negative control).
  Machinery evidence only — NOT live efficacy.
- Failure-injection coverage in tests: forged roles, tampered rows,
  replayed episodes, illegal transitions, missing receipts, bundle
  tamper, prompt-injection-as-data, revocation mid-serving, partition
  overlap, out-of-scope/unknown-repo serving.

## M10 — Release qualification: IMPLEMENTED_NOT_EFFICACY_QUALIFIED

- Suite: **741 passed, 2 skipped** (`PYTHONPATH=src pytest tests/`).
- Docs: ARCHITECTURE_V3_3, SECURITY_BOUNDARIES_V3_3, MEMORY_DESIGN,
  EVOLUTION_DESIGN, EVALUATION_PROTOCOL_V3_3, V33_LIMITATIONS, this
  report.
- Release artifacts under `release/` with manifest + source inventory.
- Efficacy requires a live-model campaign on a powered sample; the
  deterministic run proves machinery, not effect size.

### Post-build release verification (repair pass)

- The first shipped archive failed `tools/verify_release.py` twice:
  flat layout (no single project directory) and an embedded manifest
  that did not match the archive contents. Rebuilt with
  `verify_release.build_zip`: single project dir, 297 covered files,
  `verify()` + fresh-extraction `verify_tree` + `compileall` +
  extracted-test smoke all pass (`release/verification.json`).
- `RELEASE_SHA256.json` regenerated for the v3.3 tree; the prior file
  was a stale v2-era manifest. `release/` provenance is intentionally
  out-of-band: an archive cannot contain its own checksum.
- All six `evidence/` directories populated: baseline, integration
  (campaign + exported skill bundle), security (13/13 failure-injection
  scenarios green), benchmark, qualification, release.
- Archive content verified identical to commit `62588bb` for every
  manifest-covered file.

### Completion pass 2 (metrics closure + live study)

- `benchmark.py`: added the missing `B_vs_A` paired contrast — every
  arm now has a vs-baseline paired outcome (previously B was the only
  arm without one).
- `governed_eval.compute_metrics`: added literal spec metric keys
  `paired_win_rate`, `paired_loss_rate` (vs arm A, same valid-solve
  rule) and `mean_cost_per_verified_solve` (`None` — cost is unmetered,
  never fabricated). Suite: 710 passed, 2 skipped.

### Completion pass 3 (release binding + qualification authority)

- **Release archive was stale and could self-embed.** `dee2c4b`
  inventoried `release/` into `RELEASE_SHA256.json` without rebuilding
  the ZIP, so the shipped archive still contained pre-hardening code.
  Worse, the next build would embed the previous ZIP (and its stale
  checksum) inside itself, and `verify()` would still pass because the
  archive matched its own embedded manifest. `release/` is now
  out-of-band: excluded from the inventory, rejected as an archive
  member, and `build_canonical_zip` re-hashes every member against the
  source tree (`verify_against_tree`), records the Git commit, and
  refuses a dirty tree. New tests cover embedding, stale archives,
  dirty builds, and source binding.
- **Qualification accepted unauthenticated digests.**
  `CandidateRegistry.qualify` checked only that `receipt_refs` were
  64-hex strings. It now requires a deployment-supplied
  `receipt_authority`; every digest must resolve to a
  signature-authenticated receipt with outcome `pass`. Wiring this in
  exposed a latent campaign bug: qualification drew from a dict seeded
  with synthetic authority-demo receipts, so a random digest sort could
  cite a receipt the verifier never issued (flaky ~80%). Holdout
  evidence is now separate, and no verified pass receipt means no
  qualification.
- **Regression metric was mislabeled.** `verified_regression_rate` was
  the absolute failure rate, so baseline A reported 0.5 regressions
  against itself. It is now the fraction of baseline-verified solves an
  arm loses; `failure_rate` keeps the absolute number.
- **Memory and serving evidence binding.** `MemoryStore.ingest` takes an
  `evidence_check` hook wired to `verify_experience_evidence`
  (journal resolution + signature + outcome match); serving audit rows
  carry `task_id`, and `record_outcome` binds a receipt digest/outcome
  to the exact served guidance digest.
- Suite: **741 passed, 2 skipped**. Deterministic campaign unchanged
  (A=0/B=2/C=2/D=0/E=2); live governed campaign re-run at this tree:
  all arms 2/2 (ceiling), authentic lifecycle.
- `tools/smoke_integration.py` run locally on macOS: CLI + authed
  loopback HTTP smoke passes (401/403/200 status boundaries).
- `tools/live_study.py` executed against authenticated `codex exec`
  (ChatGPT login): 6 held-out tasks × arms A–D. Real result:
  A=4, B=3, C=3, **D=5** — served procedures were the best arm and
  D-vs-A is 1W/0L, but p=1.0: positive direction, underpowered,
  gate not met (`evidence/benchmark/live_study_v33.json`).
- `tools/governed_live_campaign.py` (new) ran the complete v3.3
  lifecycle with real `codex exec`: baseline dev episodes (A=2/2),
  induction, evolution, 5-arm sealed holdout. Result: **all arms
  2/2** — codex hit the fixture ceiling unaided, null efficacy
  contrast, but the full governed loop (episodes → receipts →
  qualification → serving → revocation) executed authentically with
  a real agent (`evidence/benchmark/live-campaign/`).

### Completion pass 4 (fail-closed extraction gate)

- **The release build recorded its extraction checks instead of
  enforcing them.** `package_release` ran `compileall` and the extracted
  `tests/v3/test_candidates.py` smoke test, then wrote their results into
  `release/verification.json` — but never inspected either result, so an
  archive whose extracted tree failed to compile or failed its smoke test
  could still be packaged under a green manifest. `fresh_extraction_checks`
  now raises on both, and records the smoke return code alongside its
  tail. Four regression tests cover the gate (passing extraction, failing
  smoke, missing smoke, uncompilable source).
- Suite: **741 passed, 2 skipped** (737 + the four gate tests).
  Artifacts rebuilt and bound to the fix commit: archive, embedded
  manifest, source inventory and `SHA256SUMS` all re-verified, with
  `verify_against_tree` reporting `source_bound: true`.

### Completion pass 5 (authority/evidence binding + serving integrity)

- **A pass receipt could qualify any candidate.** `CandidateRegistry`
  authenticated the receipt signature but never the receipt's
  relationship to the candidate; both campaigns qualified every skill
  and memory variant with one arbitrary holdout pass receipt. Added
  `CandidateEvidenceV1` (evaluator-signed binding of receipts to one
  exact candidate record/content digest, holdout partition, protocol)
  and `CandidateEvidenceAuthority`; qualification now requires every
  cited receipt to be covered by an authenticated binding that names
  the candidate. Unrelated receipts fail with
  `evidence_receipt_not_bound` / `evidence_candidate_digest_mismatch`.
- **Serving state was a mutable column gated by a role string.**
  Added `CandidateDecisionV1` (operator-signed exact-edge decision) and
  `CandidateDecisionAuthority`; `evaluating→qualified` and
  `qualified→revoked` now require a decision binding the candidate
  digest, edge, evidence handles and actor identity. Decision nonces
  are consumed atomically with the transition (`decision_replayed` on
  reuse).
- **The state column is no longer trusted.** Every read folds the
  hash-chained transition log, requires the committed state column to
  match, and re-authenticates the decision/evidence behind each
  qualified candidate. A direct SQL flip raises
  `state_projection_drift`; the gateway abstains `catalog_unavailable`
  with an audited `integrity_error`. Legacy qualified rows are
  `state_not_decision_backed`, excluded from serving, and revocable
  under a signed decision.
- **Serving outcomes are receipt-authenticated.** `record_outcome`
  resolves the receipt through a configured authority and requires the
  same task and outcome; a bare digest no longer writes a
  `serving_outcome` row. A revoked evidence receipt/binding suppresses
  the candidate (`evidence_revoked`).
- **Campaigns evaluate each candidate individually.** Both campaigns
  now run a sealed-holdout probe composed from one candidate at a time,
  then issue a candidate-specific evidence binding and decision. The
  deterministic campaign still reproduces A=0/B=2/C=2/D=0/E=2 and
  qualifies 5 candidates; the live dry-run still passes.
- Suite: **762 passed, 2 skipped** (741 + 21 new candidate/serving
  tests). Full suite re-run at this tree.

### Completion pass 6 (review repairs on pass 5)

- **The upgrade resealed an already-chained database without checking
  it.** Adding the evidence/decision fields changed the audit digest
  domain, so opening a v3.3 database recomputed every `entry_digest` —
  silently laundering any tampering performed before the upgrade and
  invalidating pre-upgrade external anchors. `_migrate` now verifies the
  old chain end-to-end against the old domain first; a broken
  pre-migration chain refuses to open
  (`audit_chain_tampered:pre_migration_*`), a clean one is resealed and
  recorded in `registry_migration`, reported by
  `verify()["migrations"]`.
- **A missing decision/evidence row froze the whole catalog.** `_project`
  raised on absence, and `submit`/`transition` call it, so a lost
  artifact row blocked intake and takedown as well as serving. Missing
  rows are now `unbacked` reasons (`decision_missing`/`evidence_missing`):
  serving still fails closed, but the catalog stays writable and the
  candidate can be revoked under a signed decision.
- **Expiry compared timestamps as strings.** `2026-10-25T10:00:00+05:00`
  (= 05:00Z) was accepted at 08:00Z, and a fractional second past expiry
  was accepted. Expiry is now compared as parsed UTC instants, and
  `expires_at <= issued_at` is refused at issuance.
- **Revoking the decision did not stop serving.** Basis revocation
  covered receipts and evidence bindings but not the decision digest;
  the decision is now part of the revocation basis, and
  `qualified_bases()` folds and authenticates the catalog once per serve
  instead of once per candidate.
- **Protocol pinning was optional while the docs claimed it was
  required.** Qualification without `expected_evaluation_protocol_digest`
  now refuses (`qualification_requires_expected_protocol`), and a
  serving replica without the pin cannot read the qualified catalog
  (`serving_protocol_unpinned`).
- **Probes bypassed the governed evaluation.** Both campaigns called
  `harness.run` directly for the per-candidate probe, skipping
  repository-disjointness and conformance accounting while citing the
  preregistered protocol digest. Added `run_candidate_probe`, which
  enforces disjointness and records budget/sample-size conformance; the
  evidence records that block, and a candidate that composes no guidance
  is reported as `no_guidance` instead of being bound to a pass.
- Suite: **777 passed, 2 skipped** (762 + 15 review-repair tests).
- Release re-binding: `release/` and
  `evidence/qualification/qualification_run.json` are regenerated from
  the commit that carries this report — the suite and deterministic
  campaign rows were re-run there, and the live/failure-injection rows
  are marked as carried over from `980dd34`. `tools/package_release.py`
  refuses a dirty tree by design, so the archive is built only from the
  clean commit; its exact source commit is recorded in
  `release/release_manifest.json`.

### Completion pass 7 (skill ingestion, M10)

- **Real skills had no governed entry point.** The candidate plane could
  generate skill variants from episodes but could not ingest a skill a
  human had written; `skill_package.import_bundle` only accepted a
  pre-built SIS bundle. Added `sis.v3.skill_ingest` and
  `tools/ingest_skills.py`: a skill directory or tree (`SKILL.md` +
  `references/`/`scripts/`/`assets/`) becomes a bounded `CandidateV1`
  of type `skill_bundle` at PROPOSED, submitted by the `learner` role.
- **Bounded, non-executing parse.** Frontmatter is parsed with a
  dependency-free scalar reader; the body is split into contract-sized
  instruction chunks (the v1 contract caps any string at 4 KiB, and real
  bodies are larger); resources are recorded by digest and size, never
  inlined; symlinks, traversal, hidden files, non-UTF-8 and control
  characters are refused.
- **Ingestion is not qualification.** A claimed `qualified` status is
  ignored, no signing material is held, and scan findings (shell tokens
  in served steps, prompt-injection phrasing in the body) are advisory
  and reported. The end-to-end test ingests a skill, qualifies it with
  evaluator evidence and an operator decision, and serves its steps
  through the gateway.
- Validated against the workspace catalogs: 33/34 `skills-main` and
  20/21 `vskill` skills ingest at PROPOSED; the two rejections are
  skills whose body or resource set exceeds the record bound and are
  reported with reasons. Re-ingesting either tree is a no-op.
- **Worked holdout registry.** `tools/skill_holdouts.py` holds the
  examples; `tools/skill_holdout.py` runs ingest → probe (arm E with the
  skill's guidance, arm A without) → `CandidateEvidenceV1` +
  `CandidateDecisionV1` → serve → recorded outcome. Registered:
  `write-skills`, `php2shell-check` and `write-tests` (a meta-test that
  requires the submitted suite to pass on the original and fail on a
  mutated implementation). All three qualify and serve their steps with
  A=0/E=1; the registry also records planned A/B tiers and every excluded
  skill with a reason, and the tool exposes `--list`, `--tier`, `--only`.
- `OutcomeVerifier` accepts an explicit resource envelope (default
  unchanged). The holdout tool sets `process_count=None` because the
  `write-tests` meta-test forks a nested test run, which `RLIMIT_NPROC=64`
  blocks on macOS.
- Suite: **804 passed, 2 skipped** (777 + 27 ingestion/holdout tests).

## Defects found and fixed during the build

| defect | fix |
|---|---|
| `preregister` crashed on float alpha/min_effect (canonical_json rejects floats) | digest a normalized copy; raw values retained in doc |
| `report_digest` crashed on float metrics | same normalization |
| campaign: strict partition rule blocked dev reuse | disjointness relaxed to seal holdout/monitoring while allowing induction↔development overlap (documented) |
| campaign: double `verifier.evaluate` on identical trees → `duplicate_evaluation` | reuse harness-issued receipts via `load_receipt` |
| campaign: raw step concat starved real steps behind an 8-item cap | merge via `compose_guidance` |
| campaign: buggy `clamp` fixture passed its own test; `dedup`/`clamp` holdouts untransferable by design | holdouts redesigned as unseen-repo variants `money2`/`slug2` of the dev conventions |
| campaign: `scripted_agent` wrote `<task>.py` not the fixture's module | write the declared module name |
| release build: extracted-tree compile/smoke results were recorded but never enforced | both fail the build; smoke return code recorded; 4 regression tests |
| candidate qualification accepted an unrelated pass receipt | evaluator-signed `CandidateEvidenceV1` binding receipts to the exact candidate; campaigns probe each candidate individually |
| candidate serving state was a mutable column gated by a role string | operator-signed `CandidateDecisionV1`, audit-derived state projection, serve-time re-authentication, atomic nonce consumption |
| upgrade resealed an already-chained database without verifying it (laundered pre-upgrade tampering) | verify the old-domain chain first; refuse on break; record the reseal in `registry_migration` |
| a missing decision/evidence row froze intake and takedown along with serving | missing rows become `unbacked` reasons; serving fails closed, the catalog stays writable |
| expiry compared ISO-8601 strings, so an offset or fractional second bypassed expiry | compare parsed UTC instants; refuse `expires_at <= issued_at` |
| revoking the decision did not stop serving | decision digest joins the revocation basis; one fold per serve via `qualified_bases()` |
| protocol pinning was optional while the docs claimed it was required | qualification and qualified reads require `expected_evaluation_protocol_digest` |
| per-candidate probes bypassed disjointness/conformance accounting while citing the protocol | `run_candidate_probe` enforces both and records conformance in the evidence |
