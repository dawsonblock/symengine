# SIS v3.3.0 — Governed Learning — Release Notes

Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED**

Security/correctness gates pass; learning efficacy on real models is
deliberately not claimed. See `V33_LIMITATIONS.md`.

## What is new

- **Typed candidate plane** — `CandidateV1` (six artifact types) plus
  `CandidateRegistry`: WAL sqlite, role-gated transitions,
  operator-only qualification requiring an authenticated pass receipt,
  an evaluator-signed `CandidateEvidenceV1` binding those receipts to
  the exact candidate, and an operator-signed `CandidateDecisionV1`;
  append-only transition audit, digest-verified reads, and an
  audit-derived state projection that refuses direct state flips.
- **Experience memory** — `ExperienceRecordV1`, `MemoryStore`
  (episode-replay rejection, tamper-proof), `induce_candidate`,
  gated `retrieve_memories` with abstention.
- **Skill evolution** — `SkillOptimizer` with pure-payload mutators,
  injected dev evaluator, hard budgets, ranked frontier; intake-only
  output.
- **Composition policy** — `compose_guidance`: typed precedence,
  dedup, conflict handling (`precedence`|`abstain`), token budget.
- **Governed evaluation plane** — five paired arms (A–E), sealed
  holdout partitions, preregistered protocol digests, powered sample
  sizing, abstention/negative-transfer metrics.
- **Governed serving** — `GovernedServingGateway`: registry-resolved
  repo identity, scope/revocation/applicability/counterexample gates
  with per-candidate rejection audit; serve-time re-authentication of
  the decision/evidence behind every qualified candidate; advisory-only
  output; outcomes require an authenticated receipt for the served task.
- **vskill-style packaging** — export/verify/import of skill bundles;
  imports land at PROPOSED regardless of claimed status.
- **Skill ingestion** — `tools/ingest_skills.py` turns real skill
  directories (`SKILL.md` + resources) into bounded `skill_bundle`
  candidates at PROPOSED, with traversal/symlink/size limits and an
  advisory scan; qualification still requires signed holdout evidence.
- **Skill holdout registry** — `tools/skill_holdouts.py` and
  `tools/skill_holdout.py` ship three worked examples (`write-skills`,
  `php2shell-check`, `write-tests`) that run ingest → holdout probe with
  and without guidance → evaluator evidence + operator decision →
  serving. The registry records planned tiers and excluded skills with
  reasons; `--list`, `--tier` and `--only` select examples, and the
  `write-tests` meta-test requires the submitted suite to catch a
  mutated implementation.
- **Migration and revocation hardening** — upgrading a v3.3 registry
  reseals its audit chain only after the old chain verifies against the
  old digest domain (recorded in `registry_migration`); a missing
  decision/evidence row excludes the candidate instead of freezing the
  catalog; expiry is compared as parsed instants; a revocation naming
  the decision suppresses serving.
- **Deterministic campaign CLI** — `tools/governed_campaign.py`
  produces `campaign_evidence.json`: A=0, B=2, C=2, D=0, E=2 on
  unseen-repo holdouts (machinery evidence).

## What did not change

- v3.2 authority model, receipt signing, statement binding, source-change
  capture, strict procedure gateway, four-arm benchmark default.
- `report_digest`/`preregister` now tolerate floats via deterministic
  normalization — digest *values* differ from a hypothetical
  un-normalized computation, but semantics are unchanged and stable.

## Verification

- `PYTHONPATH=src python3 -m pytest tests/ -q`
- **804 passed, 2 skipped** (v3.3 adds registry, memory, evolution,
  composition, serving, packaging, governed-eval, campaign and
  release-binding tests, plus authority/evidence-binding and serving
  integrity regressions).- Every module compiles (`python3 -m py_compile`).
- `python3 tools/verify_release.py release/SIS-v3.3.0-GOVERNED-LEARNING.zip`
  verifies the archive against its embedded manifest; the build also
  re-hashes every member against the source tree it came from
  (`verify_against_tree`) and records the Git commit.

## Post-build review repairs

- **Authority/evidence binding.** Candidate qualification used to
  authenticate a pass receipt but not its relationship to the
  candidate; one arbitrary holdout receipt could qualify every skill
  variant. Qualification now requires an evaluator-signed
  `CandidateEvidenceV1` naming the exact candidate, holdout partition
  and protocol, plus an operator-signed `CandidateDecisionV1` for the
  exact edge. Both campaigns run a per-candidate holdout probe.
- **Serving integrity.** `qualified`/`revoked` were mutable columns
  gated by a caller-supplied role string. The registry now derives
  state from the hash-chained transition log, re-authenticates the
  signed decision/evidence on every serving read, rejects direct SQL
  flips (`state_projection_drift`), consumes decision nonces atomically,
  and excludes legacy unbacked qualifications. `record_outcome`
  requires an authenticated receipt with the same task and outcome.
- **Release binding.** The previously shipped ZIP predated the hardening
  commit, and the build could embed the previous ZIP inside the next one
  because `release/` was inventoried. `release/` is now out-of-band:
  excluded from the archive manifest, rejected as an archive member, and
  the build refuses a dirty source tree and re-hashes the archive
  against the working tree.
- **Qualification evidence.** `CandidateRegistry` now requires a
  deployment-supplied `receipt_authority`; every cited digest must
  resolve to a signature-authenticated receipt with outcome `pass`.
  Wiring this in exposed a latent flake where qualification could cite
  a synthetic authority-demo receipt; holdout evidence is now separate
  and a run without a verified pass receipt refuses to qualify.
- **Regression metric.** `verified_regression_rate` is now relative to
  baseline solves (baseline cannot regress against itself);
  `failure_rate` carries the absolute number.
- **Memory evidence.** `MemoryStore.ingest` accepts an
  `evidence_check` hook; both campaigns bind it to
  `verify_experience_evidence`, which resolves and verifies the signed
  receipt and requires the signed outcome to match the record.
- **Serving audit.** Served guidance rows carry `task_id`;
  `record_outcome` binds a receipt digest and outcome to the exact
  guidance digest the gateway served.
- **Fresh-extraction gate.** `package_release` recorded the extracted
  tree's compile and smoke results but never checked them, so a broken
  archive could ship under a green manifest. Both now fail the build,
  and `verification.json` records the smoke return code. Four
  regression tests cover the gate.

## Upgrade notes

- No schema migrations needed for v3.2 state; new stores are new files.
- Callers opting into arm `E` must pass `arms=("A","B","C","D","E")`.
- `CandidateRegistry.qualify` requires `receipt_refs` **and** a
  `receipt_authority` callable configured at registry construction —
  wire real evaluator verification, never placeholders.
- `MemoryStore.ingest` should be called with
  `evidence_check=verify_experience_evidence` in production ingestion.
