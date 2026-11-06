# SIS v3.3 qualification report

Release designation: **SIS-v3.3.0-GOVERNED-LEARNING**
Branch: `codex/sis-v3.3-governed-learning`
Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED**

This report supersedes the historical SIS3-013 ledger (retained in Git
history). It records what was executed for this release, not what was
planned.

## Gate ledger

| Gate | Evidence | Result |
|---|---|---|
| Source baseline traceable | `docs/audits/BASELINE_INTEGRITY.md`, `evidence/baseline/` — all four manifest discrepancies traced to pushed commits; manifest was stale, not tampered | **PASS** |
| Authority transactions | `tests/v3/test_authority_db.py` (WAL, fault-at-each-step, power loss, stale head, concurrent promotion) | **PASS** |
| Receipt authenticity | `tests/v3/test_receipt_signatures.py` (forged signer, tampered body, replay, wrong key) | **PASS** |
| Qualification evidence | `CandidateRegistry` requires `receipt_authority` (signed pass receipt), `evidence_authority` (evaluator-signed `CandidateEvidenceV1` naming the exact candidate/holdout partition and the registry's pinned protocol), `decision_authority` (operator-signed exact-edge `CandidateDecisionV1`), and a pinned `expected_evaluation_protocol_digest` (unpinned registries cannot qualify or serve qualified candidates) | **PASS** |
| Trust-domain separation | policy roles: learner/evaluator/operator; learners hold no signing material or authority writes | **PASS** |
| Memory provenance | `verify_experience_evidence` binds ingest to the evaluator journal and signed outcome | **PASS** |
| Sealed holdout | partition disjointness + repository-disjointness enforced before runs | **PASS** |
| Governed serving | scope/revocation/applicability/counterexample gates; serve-time re-authentication of decision + evidence; direct state flips abstain; prompt injection served as data only | **PASS** |
| Revocation/rollback | revoked candidates stop serving immediately; signed revocation decision; audit chain verifies | **PASS** |
| Release integrity | ZIP ↔ embedded manifest ↔ source tree all verified; `release/` excluded from the archive | **PASS** |
| Learning efficacy | live campaigns below | **NOT ESTABLISHED** |

## Executed verification

| Command | Result |
|---|---|
| `PYTHONPATH=src python3 -m pytest tests/ -q` | **804 passed, 2 skipped, 0 failed** |
| `PYTHONPATH=src python3 tools/governed_campaign.py -o <dir>` | exit 0; A=0 B=2 C=2 D=0 E=2; 5 candidates qualified; revocation demo passed |
| `PYTHONPATH=src python3 tools/governed_live_campaign.py -o <dir> --wall 120` | exit 0; authenticated `codex exec`; A=2 B=2 C=2 D=2 E=2 (ceiling hit) |
| `PYTHONPATH=src python3 tools/live_study.py ... --wall 120` | A=4 B=3 C=3 D=5; D-vs-A 1W/0L, McNemar p=1.0 (underpowered) |
| `python3 tools/verify_release.py <zip>` | 306-file archive verified against embedded manifest |
| fresh extraction + `verify_tree` + `compileall` + extracted test smoke | pass |
| `python3 tools/smoke_integration.py` | CLI + authed loopback HTTP smoke pass |
| security failure injection (13 scenarios) | 13/13 green (`evidence/security/failure_injection.json`) |

## Efficacy verdict

**EFFICACY_NOT_QUALIFIED.**

- The deterministic campaign proves the machinery end-to-end with a
  scripted agent. It is not evidence about a real model.
- The live governed campaign ran the full lifecycle with a real
  authenticated Codex agent, but every arm solved both holdout tasks
  unaided. The fixtures are below the model's ceiling, so the contrast
  is null, not negative.
- The six-task live study is directionally positive for served
  procedures (D=5 vs A=4) but p=1.0 and n=6. It cannot support a claim.
- No preregistered powered holdout has been run. A claim of improved
  coding outcomes would be unsupported.
- Negative transfer is unit-tested against the audited
  `remaining_balance` false-transfer fixture (abstains with
  `prior_negative_transfer`, no procedure IDs). The live campaigns
  contain no deliberately misleading holdout, so
  `negative_transfer_rate` is `null` rather than measured live.

## What is proven

- A verified episode can become a memory candidate, and qualification
  requires three signed artifacts: an authenticated pass receipt, an
  evaluator-signed evidence binding naming that exact candidate on the
  holdout partition under the expected protocol, and an operator-signed
  decision for the exact serving-state edge. An unrelated pass receipt
  cannot qualify a candidate.
- Candidate serving state is derived from the hash-chained transition
  log and re-authenticated on every serve; a direct SQL flip, a forged
  decision/evidence row, or a legacy unbacked qualification abstains
  instead of serving.
- Candidate text cannot grant permissions, alter policy, or reach
  authority; serving is scope- and revocation-gated and audited with
  the task and the authenticated outcome receipt.
- Promoted artifacts are content-addressed, immutable in record form,
  auditable (hash-chained), revocable, and exportable/re-importable
  with unchanged identity.
- The release archive is source-bound: it cannot silently ship stale
  code, and `release/` can no longer be embedded recursively.

## What is not proven

- That any of the three learning tracks improves solved-task rate on
  unseen repositories under a powered, preregistered design.
- OS-level isolation: execution remains `isolation:unverified_local`.
- Cost per verified solve: not metered (`None`, never fabricated).
- Semantic (not lexical) conflict/counterexample detection.

## Release decision

Security and correctness gates pass. The release is published as
**IMPLEMENTED_NOT_EFFICACY_QUALIFIED** — the strongest claim the
evidence supports. A security or integrity blocker would take
precedence over any benchmark result; none is open.
