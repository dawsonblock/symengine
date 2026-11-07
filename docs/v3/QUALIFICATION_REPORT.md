# SIS v3.3.2 development qualification status

Updated: 2026-11-07. Base revision: `39c3be10b46458e3b4d990d8f6c45fc34d6ba110`
plus uncommitted evidence-qualification, SQLite-test, and release-check repairs.
Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED**. This is an unsigned development
snapshot, not a newly published or signed release.

## Current scope and limitations

- Qualification now requires paired baseline outcomes by default and agreement
  between certificate primary metric and qualification policy. The explicit
  legacy opt-out remains digest-visible. Historical signed certificates are
  preserved; changed policies require new certificates (see `MIGRATION.md`).
- Six tests in `tests/v3/test_control_plane_sqlite.py` exercise real SQLite
  file-lock serialization, replay protection, outcome binding, and shared
  serving decisions. They are included in the development archive even while
  untracked in Git. They do not qualify PostgreSQL or multi-host operation.
- PostgreSQL qualification is still unrun: no disposable DSN is configured,
  and the earlier private server setup was denied at `shmget`. No workaround
  or retry was attempted for this repair.
- Twelve evaluator/campaign tests previously hit `sandbox_apply: Operation
  not permitted` in this execution context. They are explicitly deselected
  from this repair's broad test run, not passed or relabelled. The prior
  Devin run of 1011 passed / 11 skipped predates the SQLite and CI tests and
  is historical evidence, not a full pass for this snapshot.
- Real-agent efficacy remains unestablished. A sealed, repository-disjoint,
  powered study, validated execution isolation, model availability and a
  precommitted run budget remain prerequisites. No live paid run was made.

## Verification of this development repair

- Broad permitted suite: **1013 passed, 11 skipped, 12 deselected** (48.90s),
  Python 3.12.0 / pytest 8.4.2 on macOS. The deselections preserve the earlier
  sandbox denial boundary. Skips: 8 PostgreSQL, 1 Windows ACL, 1 missing skill
  corpus, 1 unavailable pinned Git baseline.
- Focused release/CI/SQLite suite: **40 passed** (3.25s).
- These are local results. The updated GitHub workflow has not been pushed or
  observed running remotely, and no full current-snapshot pass is claimed.

## Release verification policy

Tags and published GitHub releases run `tools/check_release_ci.py --mode
release`: stale, missing, malformed, or incomplete inventories fail the job.
Ordinary branch/PR CI uses explicit development mode, which permits inventory
drift but labels it **not release verification**. Missing/malformed manifests
still fail. Neither mode regenerates the manifest to hide a mismatch.

The development ZIP is rebuilt with `tools/build_canonical_zip.py --allow-dirty`,
then checked internally, against the complete current source tree, and after
fresh extraction. Its commit and dirty paths are recorded alongside its hash.
The output and local verification logs are in `build/release-repair-20261107/`;
`build/` is intentionally excluded from distributed source. The refreshed
`RELEASE_SHA256.json` is an unsigned inventory, not publisher authentication.
Historical signed provenance under `release/` is unchanged and does not attest
this development ZIP.

## Historical v3.3.0 qualification report (retained verbatim below)

The following report records its original release and test environment only.
Its 804-test count, 306-file archive, gate passes, and release decision are
not current qualification claims for the development snapshot above.

# SIS v3.3 qualification report

Release designation: **SIS-v3.3.0-GOVERNED-LEARNING**
Branch: `codex/sis-v3.3-governed-learning`
Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED**

This report supersedes the historical SIS3-013 ledger (retained in Git
history). It records what was executed for this release, not what was
planned.

## Gate ledger

| Gate | Evidence | Result |
| --- | --- | --- |
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
| --- | --- |
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
