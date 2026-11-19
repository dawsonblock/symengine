# SIS v3.3.3 — Trust-Boundary Repair

Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED**

This is the current release. It closes five externally audited
trust-boundary defects; the red-to-green reproductions are in
`tests/v3/test_v333_trust_boundary.py`.

## What changed

- Local execution can no longer self-certify isolation:
  `LocalSubprocessExecutor` never mints `isolation:verified` and refuses
  `verified_isolation=True`; production classification requires an
  independently signed `IsolationAttestationV1` (`sis.v3.isolation`),
  never a self-reported marker.
- Experience evidence binds the full evaluation lineage: evaluator-signed
  `ExperienceRecordV2` records are checked against task, attempt,
  repository snapshot and execution receipt (via the evaluator journal)
  before they can enter memory; V1 records are legacy/untrusted reads.
- `MemoryStore` integrity: trusted-signer mode accepts and serves only
  signed V2 records, re-verifying on every access, and an append-only
  `memory_chain` (custodian-signed when `chain_key` is configured)
  detects mid-history deletion, rewrites and forged entries.
  `repair_chain` migrates pre-chain databases, `last_chain_failure`
  reports the check that failed, and `head_digest` is the external
  rewind witness — pinned into campaign evidence by the governed tools.
- Paraphrase-tolerant counterexample suppression: content-token
  containment ignores function words and negation framing so rephrased
  unsafe conditions still suppress memory transfer (heuristic;
  over-fires toward suppression, auditable via `on_suppress`).
- Signature-directed stage-2 search: induction compares evaluation
  signatures over train+validation+probe inputs and emits only
  combinations guaranteed to fit, closing the enumeration-order
  starvation that hid representable rules inside the candidate budget.
- Release provenance is bound to the shipped source: a suite test fails
  when manifest-covered files changed after `source_commit`.

## Test evidence

- Default suite: **1122 passed, 12 skipped, 0 failed**
  (`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 PYTHONPATH=src
  python3 -m pytest -q`).
- Five audited defects reproduced on the prior tree and closed on this
  one; chain migration/repair, key adoption and suppression-audit paths
  are covered in the same suite.

## Not qualified

- Evaluator isolation (M6): the attestation contract is implemented and
  verified, but no in-tree backend or isolator signer produces
  attestations — the production gate stays closed until a qualified
  isolator exists.
- Real-agent efficacy (M9): unchanged; no improvement is claimed.

## Artifacts

- `release/SIS-v3.3.3.zip` (384 files), verified against
  `RELEASE_SHA256.json`.
- `release/provenance.dsse.json`, signed with a `qualification-only` key.

---

## SIS v3.3.2 — Authority Consistency & Runtime Closure (previous release)

Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED**

Superseded by v3.3.3. The detailed engineering record is in
`docs/V332_AUTHORITY_CONSISTENCY.md`; deployment and recovery are in
`docs/V332_OPERATIONS.md`; executed acceptance scenarios are in
`docs/V332_ACCEPTANCE_MATRIX.md`.

### What changed

- Shared SQLite/PostgreSQL control plane: atomic nonce consumption and
  decision receipts across replicas.
- Authority checkpoints witness revocation, supersession and custody entry
  counts; restoring custody history fails closed.
- Authenticated v3 serving boundary (`/v3/guidance`, `/v3/outcome`), legacy
  `/v1` isolation, readiness reporting, and exact outcome binding.
- Production isolation gate: `LocalSubprocessExecutor(production=True)`
  refuses to run without `verified_isolation=True`.
- Signed SLSA-shaped release provenance, a dependency lock, and a PostgreSQL
  CI job.

### Test evidence

- Default suite: **986 passed, 8 skipped** (981 at the original M0–M5
  qualification; five release-tooling tests were added in review).
- PostgreSQL suite (`SIS_POSTGRES_DSN`): **986 passed, 3 skipped**.
- Five v3.3.1 defects reproduced on the baseline and closed on this tree.

### Not qualified

- Evaluator isolation (M6): the seatbelt/subprocess backend is not a validated
  OS boundary; hostile-code execution stays disabled in production.
- Real-agent efficacy (M9): the external Codex quota blocked the preregistered
  run; no improvement is claimed.
- Full multi-host PostgreSQL deployment, a disaster-recovery drill, and SLSA
  *level* conformance.

### Artifacts

- `release/SIS-v3.3.2-AUTHORITY-CONSISTENCY.zip` (375 files), verified against
  `RELEASE_SHA256.json`.
- `release/provenance.dsse.json`, signed with a `qualification-only` key.

---

## SIS v3.3.1 — Authority Closure and Governed Skill Learning (previous release)

### Release classification

**`IMPLEMENTED_NOT_EFFICACY_QUALIFIED`**

- P0 authority, evaluation-certificate, execution-identity and evidence
  custody gates are implemented and covered by adversarial tests.
- The evaluator sandbox is implemented as defense-in-depth (seatbelt,
  resource limits, protected-path denial, network denial). It is **not**
  a validated OS boundary; production hostile-code evaluation requires a
  rootless worker or microVM.
- A real five-arm Codex run was **attempted** (8 preregistered tasks).
  Codex hit its usage limit after 20 of 40 arm runs; the final four
  tasks had zero tool events and are classified as infrastructure
  failures, not task failures. The real-agent gate is therefore
  `BLOCKED_EXTERNAL_AGENT_QUOTA`; no efficacy claim is made. The runner
  now fails closed on no-action/error events.

### What changed

#### Authority closure (P0)

- `AuthorityCheckpointV1`, `FileAuthorityCheckpointStore`,
  `AuthorityJournal`, `AuthorityStateVerifier`.
- Monotonic sequence, previous-digest chain, authority epoch, journal
  head/sequence and candidate-revision digest.
- Compare-and-append with OS file locking and atomic replacement.
- Crash-recoverable publication; local-ahead serving denial;
  rollback/divergence detection.
- Production serving requires a checkpoint-verified registry; a
  local-only database is not rollback resistant.

#### Evaluation evidence closure (P0)

- `EvaluationCertificateV1`, `QualificationPolicy`,
  `QualificationValidator`, `ProtocolRegistry`.
- Evidence classes: exploratory, demonstration, confirmatory, invalid.
- Candidate-delivery attestations; actual delivered artifact is bound per
  task.
- Sample size, preregistration, protocol conformance, holdout partition,
  statistical acceptance, negative transfer, revocation and scope are
  re-derived. A 2-task run cannot satisfy a 29-task protocol.
- Production qualification requires a certificate; demonstration
  registries cannot serve production.

#### Execution identity and custody (P0)

- `ExecutionIdentityV1` and `ExecutionIdentityAuthority`.
- Tree/commit/family/workspace/task/nonce binding, expiry and replay
  checks; contradictory claims abstain with no actionable instructions.
- `EvidenceCustodyStore`: immutable objects, dependency links, signed
  revocation/supersession logs, explicit offline policy.
- Deleted, altered, revoked, superseded or unavailable evidence fails
  closed.

#### Skill ingestion (P1)

- Scope-aware candidate ids; identical content for two scopes produces
  two candidates; metadata conflict is explicit.
- Structured Markdown parser; code fences, quotes and example commands
  never become active instructions; line references preserved.
- High-severity prompt-injection/shell-step findings block automatic
  qualification and are preserved for review.
- Discovery raises rather than silently truncating at 500; pagination and
  explicit completeness flags.
- Bounded large documents (96 KiB accepted, full body SHA-256, explicit
  inline truncation), frontmatter variants, duplicate/symlink/size
  safeguards, never executes installation scripts.

#### Evaluator reliability and sandbox (P1)

- Pinned runtime profile (Python 3.12, pytest 8.4.2), plugin autoload
  disabled, explicit plugin policy.
- Bootstrap probe separates evaluator initialization from task execution.
- 2 GiB default address-space envelope; all three scripted holdouts run
  without manual memory-limit changes.
- Outcome taxonomy: TASK_PASS, TASK_FAIL, EVALUATOR_BOOTSTRAP_ERROR,
  RESOURCE_LIMIT, TIMEOUT, SANDBOX_FAILURE, EVIDENCE_FAILURE,
  INFRASTRUCTURE_ERROR.
- Seatbelt denies protected paths (keys, evaluator registry, authority
  stores) and network; receipts record isolation facts.

#### Learning qualification (P1)

- Five-arm campaign (`A` baseline, `B` memory, `C` skills, `D` symbolic,
  `E` integrated), preregistered protocol, hidden/disjoint holdout,
  frozen candidate digests.
- Exact McNemar, Wilson intervals, Newcombe difference interval, power
  analysis, negative transfer, resource overhead, failure categories,
  integration-vs-components.
- Scripted demo is labelled demonstration and cannot claim efficacy.
  The real-agent runner is implemented and was executed until the Codex
  quota blocked it; the gate remains externally blocked.

### Test evidence

- Baseline v3.3 branch: **804 passed, 2 skipped**.
- v3.3.1: **926 passed, 3 skipped, 0 failed**
  (`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 PYTHONPATH=src
  python3 -m pytest -q`).
- New suites: authority checkpoints 23, evaluation certificates 22,
  execution identity/custody 22, skill ingestion hardening 19 + 1 skip,
  evaluator runtime 19, learning qualification 15.
- Skill compatibility: 65/66 vskill `SKILL.md` files parse; the one
  rejection is an e2e fixture with no description and only an HTML
  comment body. Five large documents were explicitly truncated with
  preserved body digests.
- Scripted holdouts: `write-skills`, `php2shell-check`, `write-tests` all
  qualified under the pinned 2 GiB profile; A 0/1, E 1/1 each.

### Known limitations

- Windows is an experimental CI target. The local vault ACL and SQLite
  lifecycle tests are POSIX-specific; Linux/macOS POSIX is the supported
  evaluator platform for this release.
- Local sandbox is not a validated hostile-code boundary.
- Checkpoint/custody separation is a deployment requirement; a principal
  that can write both the candidate DB and the checkpoint store defeats
  rollback resistance.
- A compromised authority or evaluator key defeats its corresponding
  gate.
- Pattern-based injection scanning is advisory, not proof of safety.
- No valid powered real-agent efficacy result: the Codex quota blocked
  the attempt after four of eight tasks; no claim of improvement.

### Artifacts

- `release/SIS-v3.3.1-AUTHORITY-CLOSURE.zip`
- `release/RELEASE_SHA256.json` (in-archive inventory)
- `release/release_manifest.json`, `release/source_inventory.json`,
  `release/verification.json`, `release/SHA256SUMS` (out-of-band
  provenance)
- `evidence/` — baseline, authority, adversarial, ingestion, sandbox,
  evaluation and release evidence.
- `evidence/release/release_verification.json` is out-of-band: it
  contains the archive hash and therefore cannot be a member of the
  archive it describes.
