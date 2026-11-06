# SIS v3.3.2 — Authority Consistency & Runtime Closure (M0–M5)

Status: **implementation complete for M0–M5; production security
qualification is not claimed.** M6–M9 remain open. This document records
exactly what changed, how each v3.3.1 defect was reproduced, and which
claims remain unsupported.

## Baseline

| Item | Value |
|---|---|
| Baseline version | 3.3.1 |
| Baseline commit | `c6b6ea7eb9f7807ab5c898a20ca229991f90d8cd` |
| Baseline suite | 926 passed, 3 skipped |
| Python / pytest | 3.12.0 / 8.4.2 |
| Baseline evidence | `evidence/v332/baseline.json` |
| Reproduced defects | `evidence/v332/baseline_reproduction.json` |
| Fixed reproduction | `evidence/v332/fixed_reproduction.txt` |

The pristine v3.3.1 worktree was kept out of the release tree and the
five target defects were executed there. All five reported `open: 5`.
The same checks report zero open defects on this tree. Source hashes for
the five files that carry the fixes are recorded in `baseline.json`.

## Reproduced defects and fixes

### D1 — Execution identity could be disabled in production

`GovernedServingGateway(production=True, require_execution_identity=False)`
accepted unauthenticated requests and delivered learned text.

Fix: production construction rejects `require_execution_identity=False`
and requires a shared control plane. `ExecutionIdentityAuthority` now
enforces an explicit maximum lifetime (default 3600 s) and the gateway
can bind the authenticated caller's requester identity into the signed
session check. Missing, expired, over-long, contradicted or disabled
identity produces no guidance.

### D2 — Replay protection was process-local

The gateway held `used_session_nonces` in a Python set and added the
nonce after verification. Two replicas each accepted the same signed
session; two threads could race the check-then-add.

Fix: `sis.v3.control_plane` provides a durable `session_nonce` table.
`commit_authorization` inserts the nonce and the decision receipt in one
transaction, so exactly one racing replica commits. Production cannot
construct a gateway without a control plane.

### D3 — Custody rollback was invisible

`AuthorityCheckpointV1` covered the candidate journal only. Restoring a
pre-revocation custody directory left `custody.verify()` healthy and
serving unaffected.

Fix: checkpoints now carry `revocation_head`, `supersession_head` and
`custody_entry_count`. `AuthorityStateVerifier` rejects a local custody
state that is behind, diverged or missing. A custody revocation must be
followed by a checkpoint publication before serving resumes. Checkpoints
with no custody history remain byte-identical to v3.3.1, so existing
signatures and the previous-digest chain still verify
(`tests/v3/fixtures/v331_checkpoints`).

### D4 — Diamond-shaped evidence graphs were rejected

`EvidenceCustodyStore.status` used one shared `visited` set for the
whole traversal, so a valid shared dependency looked like a cycle.

Fix: traversal keeps the active path separate from a memo of completed
results, with depth and node bounds. Diamonds are `active`, real cycles
are `invalid`, and a revoked shared leaf still propagates `revoked`.

### D5 — Revocation could land during guidance composition

Serving authenticated the catalog, composed guidance, and returned it
without re-checking authority. A revocation committed in that window was
delivered anyway.

Fix: production serving captures a witnessed snapshot (checkpoint plus
custody heads), composes against it, then revalidates the snapshot and
commits the nonce and decision receipt atomically. A changed snapshot
aborts the decision. The control plane's `authority_head` row is
advanced by `AuthorityJournal.publish`, so a stale snapshot cannot
commit after a revocation publication.

## Control plane

`src/sis/v3/control_plane.py` implements two profiles behind one
interface:

- `SqliteControlPlane` — single-host development and single-host
  production. Uses `BEGIN IMMEDIATE`, WAL and a busy timeout.
- `PostgresControlPlane` — multi-process production. Uses
  `INSERT ... ON CONFLICT` and one transaction per decision. Requires
  the optional `psycopg` driver.

The signed checkpoint file remains the independent rollback witness.
The control-plane `authority_head` row is the serialization point, not a
replacement witness: restoring the whole database still fails against
the checkpoint file.

Schema: `session_nonce`, `authorization_receipt`, `guidance_outcome`,
`authority_head`.

## Production serving boundary (M5)

`src/sis/v3/serving_service.py` is the only production guidance entry
point:

- `POST /v3/guidance` requires `Authorization: Bearer <key>`; the key
  maps to a requester identity that is checked against the signed
  execution identity.
- `POST /v3/outcome` binds an authenticated outcome receipt to the
  committed authorization, not to an in-memory task map.
- Configuring the v3 service isolates legacy `/v1` learning routes
  by default (`SIS_V3_ONLY=1` also forces it); a migration window can
  opt back in with `SIS_ALLOW_LEGACY_V1=1`.
- `serve()` applies the configured custody freshness policy before
  composing and distinguishes `advisory` (qualified advice, no
  procedure authority) from `abstain` (no usable guidance).

`create_server` is exposed so deployments and tests can bind the service
without starting the process-global CLI loop.

## Qualification status

Passing:

- Full suite: **981 passed, 8 skipped** at the original M0–M5
  qualification (v3.3.1: 926 passed, 3 skipped). The review added five
  release-tooling tests, so the current tree is **986 passed, 8 skipped**.
- 50 security regression tests in
  `tests/v3/test_v332_security_regressions.py` and 5 provenance
  tests in `tests/v3/test_v332_release_provenance.py`.
- Five-defect reproduction: 5 open on v3.3.1, 0 open on this tree.
- v3.3.1 checkpoint signature and digest-chain compatibility.

Not qualified:

- **M6 evaluator isolation** — untrusted evaluation code is still not
  executed inside an independently validated OS sandbox. Hostile-code
  execution must stay disabled in production.
- **M7–M8** — control-plane schema versioning, full automated key
  rotation, a tested disaster-recovery drill and SLSA *level*
  conformance remain open. The canonical ZIP, regenerated inventory,
  dependency lock and signed in-toto/SLSA-shaped provenance are in
  place: `release/SIS-v3.3.2-AUTHORITY-CONSISTENCY.zip` (375 files)
  verifies against `RELEASE_SHA256.json`, and the provenance envelope
  verifies against the archive. The exact archive digest is recorded in
  `release/release_manifest.json`. The signing key is labelled
  `qualification-only`; a production trust root must be supplied by the
  release custodian.
- **M9 efficacy** — no real-agent benchmark improvement is claimed. The
  prior Codex quota block is unchanged; see
  `docs/V332_EFFICACY_STATUS.md`.
- **Release artifact** — `tools/verify_release.py .` reports 375 files
  matched; the ZIP and DSSE provenance both verify. CI now has a
  PostgreSQL job.

- **PostgreSQL** — the adapter was exercised against a disposable
  PostgreSQL 14.20 cluster: duplicate nonce rejection, four concurrent
  replicas producing exactly one commit, two replicas sharing one head
  producing one advisory decision, outcome binding and head monotonicity.
  The full suite with `SIS_POSTGRES_DSN` set is **986 passed, 3 skipped**
  (see `evidence/v332/qualification.json`). A real multi-host deployment
  must still be qualified against its own server, roles and network
  policy; a local cluster is not that qualification.

Custody revocations and supersessions publish a new checkpoint through
`EvidenceCustodyStore.bind_on_change` when a deployment binds
`journal.publish`. A publication failure propagates: the log entry is
durable but unwitnessed, and serving stays closed until the head is
published.
