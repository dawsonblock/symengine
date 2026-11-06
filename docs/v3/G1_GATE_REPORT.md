# G0/G1 Gate Report — V2 Authority Recovery → v3.1-alpha

Status date: 2026-10-24. Branch: `codex/sis-authority-transfer-qualification`.
Commits: `d79a813` (baseline import) · `35b9831` (PR-00 freeze) · `b4c9664` (PR-01/PR-02) · `f7429d0` (PR-02 migration tests).

This is an engineering gate report — **not** a v4.0 qualification certificate.
No efficacy, production-hardening, or cross-repository claims are made.

## Provenance (G0) — PASS

| Evidence | Value |
|---|---|
| Source archive | `SIS-2026-10-24-FULL-UPGRADED-V2-Authority-Recovery.zip` |
| SHA-256 (re-verified) | `f62ef2a500fe487cf17fb1b7d19862ab0eb686c411663b89d02011f310a7d077` |
| Baseline commit | `d79a813` — `git archive d79a813` diffed byte-identical to extracted archive |
| Focused baseline | `42 passed` (authority_recovery, upgrade_integrity_learning, benchmark, codex_adapter, retrieval) |
| Full-suite baseline | `562 passed, 2 skipped` — recorded in `docs/v3/V2_BASELINE.md` |

## G1 — one authority, transactional promotion, legacy deprecation — PASS

### PR-01: qualification is not a writable attribute

- `ProcedureStore.add` no longer accepts `allow_qualified` or any
  decision-managed status; intake is revision-1 `draft`/`candidate` only.
- `AuthorityDB.add_seed` applies the same contract to the authority store.
- `PromotionController` requires an `AuthorityDB`; constructing one with a
  JSONL log dir is rejected (`legacy JSONL decision journals are no longer a
  write target`).
- `GuidanceGateway` moved to `sis.v3.compat.guidance_gateway`; the old import
  path is a `DeprecationWarning` shim. `StrictGuidanceGateway` is the serving
  boundary and verifies store + projection on every request.

### PR-02: atomic decision+revision persistence

- `src/sis/v3/authority_db.py`: SQLite WAL, `synchronous=FULL`,
  `foreign_keys=ON`, `busy_timeout=15s`. Tables: `procedure_revision`,
  `signed_promotion_decision`, `receipt_binding`, `scope_grant`,
  `revocation`, `nonce_consumption`, `schema_migrations`, `audit_event`,
  `quarantined_revision`.
- `commit_transition` runs the full verification gate inside
  `BEGIN IMMEDIATE`: chain-head recheck, candidate binding, decision
  re-verification against replayed state, revision insert, decision insert,
  receipt bindings, qualified-head cross-check — all-or-nothing.
- `tools/migrate_authority.py`: dry-run reconciliation quarantines any
  rev-1 record carrying a decision-managed status and any rev>1 without a
  verified backing decision; `--execute` imports into a fresh AuthorityDB
  and re-verifies; `--cutover` keeps byte-identical backups and renames
  legacy files to `.migrated`; reports are Ed25519-signed.

### Test evidence (exact commands)

```
PYTHONPATH=src:. python3 -m pytest -q
  → 585 passed, 2 skipped   (17.2s)

PYTHONPATH=src:. python3 -m pytest -q tests/v3/test_authority_db.py
  → 16 passed  (fault injection at all 8 commit steps, 4-process concurrent
    writers, restart, WAL torn-write, stale writer, in-tx head recheck,
    double promotion, backup/restore, corrupted page)

PYTHONPATH=src:. python3 -m pytest -q tests/v3/test_migrate_authority.py
  → 6 passed   (quarantine, signed report verification, cutover/rollback)

PYTHONPATH=src:. python3 -m pytest -q tests/v3/test_promotion.py \
    tests/v3/test_authority_recovery.py tests/v3/test_retrieval.py \
    tests/v3/test_roadmap_modules.py tests/v3/test_procedures.py \
    tests/v3/test_upgrade_integrity_learning.py
  → all pass

python3 tools/build_release.py --check
  → release manifest covers 243 files and is current
python3 tools/verify_release.py --compile .
  → release verified: 243 files, all SHA-256 matched; compile check passed
```

### Shared adversarial matrix coverage (G1 scope)

| Requirement | Evidence |
|---|---|
| Direct catalog insertion / stale write API | `test_direct_qualified_write_rejected`, `test_strict_gateway_rejects_direct_qualified_catalog_seeding` (3 layers: API reject → verify fails → serving abstains) |
| Uncommitted/missing decision | `test_fail_closed_if_committed_revision_disappears`, `_projection_drift` (`decision_materialization_drift`) |
| Stale process / writer | `test_stale_controller_cannot_append_after_independent_commit`, `test_second_process_controller_is_stale_after_first_commits`, `test_in_tx_head_recheck_catches_race` |
| Incomplete/torn write | `test_failed_commit_leaves_zero_state_and_retry_succeeds`, `test_fault_at_each_step_yields_no_partial_state`, `test_power_loss_simulation_drop_connection_mid_commit`, `test_wal_sidecar_does_not_leak_uncommitted_state` |
| Invalid signatures | `verify_decision_v2` replay + `test_forged_qualified_without_evaluator_signature_detected`, receipt/signature adversarial tests in `ReceiptAuthorityTests` |
| Double promotion / replay | `test_identical_decision_cannot_commit_twice`, `test_repeated_transition_is_new_decision_not_replay`, `decision_already_committed` |
| Cross-process concurrency | `test_concurrent_process_writers` (spawn, 4 writers), `test_concurrent_writers_serialize` (8 threads) |
| Cancellation / budget overrun | Unchanged `BenchmarkHarness` semantics — `budget_exceeded` never counts as solved (PR-06 hardens enforcement) |

### Not proven here (explicit non-claims)

- **No efficacy claim** — no paired uplift study exists yet (G6).
- **No live-Codex claim** — the adapter remains unit-tested only (G3).
- **Repository identity** is still a caller-supplied string until PR-03's
  trusted registry; `min_distinct_repos` is a digest proxy, not proof of
  repository disjointness.
- **Process-identity enforcement**: `authority` binding is in-process
  hygiene — real isolation requires the deployment boundary (candidate
  writers must run under a different service identity).
- `receipt_binding` stores digest/task/repo only; full receipt payloads
  remain in evaluator custody.

### Rollback / disaster recovery

- `git revert` PR-01/PR-02 commits restores the baseline, or re-extract the
  verified archive. Baseline commit `d79a813` is immutable provenance.
- Migration rollback: rename `*.migrated` files back and delete the new
  `authority.db`; byte-identical backups exist under `pre-migration-backup/`
  (verified by `test_cutover_renames_and_is_reversible`).
- `AuthorityDB.backup()` produces a consistent online copy; restore verified
  by `test_backup_restores_to_consistent_state`.

## Verdict

**G0 PASS · G1 PASS** — proceed to PR-03 (verified scope grants + repository
registry, G2). Do not advance to live Codex or symbolic-learning claims; no
v4.0 qualification may be asserted from this state.
