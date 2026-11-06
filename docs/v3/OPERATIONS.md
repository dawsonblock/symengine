# SIS v3.1-alpha — Operations & Hardening Checklist

Deployment-side controls required before treating any build as
production-safe. These are NOT provided by the codebase itself.

## Key custody
- Evaluator/registry/operator keys must live in an HSM or KMS; the
  codebase only sees Ed25519 seeds. Rotate signer keys and revoke the
  old signer via `RevocationAuthority` (`signer` kind) — revocation is
  enforced per request without restart.
- The operator token gate (`authority_testkit` tokens are test-only)
  must be replaced by real identity in deployment.

## AuthorityDB
- SQLite WAL + synchronous=FULL + foreign_keys; single-writer by design.
- Back up db file AND -wal/-shm together, or use the migration tool's
  byte-identical backup path (`tools/migrate_authority.py`).
- Verify integrity on restart: `PromotionController(db).verify()` —
  any tampered row fails closed (`catalog_unavailable`).

## Registry / grants / revocations
- Registry file is signed JSONL; a malformed or unsigned line fails
  closed on load. Keep the registry under the same custody as keys.
- Grants expire; serve-time `now` governs expiry — keep clocks synced.
- Revocation drill (quarterly): revoke a receipt → confirm cascade
  suspension; revoke a signer → confirm all its artifacts untrusted.

## Execution
- `LocalSubprocessExecutor` is `unverified_local`: resource limits are
  best-effort, NOT a security boundary. Run agent workspaces in
  containers/VMs in production.
- Benchmark budgets are hard-enforced by the harness watchdog; agent
  token/tool counters are UNVERIFIED unless harness-metered.

## Evaluation & release
- Before any efficacy claim: run the preregistered repository-disjoint
  paired study (`assert_repository_disjoint` + `paired_summary`); the
  bar is D-vs-A `solved_delta > 0` with `mcnemar_exact_p <= 0.05`.
- Release: `python3 tools/build_release.py` then
  `python3 tools/verify_release.py --compile .`; commit
  `RELEASE_SHA256.json` with the release tag.
