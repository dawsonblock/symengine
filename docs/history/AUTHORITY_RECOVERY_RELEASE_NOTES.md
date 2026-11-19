# SIS authority-recovery engineering release — 2026-10-24

This is a **research development release**, built on `SIS-2026-10-24-FULL-UPGRADED.zip`. It is not a certified production deployment or a demonstrated self-improving coding agent.

## Engineering changes

- Promotion transitions now commit the signed `PromotionDecisionV2` **before** appending the corresponding procedure revision, providing a recoverable write-ahead decision journal. The two JSONL files are **not** one OS transaction; consistency is enforced by fail-closed guidance and authenticated, deterministic recovery.
- Recovery independently validates the decision log's cryptographic signatures, authorization, status transitions, digest chain and qualified-head transitions **before** replaying any missing catalog revision. It reconstructs only a revision whose digest exactly matches the signed decision and its existing predecessor.
- Projection verification now checks materialization of *every* decision-backed status (not just qualified state). This closes the previously reproducible failure where missing non-qualified records escaped drift detection.
- Malformed, newline-terminated journal entries are treated as corruption and preserved, not automatically discarded as crash debris. Incomplete, unterminated tails can be truncated on restart for recovery; entries must then be revalidated.
- A POSIX `flock` guards promotion transitions and startup recovery to prevent cooperating writers from interleaving their journals. Stale in-memory controllers reject further transitions. On Windows, an externally managed exclusive single-writer service is required; the POSIX file lock is not a defense against malicious local processes.
- Added fault-injection tests for crash-before-catalog-commit, fail-closed serving, recovered signed qualification, missing predecessor, stale controllers, and corrupt journal tails.
- Updated legacy fixture tests to assert that unsigned qualified seed records cannot be laundered through a promotion transition. Canonical release sources correctly omit historical `SOURCE_SHA256.json`, so the legacy manifest test now accepts that release-mode condition.

## Validation and limits

- Targeted authority/learning tests: **39 passed**.
- Adapter/benchmark/retrieval/schema/roadmap subset: **103 passed, 1 skipped**, with **37 passing subtests**.
- Additional v3 executor-heavy tests and all legacy tests were **not qualified as a full passing suite** in this run: longer combined runs exceeded the execution window.
- Authenticated Codex Python SDK threads, real external guidance delivery, full resource isolation, and cross-repository efficacy **remain unverified**. Do not claim solved-task uplift.
- `ProcedureStore.add(..., allow_qualified=True)` has been **removed** (PR-01, v3.1-alpha). Intake accepts only revision-1 `draft`/`candidate` records; decision-managed states exist exclusively inside `AuthorityDB` through committed signed decisions. The legacy `GuidanceGateway` moved to `sis.v3.compat.guidance_gateway` (test/fixture namespace — never production serving). Production serving is `StrictGuidanceGateway` over `AuthorityDB` + `PromotionController`.
- Repository identity and lineage come only from `RepositoryRegistry` — signed `RepositoryIdentityV1` records issued under registry-custody keys, rejecting alias collisions (v3.1-alpha, PR-03). Repository-family and cross-repository eligibility require committed signed `ScopeGrantV1` records in `AuthorityDB`, verified per request (signature, registry lineage, expiry, distinct transfer evidence) by `ScopeGrantAuthority`. The role-controlled catalog `set_scope` write path and the `namespace_authorizer` callback were removed — scope metadata is a read-only projection of grants and is never proof of transfer eligibility.
- Promotion journal and procedure catalog require the same trusted host, protected filesystem and key custody. This is crash recovery, **not** tamper-proof storage under an attacker with local write permission.
- The normal `ProcedureStore` uses thread-level locks, not a database-wide multi-process transaction. Use a single owning promotion service and protected storage; do not share the writable catalog with other processes or principals.

## Recommended next work

1. Remove or encapsulate the legacy qualified-record writer and legacy guidance surfaces behind an explicit migration.
2. Add an append-only database or single transactional store for promotion decisions and procedure revisions; formally test process crashes and power-loss durability.
3. Enforce repository lineage in independent signed evaluator receipts, then use it in scope decisions.
4. Exercise authenticated SDK runtime with read-only, stream-interruption and sandbox regression tests.
5. Run repository-disjoint, cost-matched, independently graded Codex vs. Codex+SIS benchmarks.

## Verification

Run from the extracted source tree:

```sh
PYTHONPATH=src:. python -m pytest -q tests/v3/test_authority_recovery.py tests/v3/test_promotion.py tests/v3/test_upgrade_integrity_learning.py
PYTHONPATH=src:. python -m pytest -q tests/v3/test_codex_adapter.py tests/v3/test_benchmark.py tests/v3/test_retrieval.py
python tools/build_release.py --check
python tools/verify_release.py .
```

The generated ZIP's SHA-256 and the exact tests run are recorded in the accompanying external release verification file.
