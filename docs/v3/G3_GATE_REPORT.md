# G3 Gate Report — Signed Revocations + Evidence Cascade

Status date: 2026-10-24. Branch: `codex/sis-authority-transfer-qualification`.
Extends `G1_GATE_REPORT.md` + `G2_GATE_REPORT.md` (G0 provenance unchanged:
archive SHA-256 `f62ef2a500fe487cf17fb1b7d19862ab0eb686c411663b89d02011f310a7d077`).

This is an engineering gate report — **not** a v4.0 qualification
certificate. No efficacy or production-hardening claims are made.

## Scope

PR-04 completes Stage 1: "enforce signed repository scope and evidence
revocation." G2 delivered signed grants; G3 makes invalidation equally
authoritative — revocations are signed, committed atomically, and honored
on every request without a process restart.

## Implementation

- **`src/sis/v3/contracts.py`** — `RevocationV1`: `kind ∈ {record,
  receipt, grant, signer}`; `target_digest` for digest kinds,
  `target_id` for `signer`; reason, actor, `issued_at`, signer key id,
  signature.
- **`src/sis/v3/revocation.py`** — `RevocationAuthority`: operator-role
  gated issuance under revocation-custody keys; `verify` re-checks the
  signature under trusted signer keys.
- **`src/sis/v3/authority_db.py`** — `commit_revocation(revocation,
  authority, verifier)`: the mandatory verifier runs inside the write
  transaction; `(target, kind)` uniqueness is a conflict, not silent
  state; the full signed record is stored in `revocation_json`.
  `revocations()` fails closed on undecodable rows. `verify()` checks
  decode, kind, and target consistency for every revocation row.
- **`src/sis/v3/promotion.py`** — `PromotionController.revoke` commits
  the signed revocation, then enforces it: `receipt` revocations run
  `Catalog.cascade_suspend`, suspending every qualified record citing
  the evidence through real signed suspension decisions; `signer`
  revocations remove the evaluator key from the trusted set.
- **`src/sis/v3/secure_guidance.py`** — per-request resolution of
  committed revocations: `record` digests join the serving denylist;
  records citing a revoked `receipt` in `evidence_refs` or
  `counterexample_refs` are denied even before their cascade suspension
  commits; `grant` digests and `signer` key ids flow into
  `ScopeGrantAuthority.permits` alongside revoked receipt digests
  (`evidence_revoked`).
- **`src/sis/v3/scope_grants.py`** — `verify`/`permits` accept
  `revoked`/`revoked_signers` sets so committed revocations stop grants
  without mutating the authority object.

## Test evidence (exact commands)

```
PYTHONPATH=src:. python3 -m pytest -q tests/v3/test_revocation.py
  → 15 passed

PYTHONPATH=src:. python3 -m pytest -q
  → 625 passed, 2 skipped   (19.3s)
```

| Case | Result |
|---|---|
| Forged signature / untrusted signer / missing verifier | rejected in-tx |
| Unbound authority commit | rejected |
| Duplicate `(target, kind)` revocation | conflict |
| Record revocation | denied next request; survives restart |
| Receipt revocation | citing records denied pre-cascade; cascade suspends them via signed decisions; grants citing it stop permitting |
| Grant revocation | cross-repo serving stops; owner-local unaffected |
| Signer revocation | its grants stop permitting; evaluator key cannot sign new decisions |
| Tampered `revocation_json` row | `undecodable_revocation` in `verify()` + `catalog_unavailable` abstain |
| Unaffected records | keep serving (p2 baseline in every test) |

## Gate assessment

**G3 PASS** — Stage 1 (PR-00…PR-04) complete: one transactional
authority store; qualification only via signed decisions; scope only via
signed grants on verified registry identity; revocation only via signed
committed records honored at every request.

## Explicit non-claims

- Revocation signer custody here is test-scope; production custody is a
  deployment concern.
- No revocation-of-revocation or appeal semantics are modeled.
- Stage 1 gates are about *authority integrity*, not efficacy —
  the decisive v4.0 criterion (independently verified cross-repository
  uplift under controlled budgets) is still unmet and unclaimed.
