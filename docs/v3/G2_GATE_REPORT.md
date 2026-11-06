# G2 Gate Report — Verified Scope Grants + Repository Registry

Status date: 2026-10-24. Branch: `codex/sis-authority-transfer-qualification`.
Extends `G1_GATE_REPORT.md` (G0 provenance unchanged: archive SHA-256
`f62ef2a500fe487cf17fb1b7d19862ab0eb686c411663b89d02011f310a7d077`).

This is an engineering gate report — **not** a v4.0 qualification
certificate. No efficacy, production-hardening, or cross-repository
uplift claims are made.

## Scope

PR-03 closes the hole recorded at G1: catalog scope was role-string
metadata persisted in an unsigned JSON sidecar, and cross-namespace
serving relied on an optional `namespace_authorizer` callback. Both are
removed. Repository identity now comes from a signed registry and
extended scope from committed signed grants — each re-verified on every
request.

## Implementation

- **`src/sis/v3/contracts.py`** — new records:
  - `RepositoryIdentityV1`: registry id, family id, immutable
    `base_tree_digest`/`base_commit`, trust domain, attestation digest,
    registry signature.
  - `ScopeGrantV1`: binds one `procedure_revision_digest` to a target —
    `target_registry_id` XOR `target_family_id` enforced at contract
    validation; `allowed_use ∈ {guidance}`; evidence receipt refs;
    `expires_at`; `grant_nonce`; signature.
- **`src/sis/v3/repository_registry.py`** — `RepositoryRegistry` is the
  only identity source for scope decisions. `register`/`issue` verify the
  registry signature and reject alias collisions (same registry id with a
  different body; same `base_tree_digest` or `base_commit` under another
  id). `load`/`dump` persist a signed JSONL registry file; a malformed,
  unsigned, or aliased line fails closed — partial registries are never
  silently accepted.
- **`src/sis/v3/scope_grants.py`** — `ScopeGrantAuthority(registry,
  trusted_signers, revoked_*, min_transfer_receipts=2)`:
  - `issue` is operator-role gated, signs with the custody key, and runs
    the same `verify` used at serve time before returning the grant.
  - `verify` checks signature under trusted (non-revoked) signer keys,
    expiry, registry resolution of source and target, self-grant
    rejection, revision binding, and the transfer-evidence rule: evidence
    receipts' `evaluated_repo_digest` values must resolve through the
    registry to **≥2 genuinely distinct registry identities**, including
    the source — and the target for cross-repository grants. Tree-digest
    comparison alone never establishes identity.
  - `permits(record, owner_identity, requester, grants, receipts_for)`
    is the serving predicate over committed grants.
- **`src/sis/v3/authority_db.py`** —
  - `commit_scope_grant(grant, receipts, authority, verifier)`: inside one
    `BEGIN IMMEDIATE` transaction — mandatory `verifier` re-check,
    bound-revision existence, grant id/digest uniqueness, atomic
    `nonce_consumption` insert (replay → `grant_nonce_replayed`), grant row,
    `grant_receipt_binding` rows, audit event.
  - `scope_grants(digest)`, `receipts_for_grant(grant_id)` (serve-time
    evidence re-verification from stored receipt JSON),
    `commit_revocation`/`revocations`, and grant decode/digest/revision
    checks inside `verify()`.
  - `scope_grant.procedure_revision_digest` is FK-bound to
    `procedure_revision.record_digest`; `grant_receipt_binding` is
    FK-bound to `scope_grant`.
- **`src/sis/v3/catalog.py`** — `set_scope` and the JSON sidecar are
  retired. `scope_of` is a read-only projection: `repository` default,
  `family`/`cross_repository` only where a committed grant names that
  target for the current revision.
- **`src/sis/v3/secure_guidance.py`** — `StrictGuidanceGateway` takes
  `repository_registry`/`grant_authority` instead of
  `namespace_authorizer`. Each request resolves `repository_id` through
  the registry (unresolved → abstain); repo-local matches on resolved
  identity; anything beyond repo-local must pass
  `ScopeGrantAuthority.permits` with the request's `now` for expiry.

## Test evidence (exact commands)

```
PYTHONPATH=src:. python3 -m pytest -q tests/v3/test_scope_grants.py
  → 26 passed

PYTHONPATH=src:. python3 -m pytest -q
  → 610 passed, 2 skipped   (17.7s)
```

Adversarial coverage (`tests/v3/test_scope_grants.py`):

| Case | Result |
|---|---|
| Forged signature / untrusted signer | rejected at verify and commit; never served |
| Unbound authority commit, missing verifier | rejected |
| Duplicate registry-id, tree-digest, or commit alias | rejected at register |
| Wrong-key identity; tampered registry line | rejected / load fails closed |
| Unresolvable or empty requester identity | abstains |
| Same-family membership without grant; family grant leaking cross-family | abstains |
| Source-mismatched grant (repo-b→repo-c grant, owner repo-a) | abstains |
| Expired grant at serve time (`now` injected) | abstains; expiry also blocks issue |
| Grant on superseded revision after re-qualification | abstains (digest binding) |
| Insufficient evidence (<2 distinct registry identities) / unregistered trees | rejected |
| Nonce replay | `grant_nonce_replayed` — atomic conflict |
| Post-commit `grant_json` tamper | abstains; `db.verify()` reports mismatch |
| Committed grant row deletion | abstains; `db.verify()` stays clean |
| Signer / grant revocation | serving stops immediately |
| Legitimate cross-repository and family grants | serve in scope |

## Gate assessment

**G2 PASS** — identity and scope are now signed, registry-anchored and
re-verified per request; repository-local remains the safe default; every
missing/ambiguous/forged lineage path fails closed.

## Explicit non-claims

- No efficacy or solved-task uplift is claimed.
- No live Codex integration is claimed.
- The registry's in-memory/JSONL store is not itself hardened custody —
  production deployments still need operator-controlled key custody.
- Grant revocation cascade (evidence-level) is wired at the store layer;
  full revocation semantics land in PR-04.
- Cross-repository *eligibility* is enforced; cross-repository *efficacy*
  remains unmeasured pending the preregistered repository-disjoint study.
