# V335-03 — Explicit memory chain membership

Status: implemented on `repair/v335-resource-security`. Scope limited to
`src/sis/v3/memory.py`, `docs/v3/MEMORY_DESIGN.md`,
`docs/v3/TRUST_BOUNDARIES.md`, and the regression file
`tests/v3/test_v335_chain_membership.py`. No receipt schema,
control-plane, or unrelated module changes.

## Defect

`MemoryStore` proved a store-wide invariant — `_chain_state` requires the
chain to cover exactly the experience rows present — and treated that as
sufficient evidence for every individual record. Two gaps followed:

- `trust_status(record)` returned `trusted` for a correctly signed
  record that was never ingested. The empty store's chain covers the
  empty table, so the invariant held while the record had no chain entry
  at all.
- `by_outcome` evaluated the invariant before reading rows. A row that
  appeared between the check and the read was returned with only its
  row-local digest and signature checked, not its chain membership.

The second gap is a time-of-check/time-of-use window; the first is
simply the wrong question. Neither is a signature or lineage failure,
so no existing check could catch them.

## Fix

- `_require_membership(record)` answers the per-record question in one
  statement:

  ```sql
  SELECT 1 FROM experience e
    JOIN memory_chain c ON c.record_digest = e.record_digest
   WHERE e.experience_id=? AND e.record_digest=?
  ```

  Joining both tables in a single statement makes the row and its chain
  entry one snapshot, so the answer cannot be invalidated by a write
  between two reads. A miss raises `experience_unchained:<id>`.
- `trust_status` now requires chain, membership, signature and lineage,
  in that order. `get` and `by_outcome` check membership per returned
  record when chain trust is configured (`trusted_signer_keys` or
  `chain_key`).
- Development stores are unchanged: without a trust root, reads keep
  serving legacy rows that predate the chain.

Membership is deliberately not folded into `_record_integrity`: ingest
calls that before the row exists. It is a read-path property, and
`repair_chain` still refuses to chain legacy rows, so membership remains
evidence of presence rather than provenance.

## Red evidence (before the fix)

`tests/v3/test_v335_chain_membership.py` against the pre-fix
`src/sis/v3/memory.py`:

- `test_unstored_record_is_not_trusted`: `trust_status` returned
  `trusted` for a record with no row and no chain entry.
- `test_by_outcome_rejects_row_added_after_the_chain_check`: the
  interleaved unchained row was returned instead of raising.

Both fail; the two tests that pin preserved behaviour (ingested records
become trusted, development reads ignore the chain) pass before and
after.

## Green evidence

- `tests/v3/test_v335_chain_membership.py`: 4 passed.
- Focused memory/trust/retrieval/induction suites: 199 passed with only
  the expected pre-seal release-identity failure.
- Full suite: see V335-04.

## Remaining work (not in V335-03)

V335-04 pinned full suite, version bump, qualification report, and the
release seal.
