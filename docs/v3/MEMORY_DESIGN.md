# SIS v3.3 Experience Memory (Track B)

ReasoningBank-style episodic memory, rebuilt on SIS integrity rails:
schema-validated records, digest-bound storage, evidence-referenced
induction, gated retrieval with abstention. No pickle, no unverified
promotion.

## Record — `ExperienceRecordV1`

Immutable, content-addressed. Large artifacts are referenced by digest,
never embedded.

| field | meaning |
| --- | --- |
| experience_id / episode_id | identity; episode dedup key with fingerprint |
| repository_registry_id | signed registry identity (trusted, not self-declared) |
| task_fingerprint | sha256 of the task's identity material |
| task_category | family label used for scope/targeting |
| agent_config_digest | config commitment, not config content |
| trace_digest | immutable reference to the stored trace |
| outcome_receipt_digest | the verified outcome this lesson stands on |
| outcome | `pass`/`fail` — success and failure are distinct classes |
| failure_category | populated only for failures |
| lesson | the extracted reusable text (payload candidate) |
| facts | observed facts (what the trace showed) |
| hypotheses | inferred causes (model-generated; NOT causal truth) |
| applicability | predicate list evaluated against RetrievalContext |
| counterexamples | strings that suppress this memory when present |
| provenance | generator + method metadata |

## Store — `MemoryStore` (sqlite, WAL)

- `ingest` is idempotent on identical records; the same
  `(episode_id, task_fingerprint)` with different content raises
  `DuplicateEpisode` — a replayed episode cannot masquerade as a second
  independent attempt.
- `ingest(record, evidence_check=...)` accepts an optional trust-boundary
  hook. A production store does not rely on the caller: it runs
  `verify_experience_evidence(record, verifier,
  require_registered_task=True)` itself, which resolves
  `outcome_receipt_digest` in the evaluator's own journal, verifies the
  signature, requires the signed outcome to equal the record's claimed
  outcome, and requires the task to be registered with the exact suite
  commitment the receipt names. A record that names a receipt it does
  not have is rejected before any write.
- `get`/`by_outcome` re-verify the stored digest on every read; tampered
  rows raise `experience_tampered` and fail closed.
- Trusted reads require the exact record to be a chain member. The
  store-wide invariant ("the chain covers exactly the rows present") is
  evaluated at a different instant from the row read, so it cannot bind
  the row a caller receives. Membership is one statement joining
  `experience` to `memory_chain`, and a non-member — never ingested, row
  removed, or inserted after the invariant check — raises
  `experience_unchained`. Membership is not provenance: signature and
  lineage still decide whether a member is trusted.

## Trust profiles — `MemoryTrustProfile`

The store's trust configuration is explicit; there is no silent
downgrade. A profile is a closed enumeration, not a bag of caller-chosen
flags: construction rejects any name other than `development` or
`production`, requires every production control to be enabled, and
requires a development profile to enable none.

| profile | requirements | trust report |
| --- | --- | --- |
| `development()` (default) | none beyond the configured roots | `untrusted:development_profile` |
| `production()` | trusted signer keys, custodian `chain_key`, external `MemoryWitness`, evaluator verifier with `registered_task` | `trusted` only after chain + witness + signature + lineage |

A production store refuses to construct when any root is missing,
including a verifier that cannot perform registered-task verification.
Production reads re-check chain membership and lineage on every row, and `repair_chain`
refuses to chain legacy or untrusted rows — membership in a trusted
chain is not provenance. `trust_status(record)` derives trust from the
profile's full contract *and* the controls the store still holds; it
does not key off the profile-name string alone. It returns either
`trusted` or `untrusted:<reason>`; `is_trusted` is its Boolean form.


## External witness — `MemoryWitness`

The chain detects mid-history edits but cannot detect that its newest
entries were deleted by restoring an older snapshot. `MemoryWitness`
records the observed `(sequence, memory_head_digest)` in an append-only
file signed under a separate custodian key, stored outside the memory
database's directory (the store enforces the path separation). Every
record commits to the previous witness digest, so interior deletion is
also detectable.

Every production read requires the store's position to equal the newest
witness. A restored snapshot is `memory_rollback_detected`; a database
that advanced without the witness append is `memory_witness_stale` and
requires the operator's `reconcile_witness()` after the chain verifies.
Reconciliation cannot re-anchor a rollback. A rebuild over an existing
witness requires a fresh witness epoch under the separate authority.

The witness key and path must be controlled by a different principal
from the memory database; if one principal controls both, it can forge
a consistent pair.

## Induction — `induce_candidate`

One record → one `experience_memory` `CandidateV1`:

- `payload.lesson` = the lesson; `facts` and `hypotheses` are carried
  separately in the payload so evaluators can see what was observed vs
  inferred.
- Default `repository_scope` is `registry_id` of the source repo; callers
  may widen to `family_id` deliberately (cross-repo transfer is a scope
  decision, not an accident).
- Output lands at PROPOSED via `candidate:write`. Nothing qualifies here.

## Retrieval — `retrieve_memories`

Hard gates before ranking (all must pass, in order):

1. `candidate_type == "experience_memory"`
2. trust: `trust_check(candidate)` must return true when supplied —
   without it the pool is caller-vouched. Trust is decided before
   applicability and can never be rescued by a high score.
3. every `applicability` predicate holds against the caller's
   `RetrievalContext`
4. no `known_counterexamples` string appears in the task's
   failure/symbol/file context (negative-transfer suppression)
5. deterministic score = matched-gates×10 + source-episode count,
   floor `min_score`

Then: content-digest dedup, score ordering, greedy `token_budget`
packing, `limit`. Abstains by returning `()` — an empty result is a
first-class answer, never a fallback to ungated text.
`on_reject(candidate, stage, detail)` reports every hard-gate removal
with `stage` one of `untrusted`, `inapplicable`, `suppressed`,
`low_score`.

Unqualified candidates are filtered out before this function is ever
reached: serving passes only `registry.qualified()` into retrieval.
