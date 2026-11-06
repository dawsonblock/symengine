# SIS v3.3 Experience Memory (Track B)

ReasoningBank-style episodic memory, rebuilt on SIS integrity rails:
schema-validated records, digest-bound storage, evidence-referenced
induction, gated retrieval with abstention. No pickle, no unverified
promotion.

## Record — `ExperienceRecordV1`

Immutable, content-addressed. Large artifacts are referenced by digest,
never embedded.

| field | meaning |
|---|---|
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
- `ingest(record, evidence_check=...)` is the trust-boundary hook.
  Production ingestion passes `verify_experience_evidence(record,
  verifier)`, which resolves `outcome_receipt_digest` in the evaluator's
  own journal, verifies the signature, and requires the signed outcome
  to equal the record's claimed outcome. A record that names a receipt
  it does not have is rejected before any write.
- `get`/`by_outcome` re-verify the stored digest on every read; tampered
  rows raise `experience_tampered` and fail closed.

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

Hard gates before ranking (all must pass):

1. `candidate_type == "experience_memory"`
2. every `applicability` predicate holds against the caller's
   `RetrievalContext`
3. no `known_counterexamples` string appears in the task's
   failure/symbol/file context (negative-transfer suppression)
4. deterministic score = matched-gates×10 + source-episode count,
   floor `min_score`

Then: content-digest dedup, score ordering, greedy `token_budget`
packing, `limit`. Abstains by returning `()` — an empty result is a
first-class answer, never a fallback to ungated text.

Unqualified candidates are filtered out before this function is ever
reached: serving passes only `registry.qualified()` into retrieval.
