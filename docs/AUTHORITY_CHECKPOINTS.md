# Authority Checkpoints and Rollback Resistance

## Defect closed

The v3.3 candidate registry hash-chains every transition. That detects
rewritten, reordered or inserted rows, but not a deleted tail: removing
the final revocation leaves a shorter, internally consistent chain. An
attacker with write access to the candidate SQLite file could therefore
restore a previously qualified candidate.

## Checkpoint

`AuthorityCheckpointV1` is signed by the trusted authority key and binds:

- `authority_epoch` — rejects checkpoints replayed from an old epoch;
- `sequence` — monotonic publication sequence (1, 2, 3, …);
- `previous_digest` — append-only checkpoint chain;
- `journal_sequence` and `journal_head` — the candidate transition log
  position and sealed head;
- `candidate_revision_digest` — digest over every candidate id, record
  digest and current state (including serving states);
- `candidate_count` / `qualified_count`;
- `issuer_identity`, `policy_version`, `issued_at`, `signer_key_id` and
  the Ed25519 signature.

Signing is domain-separated:
`sis-v3:authority_checkpoint:1\0` + canonical JSON without `signature`.

## Store

`FileAuthorityCheckpointStore` is the reference backend:

- append-only canonical JSON log;
- every read verifies signature, sequence continuity and previous-digest
  chain;
- `compare_and_append(expected_sequence, checkpoint)` takes an OS file
  lock, re-reads the head, requires `expected_sequence == latest.sequence`
  and `checkpoint.sequence == latest.sequence + 1`, then atomically
  replaces the file (temp + fsync + rename + directory fsync);
- a truncated, reordered, rewritten or unsigned log fails closed with
  `CheckpointVerificationError`;
- the store must live in custody the candidate-database principal cannot
  write. A table in the same SQLite database is explicitly insufficient;
  the constructor rejects configuring the checkpoint path as the
  candidate database itself.

## Publication protocol

`AuthorityJournal` owns the signing key and is the only publisher.

1. Read the local authority state.
2. If no checkpoint exists, anchor the current state at sequence 1.
3. If local `journal_sequence` is **older** than the checkpoint, raise
   `RollbackDetected`; never republish a rolled-back state.
4. If local equals the checkpoint, require identical head and revision;
   otherwise raise `RollbackDetected` (journal-head substitution or
   candidate-state tamper).
5. If local is **ahead**, require the local log to still contain the
   checkpointed head at the checkpointed sequence. A rewritten history
   cannot extend it. Sign the new head, CAS-append, and retry once on a
   publication race.

The database commit and checkpoint append are separate operations. A
crash after the commit leaves the local state ahead of the checkpoint:
serving denies (`local_state_unpublished`) until `recover()` or
`publish_pending()` republishes. `recover()` returns `anchored`,
`idempotent`, `published`, `rollback_detected` or `diverged`.

## Serving

`AuthorityStateVerifier.verify_local_state` compares the local state to
the latest checkpoint and returns a `VerificationResult`. It rejects:

| Condition | Reason |
|---|---|
| no checkpoint | `checkpoint_missing` |
| unsigned/forged checkpoint | `checkpoint_signature_invalid` |
| old authority epoch | `authority_epoch_mismatch` |
| policy mismatch | `policy_version_mismatch` |
| local behind checkpoint | `local_state_stale` |
| local ahead of checkpoint | `local_state_unpublished` |
| same sequence, different head | `journal_head_mismatch` |
| candidate state differs | `candidate_revision_mismatch` |
| count differs | `candidate_count_mismatch` / `qualified_count_mismatch` |
| store unreadable | `checkpoint_unavailable` |

`CandidateRegistry` calls this gate before returning any qualified
record. `GovernedServingGateway(production=True)` additionally refuses a
registry without a certificate policy or without a checkpoint-verified
mode. A local-only database is never treated as rollback resistant.

## Adoption and migration

A deployment should anchor an **empty** registry before its first
qualification. Anchoring a populated registry is trust-on-first-use: it
proves the state existed at adoption time, not that it was correct
before adoption. `docs/MIGRATION_V330_TO_V331.md` describes the safe
order.

## Adversarial coverage

`tests/v3/test_authority_checkpoints.py` reproduces:

- deleted final revocation;
- stale database restoration;
- qualified-state column modification;
- reordered audit events;
- journal-head substitution;
- forged/invalid checkpoint signatures;
- replayed old-epoch checkpoints;
- tampered checkpoint logs;
- concurrent compare-and-append;
- interrupted publication and recovery;
- unavailable checkpoint service;
- production serving after rollback.
