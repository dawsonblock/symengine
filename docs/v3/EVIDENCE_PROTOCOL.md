# SIS v3 evidence protocol (contract draft, v1)

## Record model

The authoritative Python validators are in `src/sis/v3/contracts.py`. Every
record uses `schema_version: 1`, rejects missing or unknown fields, limits its
canonical JSON to 64 KiB, rejects duplicate JSON keys, and bounds nested JSON
depth, node count, text, and collection sizes. Floating-point values are
excluded so cross-runtime canonicalization has fewer representation cases.

The contracts cover:

- `TaskEnvelopeV1`: task and repository digests, command capability IDs, actor,
  time/token/tool budgets, and an isolation profile. It contains no hidden test
  content. `permitted_commands` are identifiers for a future policy mapping,
  never shell strings.
- `ObservationEventV1`: episode/attempt sequence, observed kind, actor,
  timestamp, input/output and artifact digests, parent digest, idempotency key,
  payload digest, and bounded payload. `agent_event` represents a typed SDK
  event that is not safely classified as a tool call, edit, or completion.
- `PatchProposalV1`: source blob, normalized relative target path, exact span
  fingerprint, diff digest, purpose, procedure references, and evidence refs.
  It describes a proposal; it is not a write command.
- `ExecutionReceiptV1`: worker/environment identity, before/after tree hashes,
  command specification, exit state, bounded resource counters, and output
  hashes.
- `OutcomeReceiptV1`: evaluated tree, test-suite commitment, criterion,
  outcome, regression evidence, key ID, and a 64-byte Ed25519 signature over
  the canonical unsigned payload.
- `ProcedureRecordV1`: scoped language/task/failure signatures, structured
  preconditions and contraindications, plain-language steps, verification,
  counterexamples, evidence, status, and expiry.
- `PromotionDecisionV1`: candidate/protocol/receipt digests, actor, transition,
  policy version, rollback reference, and signature/authorization fields.
- `CandidateV1`: typed learning artifact (six kinds), content digest over the
  typed payload, repository scope, applicability preconditions, known
  counterexamples, and lineage. It carries no serving state.
- `CandidateEvidenceV1`: evaluator-signed binding of receipt digests to one
  exact candidate record/content digest on a declared partition under a
  declared evaluation-protocol digest. A receipt alone is not a
  qualification handle.
- `CandidateDecisionV1`: operator-signed authorization for one exact
  candidate transition (from-state, to-state, candidate digest, cited
  receipts/evidence, actor identity, one-use nonce). A decision for another
  candidate or edge cannot authorize this one.
- `GuidanceRequestV1` and `GuidanceV1`: bounded context and a recommendation,
  advisory, or abstention with exact evidence/policy references and at most
  three IDs.

Structured preconditions use an allowlisted `kind` and exact fields. The v1
validator does not accept Python, shell, or other executable expressions.
Procedure steps are informational text and are never executed by this module.

## Canonical identity

`canonical_json` sorts object keys, encodes UTF-8 without extra whitespace, and
rejects unsupported values. `canonical_digest(type, version, value)` computes:

```text
SHA256(UTF8("sis-v3:{type}:{version}\0") || canonical_json(value))
```

The domain prefix separates record types and schema versions. Event payload
digests are checked against the canonical payload. Digests identify content;
they do not establish semantic correctness, signer custody, or independence.

## Observations vs. outcomes

Agent statements, tool output, local test output, and candidate-reported
completion are observations. They are not evaluator labels. Outcome receipts
are created only by `sis.v3.verifier.OutcomeVerifier`, which re-digests the
submitted tree itself, replays registered acceptance material into a fresh
evaluator-owned workspace, and signs the canonical payload with Ed25519 under
`sis-v3:outcome_receipt:1`. The signing seed lives in a dedicated `key_dir`
(mode 0700/0600) and never leaves the verifier; `public_key_record` exports
public verification material, and `verify_receipt_signature` checks a receipt
offline without access to the seed.

The verifier rejects: unregistered or conflicting task registrations,
source-commit mismatches (including a task envelope missing the pinned
commit), replayed evaluation nonces, duplicate evaluations of the same
tree/criterion, and submissions it cannot measure. Its `receipts.jsonl`
journal is append-only and fails closed on restart if corrupt. In tests the
verifier still shares its callers' OS process; production custody requires a
separate evaluator service with its own credentials and an external anchor.

The v2 example signature and promotion authorization values in
`examples/v3/contracts_v1.json` remain illustrative placeholders that are not
produced or accepted by the verifier.

## Idempotence and replay

Events carry stable IDs, an idempotency key, sequence, and prior digest.
`sis.v3.episode_store.EpisodeStore` enforces them: conflicting `event_id` or
`idempotency_key` reuse, sequence gaps, and chain breaks are rejected;
byte-identical retries return the stored event; a crash-truncated tail is
repaired without rewriting earlier bytes; `verify_episode` replays and reports
tampering; `anchor_head` exports the ledger head to a separately controlled
directory. Artifacts are content-addressed and re-hashed on read. This is
append-only by implementation discipline on a writable filesystem — durable
claims against an attacker with store write access require OS-enforced
immutability or an external attestation service.

Receipts carry unpredictable IDs, per-evaluation nonces, exact tree binding,
signer key IDs, and a versioned signature domain; the verifier journal tracks
nonces and evaluated (task, tree, criterion) tuples to reject replays and
duplicates across restarts.

## Current guidance behavior

The M0 guidance function is read-only and abstains because no v3 qualified
catalog exists. Without a verified semantic task contract it returns
`unverified_task_intent`. The `remaining_balance` fixture records the known
Sub-to-Add negative transfer and requires this abstention. Existing v2
`sis_code_preview` remains a separate experimental API and is not upgraded by
this contract phase.
