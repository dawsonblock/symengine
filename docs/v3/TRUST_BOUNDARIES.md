# SIS v3 trust boundaries (M0)

## Intended target boundary

```text
Codex agent (restricted credentials)
  | read-only guidance; untrusted observation events
  v
SIS gateway / qualified-procedure reader
  | candidate artifacts only
  v
Offline learner and candidate store

Agent workspace -> isolated workspace worker -> immutable artifacts
                                      |
                                      v
                         independent outcome evaluator
                         private tests and signing key
                                      |
                                      v
                         operator governance controller
                                      |
                                      v
                         qualified procedure revisions
```

The agent-facing path must not expose evaluator-private fixtures, labels,
signing credentials, promotion APIs, or mutable qualified evidence. The worker
must not inherit SIS service credentials. A future operator must approve a
procedure only after independently verified evidence and retain a reversible
history.

## What exists in this M0 branch

- `sis.v3.contracts` defines bounded v1 data structures and canonical digests.
- `sis.v3.policy` defines a default-deny role/action matrix, assuming callers
  obtain roles from a trusted identity source.
- `sis.v3.guidance.sis_recommend` returns a bounded abstention because there
  is no v3 qualified procedure catalog.
- The v2 HTTP server has an explicit POST route inventory. Keyed deployments
  require the API key for reads and the distinct admin key for all listed
  operator mutations. Unkeyed loopback mutations remain available for the
  legacy demo.
- The v2 SQLite schema is unchanged; no v3 records are persisted.

## What is not established

The v3 components run in one process during tests: the policy module, executor,
store, and verifier do not create distinct OS users, credentials, containers,
or VMs. `unverified_local` remains an explicit label, not a secure isolation
profile — even when `sandbox-exec` denies network and out-of-workspace writes
on macOS, that backend is an experimental convenience, not a validated
boundary. Hashes and signatures establish integrity and key custody only; they
do not prove the verifier ran on a separate host from the agent. The HTTP
server's existing loopback demo mode is not appropriate for multi-user or
deployed use. No external audit anchor service, evaluator process separation,
key revocation, or task-admission service is deployed.

## Implemented boundary components

- `sis.v3.runner.LocalSubprocessExecutor`: disposable copied workspaces,
  non-shell `CommandSpec`, POSIX rlimits, scrubbed environment, bounded output
  capture, wall-clock group kill, `terminate_all`, optional macOS seatbelt
  profile. Receipts state `isolation:unverified_local` and measured
  enforcement facts (`network:seatbelt_denied` vs `network:not_enforced`).
- `sis.v3.episode_store.EpisodeStore`: append-only JSONL event logs with
  hash-chained `prior_event_digest`, idempotent append, crash-tail repair,
  artifact digest custody, `verify_episode`, and `anchor_head` export for
  separately controlled anchor directories.
- `sis.v3.verifier.OutcomeVerifier`: evaluator-custodied Ed25519 seed
  (0700 dir / 0600 file), registered hidden acceptance material injected only
  into evaluator-owned workspaces, signed `OutcomeReceiptV1`s, nonce and
  duplicate-evaluation journal, role gate `outcome:evaluate`.
- `sis.v3.signatures`: stdlib-only Ed25519 (RFC 8032 vectors verified;
  non-constant-time reference implementation; swappable for a vetted provider
  behind the same API).

## Separation requirements for later phases

1. Resolve agent, runner, learner, evaluator, and operator identities outside
   caller-controlled payloads.
2. Put hidden fixtures and signing keys under evaluator-only OS credentials —
   move `OutcomeVerifier` into its own process/host for production.
3. Execute untrusted repository content only in a separately isolated worker
   with explicit resource and network limits (replace the local executor).
4. Store verifier receipts and content-addressed artifacts under permissions
   unavailable to agent and learner identities.
5. Anchor audit heads outside the database's write authority (`anchor_head`
   exports the document; a real anchor service is still required).
6. Keep retrieval read-only and fail closed on stale context, missing evidence,
   incompatible lockfiles, revoked signers, or corrupt artifacts.
