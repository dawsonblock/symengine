# SIS v3 threat model (M0)

## Purpose and assurance boundary

SIS v3 is a planned research sidecar for an unchanged coding agent. This M0
slice adds strict record contracts, an authorization matrix, and an abstain-only
guidance API. It does not execute repository code, qualify procedures, sign
receipts, or establish a production trust boundary. Passing these tests is
software evidence for these interfaces; it is not evidence of safe hostile-code
execution or improved coding-agent solve rate.

## Assets

- Evaluator-private task identities, acceptance tests, labels, signing keys, and
  sealed answers.
- Repository snapshots, patches, test output, and agent event payloads.
- Qualified procedure revisions, their counterexamples, and evidence lineage.
- Operator credentials and the existing v2 SQLite registries.
- User task text and external content, which may contain prompt injection.

## Principals and authority

| Principal | Intended authority | Explicitly denied |
|---|---|---|
| Agent | Read qualified guidance; append observations | Evaluator data, signing, promotion, policy writes, candidate qualification |
| Runner | Execute only in a future isolated worker; append execution observations | Evaluator keys and hidden labels; promotion |
| Learner | Write untrusted candidate procedures | Qualified catalog, evaluator secrets, outcome signing |
| Evaluator | Read private fixtures; produce and sign outcome receipts | Procedure promotion and operator policy changes |
| Operator | Approve, suspend, revoke, or roll back qualified procedures | Evaluator signing key and hidden labels by default |

`src/sis/v3/policy.py` expresses this action matrix. It is a code-level policy
helper, not an OS identity boundary: a caller must resolve the role from
authenticated process or transport credentials. A role in agent-controlled
JSON is data and cannot establish authority. The existing v2 HTTP server keeps
its separate API and admin keys for keyed mode; unkeyed loopback remains a
legacy demo mode for compatibility.

## Threats and M0 controls

| Threat | M0 control | Remaining limit |
|---|---|---|
| Unknown record fields smuggle authority or change interpretation | Exact field sets for every v1 record; duplicate JSON keys rejected | No network adapter or external schema-consensus test yet |
| Oversized or deeply nested record exhausts parser resources | 64 KiB record limit, bounded text, arrays, nodes, and depth | Limits do not replace transport/process quotas |
| Digest is reused across record types or versions | SHA-256 domain prefix `sis-v3:{type}:{version}\0` | A digest identifies bytes; it does not prove custody or truth |
| Tool/repository text acts as policy | Event content is retained as payload data; guidance abstains and does not parse instructions | Future prompt construction must preserve provenance and sanitize separately |
| Agent forges operator identity in request JSON | Keyed HTTP mutations require the separate admin header; v3 roles are resolved outside JSON | Local unkeyed loopback intentionally retains old demo authority |
| Alias route bypasses mutation guard | Explicit path-to-handler and path-to-access maps; unmatched aliases do not dispatch | Any new endpoint must be classified and receive a negative test |
| Sub-to-Add recipe transfers to a balance function | v3 guidance has no qualified catalog and returns `unverified_task_intent` abstention | Legacy `sis_code_preview` remains experimental and can still show the bad proposal |
| Locally signed data is mistaken for independent outcome evidence | Contract docs distinguish receipt shape from signature verification/custody; receipts are now Ed25519-signed by an evaluator-only key | Verifier shares the caller's process in tests; no separate evaluator service, revocation, or external anchor deployed |
| Hostile repository code exhausts host resources or escapes | `LocalSubprocessExecutor` applies POSIX rlimits (CPU/address-space/file-size/NPROC), scrubbed env, capped captured output, process-group kill switch, and optional macOS seatbelt denying network and out-of-workspace writes | This is still `unverified_local`: no kernel isolation, no validated confinement claim; rlimits/seatbelt availability varies; RLIMIT_NPROC counts the UID's processes |
| Agent or tool output forges an outcome label | `OutcomeVerifier` re-digests the submission itself, runs registered acceptance material in its own fresh workspace, and signs `OutcomeReceiptV1` with an evaluator-custodied Ed25519 seed | Only receipt integrity/custody-of-key is shown; the harness driving real agents is unbuilt |
| Evidence log or artifacts are rewritten after the fact | `EpisodeStore` appends chained canonical events, deduplicates retries, repairs crash tails, refuses artifact-less references, re-hashes artifacts on read, and detects tamper on `verify_episode` | Writable filesystem underneath; a store writer could still truncate whole files — mitigation is `anchor_head` plus external custody |
| Receipt replay or double-counting | Per-evaluation nonce journal, (task, tree, criterion) duplicate rejection, signer key IDs, restart-surviving state | Journal itself is evaluator-local; compromise of the evaluator host defeats it |

## Exclusions

This phase still does not provide a validated OS-isolated worker
(Linux rootless/microVM), a live agent driver, a procedure miner, a promotion
controller, or a benchmark. The local executor must not be presented as a
secure sandbox; `sis.v3.signatures` is a non-constant-time reference
implementation; the verifier must not share agent/storage credentials in any
deployment. Do not claim a live Codex run, hostile-code containment, procedure
qualification, or agent-level efficacy from this phase.

## Prompt-injection handling

Task summaries, tool output, repository files, stored procedures, and model
proposals are untrusted content. The contracts place observed content under a
bounded payload and bind it with a digest; they do not turn the content into
instructions. Policy and evaluator decisions must remain in separately
authorized channels. Any later prompt that includes this content must label its
origin and preserve the agent's system/developer/user authority hierarchy.
