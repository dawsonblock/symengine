# Security Threat Model — SIS v3.3.2

This model covers the v3.3.2 authority, custody, control-plane and serving
boundary. The v3.3.1 baseline is preserved in `docs/V331_ARCHITECTURE.md`;
the v3.3.2 changes and evidence are in `docs/V332_AUTHORITY_CONSISTENCY.md`.

## Assets

- candidate qualification and revocation authority;
- authority signing keys and checkpoint credentials;
- evaluator keys and sealed acceptance tests;
- qualification certificates, receipts and delivery attestations;
- repository identity registry and execution identities;
- served guidance (must not become authority).

## Adversaries

1. **Candidate-database writer** — can read/write the SQLite file but not
   the authority key or checkpoint store.
2. **Malicious optimizer/learner** — supplies candidate content and
   claims of success.
3. **Malicious skill author** — supplies Markdown with prompt injection,
   shell commands, symlinks or oversized payloads.
4. **Compromised/misconfigured evaluator** — issues a certificate from
   underpowered, nonconforming or unrelated evidence.
5. **Caller forging repository identity** — supplies a repository name,
   tree digest or commit in task text.
6. **Evidence tamperer** — deletes, alters, revokes or supersedes
   receipts/certificates.
7. **Hostile submitted code** — attempts to read keys, authority DB,
   checkpoint credentials or sealed datasets, or reach the network.
8. **Release tamperer** — alters the archive or manifest.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Delete final revocation / restore old DB | signed external checkpoint binds journal head, sequence and candidate revision; serving rejects stale/unpublished states |
| Flip `qualified` column | hash-chain projection drift; checkpoint candidate-revision digest |
| Replay old journal/checkpoint | monotonic journal sequence + authority epoch |
| Concurrent qualification/revocation | registry write lock + checkpoint CAS |
| Replay one signed session across replicas | shared `session_nonce` uniqueness constraint; nonce and receipt committed in one transaction |
| Revocation committed during guidance composition | witnessed snapshot revalidated before commit; the decision aborts on change |
| Restored pre-revocation custody directory | signed revocation/supersession heads and custody entry count compared on every production serve |
| Stale snapshot committed after a revocation | control-plane `authority_head` compare-and-commit |
| Interrupted checkpoint publication | local-ahead detection; `recover()` republishes only if the checkpointed head is still an ancestor |
| Unavailable checkpoint service | fail closed (`checkpoint_unavailable`) |
| Optimizer self-promotion | operator-signed decision for exact edge; nonce consumed atomically |
| Valid signature, invalid evidence | certificate validator re-derives candidate, delivery, protocol, sample, conformance, statistics, scope |
| Underpowered/nonconforming run qualifies | sample size + protocol conformance + evidence class gates |
| Candidate not actually delivered | harness-signed delivery attestation per task |
| Forged repository identity | harness-signed `ExecutionIdentityV1` verified against trusted registry; contradictory claims rejected |
| Evidence deleted/altered/revoked | content-addressed custody + dependency links + signed revocation/supersession logs |
| Skill code example becomes instruction | structured Markdown parser excludes code/quotes/commands; high-risk steps removed |
| Prompt injection | high-severity finding blocks automatic qualification; content preserved for review |
| Silent discovery truncation | `SkillDiscoveryIncomplete` or explicit pagination/complete flag |
| Symlink/traversal/oversized resource | refused before parsing; hashes streamed; no execution |
| Evaluator bootstrap failure misread as task failure | pinned runtime + bootstrap probe + outcome taxonomy |
| Submitted code reads keys/authority | seatbelt deny rules for key/registry/protected paths; network denied |
| Release archive altered | SHA-256 inventory + streaming verifier + fresh extraction smoke test |

## Residual risks (honest)

- The local subprocess/seatbelt executor is **not** a validated OS
  security boundary. Kernel/dyld/side-channel attacks remain possible.
  Production hostile-code evaluation requires a rootless worker or
  microVM with a minimal runtime image.
- A candidate-database attacker who can also write the checkpoint store
  defeats rollback resistance; custody separation is a deployment
  requirement.
- A compromised authority signing key defeats checkpoints and decisions.
- A compromised evaluator key can issue a false certificate; the
  validator checks form and evidence, not the evaluator's honesty.
- Pattern-based injection scanning is advisory, not proof of safety.
- `/v3/outcome` authenticates the caller but does not yet bind the
  requester identity to the stored authorization receipt. Recording an
  outcome still requires the exact served digest and a matching
  evaluator-signed receipt, so a different authenticated client cannot
  invent a result; per-requester binding needs a control-plane schema
  change.
- The powered real-agent efficacy run is not executed in this release;
  no efficacy claim is made.

## Security release classification

All P0 authority, certificate, identity and custody gates are
implemented and covered by adversarial tests. The sandbox is
implemented as defense-in-depth and marked not a validated boundary. The
real-agent efficacy gate is blocked, so the overall release is
`IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
