# SIS v3.3.1 Architecture — Authority Closure

> **v3.3.2 supersedes this document.** The current release adds a shared
> SQLite/PostgreSQL control plane (`sis.v3.control_plane`) and an authenticated
> serving boundary (`sis.v3.serving_service`), and signs custody heads into
> authority checkpoints. See `docs/V332_AUTHORITY_CONSISTENCY.md` for the
> changes and `docs/V332_OPERATIONS.md` for deployment. The layers below remain
> accurate except where those additions change the serving path.

SIS v3.3.1 retains the v3.3 subsystems and closes the authority,
evaluation, identity, custody, ingestion and sandbox gaps that prevented
trustworthy promotion. It is a correctness/security release, not a new
learning algorithm.

## Layers

```
Agent / Codex adapter
        │  ExecutionIdentityV1 (harness-signed)
        ▼
GovernedServingGateway  ──►  CandidateRegistry (SQLite)
        │                         │  hash-chained transition log
        │                         │  signed decisions + evidence
        │                         │  EvaluationCertificateV1
        │                         ▼
        │                  AuthorityJournal ──► AuthorityCheckpointStore
        │                                      (independent custody)
        │
        └──► EvidenceCustodyStore (immutable objects, revocations)

Learning pipeline ──► CandidateV1 ──► governed evaluation ──► certificate
                                                          ──► operator decision
                                                          ──► qualification
```

## Trust boundaries

| Boundary | Owns | Never trusted from |
|---|---|---|
| Candidate database | candidate records, audit chain, materialized state | a local-only database as rollback evidence |
| Authority process | checkpoint signing key, publication sequence | candidate writers |
| Checkpoint store | append-only signed checkpoint chain | the candidate database principal |
| Evaluator | receipts, certificates, delivery attestations | optimizer-supplied candidate IDs |
| Harness adapter | execution identity | task text, repository names, tree digests in prompts |
| Evidence custody | immutable evidence, revocation/supersession | disappearance or mutable status columns |
| Serving gateway | scope/revocation/identity decisions | candidate text as authority |

## Modules added in v3.3.1

- `sis.v3.checkpoints` — external signed checkpoints, CAS publication,
  crash recovery, local-state verification.
- `sis.v3.evaluation_certificate` — `EvaluationCertificateV1`,
  `QualificationPolicy`, `QualificationValidator`, delivery attestations.
- `sis.v3.execution_identity` — `ExecutionIdentityV1` issuance and
  verification against the trusted repository registry.
- `sis.v3.evidence_custody` — content-addressed evidence, dependency
  links, signed revocation/supersession logs, offline policy.
- `sis.v3.skill_markdown` — bounded structured Markdown parsing.
- `sis.v3.evaluation_runtime` — pinned evaluator runtime, bootstrap
  probe, outcome taxonomy.
- `sis.v3.learning_qualification` — five-arm campaign analysis,
  McNemar/Newcombe statistics, real-agent gate.

## Modules added in v3.3.2

- `sis.v3.control_plane` — durable `session_nonce`,
  `authorization_receipt`, `guidance_outcome` and `authority_head` tables
  with SQLite and PostgreSQL profiles; one transaction consumes the nonce
  and commits the decision receipt.
- `sis.v3.serving_service` — bearer-authenticated `/v3/guidance` and
  `/v3/outcome` adapter over `GovernedServingGateway`.
- `sis.v3.checkpoints` additions — custody heads and entry count signed
  into `AuthorityCheckpointV1`, with v3.3.1 wire compatibility.
- `sis.v3.evidence_custody` additions — signed dependency links and
  active-path cycle detection with memoization.
- `tools/provenance.py`, `tools/verify_provenance.py` — DSSE-signed
  SLSA-shaped release provenance.

## Serving flow

1. The harness adapter issues an `ExecutionIdentityV1` binding the
   requester, registry-resolved repository, commit/tree, workspace, task,
   family, harness and session nonce.
2. The gateway verifies the identity signature, expiry, nonce, repository
   tree/commit/family and any caller-supplied identity claims.
3. The gateway checks that the registry is certificate-policy qualified
   and checkpoint-verified.
4. `CandidateRegistry` folds the hash chain, verifies the state
   projection, re-authenticates decisions/evidence/certificates, checks
   custody status and compares the local state to the latest checkpoint.
5. Scope, applicability, counterexamples and revocation gates run per
   candidate. Candidate text is delivered only as advisory
   `helpful_next_checks`; it never grants authority.
6. Any integrity/identity/custody failure returns an abstention with no
   actionable candidate instructions.

## Qualification flow

1. A candidate is submitted at `proposed` by a learner role.
2. It moves to `evaluating` through role-gated, audited transitions.
3. The evaluator runs a sealed-holdout probe, signs per-task receipts and
   delivery attestations, then issues an `EvaluationCertificateV1`.
4. `QualificationValidator` re-derives signature, candidate identity,
   delivery, protocol, preregistration, sample size, conformance,
   statistics, negative transfer, revocation and scope checks.
5. An operator signs a `CandidateDecisionV1` for the exact
   `evaluating → qualified` edge.
6. `CandidateRegistry.qualify` stores the certificate, evidence and
   decision atomically, then the authority journal publishes a
   checkpoint.

## Production vs demonstration

`CandidateRegistry.qualification_mode` is `production` only when a
`QualificationPolicy` and validator are configured. A registry without a
certificate policy can hold demonstration/exploratory evidence, but
`GovernedServingGateway(production=True)` refuses it. This is deliberate:
the v3.3 demo campaign can still demonstrate machinery without claiming
production qualification.

## What is intentionally not claimed

- The local subprocess/seatbelt executor is defense-in-depth, not a
  validated OS security boundary. Production hostile-code evaluation
  requires a rootless worker or microVM.
- A five-arm scripted campaign is machinery evidence, not learning
  efficacy.
- The powered real-agent efficacy run is gated and marked blocked unless
  actually executed with an authenticated agent and hidden holdout.
