# Evaluation Certificates and Fail-Closed Qualification

## Defect closed

v3.3 could report `conforms=false` (for example, 2 holdout tasks against
a preregistered sample of 29) and still qualify candidates. A pass
receipt also proved only that *some* task passed; it did not prove that
the candidate's instructions were delivered.

## Evidence classes

| Class | Meaning | Production promotion |
|---|---|---|
| `exploratory` | research signal, underpowered or off-plan | never |
| `demonstration` | scripted/machinery evidence | never |
| `confirmatory` | real agent, hidden holdout, conforming protocol, sufficient sample | may qualify |
| `invalid` | contradictory, revoked, corrupted or nonconforming evidence | never |

Exploratory and demonstration certificates remain stored and reported.
They are first-class evidence for research; they are not qualification.

## Certificate schema

`EvaluationCertificateV1` is evaluator-signed and binds:

- certificate id/version and `evidence_class`;
- candidate id, record digest and content digest;
- `candidate_delivery_digest` — aggregate of per-task delivery digests;
- baseline model digest, agent configuration digest;
- evaluation protocol digest, preregistration digest, task-set digest;
- repository snapshot digests;
- `individual_task_receipts`: `{task_id, receipt_digest,
  delivery_digest, attestation_digest, outcome}`;
- grader/evaluator identity;
- sample count, primary metric, confidence interval (milli-scaled
  integers), negative-transfer results;
- protocol conformance (`conforms`, executed task count, declared sample
  size, mismatches);
- qualification policy digest, partition, issued/expiry timestamps;
- signer key id and Ed25519 signature.

Signing is domain-separated:
`sis-v3:evaluation_certificate:1\0` + canonical JSON without `signature`.

## Actual candidate delivery

`CandidateDeliveryAttestationV1` is harness-signed and binds:

- candidate id, record digest and content digest;
- `delivery_digest` — digest of the exact guidance delivered for one task;
- task id, evaluator receipt digest;
- harness identity and session nonce;
- signature.

The certificate's per-task entry carries both the delivery digest and
the attestation record digest. `QualificationValidator` resolves every
attestation, verifies its signature, checks candidate/task/receipt
identity and recomputes the aggregate delivery digest. A candidate ID
supplied by an optimizer is not delivery evidence.

## Qualification policy

`QualificationPolicy` states:

- required evidence class (production: `confirmatory`);
- partition (holdout);
- minimum sample size and optional required protocol/preregistration
  digests;
- confidence level and minimum effect (milli-scaled);
- whether the interval's lower bound must be positive;
- maximum negative-transfer rate and regressions;
- delivery-attestation requirement;
- authorized repository digests and task ids;
- protocol-conformance requirement.

`QualificationValidator` re-derives every mandatory check:

1. certificate signature;
2. candidate id/digest/content identity;
3. delivery attestation per task;
4. evaluator authority;
5. protocol identity;
6. preregistration identity;
7. sample size (policy and protocol);
8. holdout partition and task scope;
9. receipt count, uniqueness and authentication;
10. protocol conformance (not just a flag: executed count and declared
    sample are recomputed);
11. statistical acceptance;
12. negative transfer/regressions;
13. certificate revocation/expiry;
14. repository/task authorization.

Any failure blocks production qualification. A forged `conforms=true`
flag with two receipts and a 29-task protocol fails
`sample_count_meets_protocol`, `sample_count_meets_policy` and
`receipt_count_matches_sample`.

## Registry enforcement

`CandidateRegistry` with a `qualification_policy` requires
`certificate_ref` on `evaluating → qualified`, validates it against the
exact candidate, requires the qualification receipt set to equal the
certificate receipt set, stores the certificate, and re-validates it on
every serving read. A missing, tampered, expired or revoked certificate
fails closed. A registry without a policy is `demonstration` mode and
cannot serve production.

## Tests

`tests/v3/test_evaluation_certificates.py` covers:

- conforming 29-task certificate qualifies;
- 2-task experiment cannot satisfy 29;
- sample count must match receipts;
- unrelated task receipt rejected;
- candidate digest mismatch rejected;
- receipt from an unauthorized repository rejected;
- high-risk skill security blocks production qualification;
- missing delivery attestation blocks;
- forged conformance flag cannot override evidence;
- exploratory evidence retained but not production;
- unknown protocol, policy mismatch, negative transfer, nonpositive
  interval, expiry, revocation, missing certificate and receipt-set
  mismatch;
- production gateway excludes demonstration-only registries.
