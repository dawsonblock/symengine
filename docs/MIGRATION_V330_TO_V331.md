# Migrating v3.3.0 to v3.3.1

v3.3.1 is additive. No table is dropped and no candidate record is
rewritten. Existing v3.3 databases open, reseal legacy audit rows only
after the old chain verifies, and remain usable.

## 1. Upgrade the package

```bash
python3 -m pip install -e .
python3 -m pytest -q
```

The project version is now `3.3.1`; the CLI and existing imports are
unchanged.

## 2. Open the candidate registry

No schema command is required. `CandidateRegistry` creates the
`candidate_certificate` table if absent. Existing qualifications without
a certificate remain readable as **demonstration** evidence, not
production qualification.

## 3. Adopt an external checkpoint (before serving)

Recommended order:

1. Start the authority process with the checkpoint signing key.
2. Point `FileAuthorityCheckpointStore` at storage the candidate-database
   principal cannot write (different service identity/host/volume).
3. Anchor the registry **before** the first qualification:

```python
store = FileAuthorityCheckpointStore(
    "/var/lib/sis-authority/checkpoints.jsonl",
    trusted_authority_keys={"authority-1": PUBLIC_HEX},
)
verifier = AuthorityStateVerifier(
    store,
    trusted_authority_keys={"authority-1": PUBLIC_HEX},
    expected_epoch=1,
    expected_policy_version="sis-v3.3.1-authority-policy",
)
registry.bind_checkpoint_verifier(verifier, production_serving=True)
journal = AuthorityJournal(
    registry, store, signer_seed=SEED, signer_key_id="authority-1",
    issuer_identity="sis-authority", authority_epoch=1,
    policy_version="sis-v3.3.1-authority-policy",
)
registry.bind_authority_journal(journal)
journal.publish()
```

Anchoring a populated registry is trust-on-first-use. For strict
rollback resistance, anchor an empty registry and re-qualify candidates
through the v3.3.1 certificate path.

## 4. Configure production qualification

```python
policy = QualificationPolicy(
    policy_version="sis-v3.3.1-qualification-1",
    primary_metric="paired solved_delta E vs A",
    min_sample_size=29,
    required_protocol_digest=PROTOCOL_DIGEST,
    required_preregistration_digest=PROTOCOL_DIGEST,
    authorized_repository_digests=(REPO_DIGEST,),
)
validator = QualificationValidator(
    policy,
    certificate_authority=cert_authority,
    delivery_authority=delivery_authority,
    protocol_registry=protocol_registry,
    receipt_resolver=resolve_receipt,
    delivery_resolver=resolve_delivery,
)
registry = CandidateRegistry(
    path, receipt_authority=..., evidence_authority=...,
    decision_authority=...,
    expected_evaluation_protocol_digest=PROTOCOL_DIGEST,
    qualification_policy=policy,
    qualification_validator=validator,
    certificate_resolver=resolve_certificate,
    delivery_resolver=resolve_attestation,
    evidence_custody=custody,
    require_evidence_custody=True,
    checkpoint_verifier=verifier,
    production_serving=True,
)
```

`qualification_mode` becomes `production`; `qualify` now requires
`certificate_ref`.

## 5. Configure execution identity

```python
identity_authority = ExecutionIdentityAuthority(
    trusted_harness_keys={HARNESS_KEY: HARNESS_PUBLIC_HEX},
    repository_registry=repository_registry,
)
gateway = GovernedServingGateway(
    registry, repository_registry=repository_registry,
    production=True,
    execution_identity_authority=identity_authority,
)
```

The adapter issues `ExecutionIdentityV1` for each task. Production
serving refuses requests without it.

## 6. Evidence custody

Point `EvidenceCustodyStore` at durable, separately protected storage.
Store receipts, evidence, certificates and delivery attestations, then
link the certificate to its dependencies. Set an
`OfflineEvidencePolicy` explicitly if offline serving is required; the
default denies it.

## 7. Skills

Re-ingest skill trees. Candidate ids now include the authorization
scope, so the same content for two scopes produces two candidates. Old
unscoped candidates remain readable but should be retired; re-ingest is
idempotent per scope.

## 8. Rollback

The v3.3.1 tables are additive. To roll back to v3.3.0, stop serving,
retain the checkpoint/custody stores for audit, and run the v3.3.0 code
against the database. Do not delete checkpoint or custody history; it is
the evidence that v3.3.1 qualification was anchored.
