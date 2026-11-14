# V335-02 — Production-verdict trust boundary repair

Status: implemented on `repair/v335-resource-security`. Scope limited to
`src/sis/v3/evaluation_runtime.py`, `src/sis/v3/isolation.py`,
`src/sis/v3/verifier.py`, and their regressions. No receipt schema,
control-plane, or unrelated changes.

## Defect

`classify_execution(production=True, isolation_verification=...)` accepted
a freely constructed `IsolationVerification(ok=True, receipt_digest=...)`.
A dataclass instance is not a cryptographic capability, so any caller
could manufacture a positive verdict and obtain TASK_PASS without a signed
attestation.

## Fix

- `classify_execution` no longer accepts `isolation_verification`.
  `production=True` is fail-closed and always returns SANDBOX_FAILURE.
  It is retained only so legacy callers cannot silently qualify.
- `ProductionClassification` and `classify_production_execution(receipt,
  attestation, policy, ...)` are the only route that can return TASK_PASS
  under production conditions. The route:
  - parses the actual `IsolationAttestationV1` (a positive verification
    object fails schema parsing);
  - verifies signer, backend allowlist, policy/image digests, required
    properties, expiry/freshness, and the exact receipt/command/workspace/
    worker binding;
  - rejects a local `isolation:unverified_local` receipt even when the
    attestation verifies;
  - only then maps the receipt to TASK_PASS/TASK_FAIL/TIMEOUT/RESOURCE_LIMIT.
- `OutcomeVerifier.evaluate` uses this route. Invalid evidence still raises
  `EvaluationRejected` before any V2 receipt is issued; a local-marker
  execution with valid attestation produces an `error` V2 receipt, never
  pass/fail.
- `ProductionIsolationPolicy` gains `revoked_keys`;
  `verify_production_isolation` rejects `signer_revoked`.
- `verify_isolation_attestation` remains documented as development-only.
  Its boolean can no longer qualify production because the public mapper
  does not accept it.

## Must-fail coverage

- Forged `IsolationVerification(ok=True, receipt_digest=receipt.digest)`
  → SANDBOX_FAILURE (`attestation_malformed`).
- Boolean `isolation_verification` → `TypeError` (parameter removed).
- Authentic attestation for a different execution receipt → SANDBOX_FAILURE
  (`receipt_mismatch`).
- Local `isolation:unverified_local` receipt with a valid attestation →
  SANDBOX_FAILURE.
- Revoked signer → SANDBOX_FAILURE (`signer_revoked`).
- Untrusted signer claiming `seccomp:inner_filter` → SANDBOX_FAILURE
  (`untrusted_signer`).
- Correctly attested production V2 receipt in the controlled harness →
  TASK_PASS and V2 issuance (existing `ProductionVerifierTests`).

## Results

- Focused isolation/runtime/trust-boundary suites: 204 passed, with only
  the expected pre-seal release-identity failure.
- Full suite: 1264 passed, 13 skipped, 1 expected pre-seal failure
  (`ReleaseIdentityTests.test_release_commit_covers_current_source`).

## Known pre-seal condition

`RELEASE_SHA256.json` remains the immutable v3.3.4 baseline. The release
identity test will fail until the v3.3.5 seal; do not regenerate the
manifest for this ticket.

## Remaining work

V335-03 memory chain membership/retrieval, V335-04 pinned suite and docs.
