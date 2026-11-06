# Authenticated Execution Identity

## Defect closed

v3.3 resolved repository scope through a trusted registry, but a caller
could still supply a repository name or tree digest in task text. A
serving decision must be bound to the *actual* execution context, not to
untrusted text.

## Record

`ExecutionIdentityV1` is issued by the trusted agent adapter and binds:

- `identity_id`, `requester_identity`;
- `repository_id` — the registry id, not a display name;
- `repository_commit` and `repository_tree_digest`;
- `workspace_identity`;
- `task_id` and `task_family`;
- `harness_identity`;
- `session_nonce`;
- issued/expiry timestamps;
- signer key id and Ed25519 `attestation`.

Signing is domain-separated:
`sis-v3:execution_identity:1\0` + canonical JSON without `attestation`.

## Verification

`ExecutionIdentityAuthority.verify` checks:

1. signature against a trusted harness key;
2. timestamps (not future beyond 300 s skew, not expired, expiry after
   issue);
3. session-nonce replay against the gateway's used-nonce set;
4. repository id resolves in the trusted `RepositoryRegistry`;
5. tree digest equals the registry identity's base tree;
6. commit equals the registry's known base commit (when set);
7. task family equals the registry identity's family;
8. any caller-supplied repository id, tree, commit, task id, family or
   requester claim is consistent.

The gateway passes the request's task id, repository snapshot digest and
base commit as expected claims, so a valid identity for repository A
cannot authorize a request claiming repository B.

## Serving behavior

`GovernedServingGateway(production=True)` requires an execution identity
by default. Missing, forged, expired, replayed or contradictory contexts
return an abstention (`catalog_unavailable`) with a non-actionable
diagnostic. No candidate or skill text is included in
`helpful_next_checks` after an identity-related abstention.

A candidate may be authorized for a repository family rather than a
specific commit; the execution identity still has to be authenticated
and the current commit/tree still has to match the trusted registry.

## Tests

`tests/v3/test_execution_identity_custody.py` covers:

- authenticated identity serves qualified guidance;
- missing identity abstains;
- mismatched tree, forged repository id, modified workspace digest;
- expired context and replayed session;
- contradictory request tree, commit and family;
- untrusted signer.
