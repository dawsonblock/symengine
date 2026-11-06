# Evidence Custody and Revocation

## Defect closed

A signed certificate is only useful if the evidence it cites still
exists, has not been altered, and has not been revoked or superseded.
Disappearance of evidence must not silently change the interpretation of
qualification.

## Store

`EvidenceCustodyStore` is content-addressed:

- `objects/<aa>/<digest>.json` — immutable record payload;
- `objects/<aa>/<digest>.meta.json` — record type, schema version,
  content SHA-256 and domain-separated digest;
- `links/<certificate_digest>.json` — certificate dependency manifest
  (candidate, receipts, evidence, delivery attestations);
- `revocations.jsonl` — signed, hash-chained revocations;
- `supersessions.jsonl` — signed, hash-chained supersessions.

Writes are atomic (temp + fsync + rename) and read-only after creation.
Reads verify both the content hash and the domain-separated digest; an
altered object is `corrupt`, not a valid substitute.

## Status

`status(digest)` returns:

| Status | Meaning |
|---|---|
| `active` | object and all dependencies present, unrevoked |
| `revoked` | the object or a dependency is revoked |
| `superseded` | the object or a dependency is superseded |
| `missing` | object absent |
| `corrupt` | object content/digest mismatch |
| `invalid` | dependency missing/corrupt, or a cycle |

`CandidateRegistry` consults custody status for the certificate on every
qualified serving read. `evidence_missing`, `evidence_corrupt`,
`evidence_revoked`, `evidence_superseded` and
`evidence_custody_unavailable` all fail closed.

## Revocation and supersession

`revoke(target_digest, kind, reason, seed, key_id)` appends a signed
entry with a previous-entry digest. `supersede(old, new, ...)` does the
same. Loaders verify the chain and every signature; a rewritten log fails
closed. Revoking a receipt invalidates every certificate that links it;
revoking a certificate invalidates the candidate's serving basis.

## Offline policy

`OfflineEvidencePolicy` makes offline serving explicit:

- `allow_offline_serving` (default `False`);
- `max_revocation_age_seconds`;
- `expected_revocation_head`.

`check_offline_serving` denies offline serving by default, rejects a
stale revocation head, and rejects revocation evidence older than the
configured bound. Durable certificates may be sufficient for offline
verification, but the deployment must state that and its freshness
requirement. Silence is not consent.

## Tests

`tests/v3/test_execution_identity_custody.py` covers:

- certificate dependency manifest;
- deleted certificate;
- altered receipt;
- revoked certificate;
- revoked receipt invalidating a dependent candidate;
- superseded certificate;
- offline default denial and explicit offline policy;
- stale revocation checkpoint;
- missing dependency in custody verification;
- tampered revocation log.
