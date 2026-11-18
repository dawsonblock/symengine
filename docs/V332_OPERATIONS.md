# SIS v3.3.2 operations

This is the deployment and recovery guide for the M0–M5 authority
controls. It does not qualify evaluator isolation (M6) or efficacy (M9).

## Profiles

### Single-host development

- SQLite candidate registry, SQLite control plane, file checkpoint store.
- `require_signed_links=True` is recommended; bind a custody link signer.
- Do not treat this profile as cross-replica replay protection.

### Multi-process production

- `PostgresControlPlane` with a DSN such as
  `postgresql://sis_control@db/sis_control`.
- `require_signed_links=True` is **required**: production `serve()`
  abstains with `evidence_custody_unsigned_links` when the bound custody
  store accepts unsigned dependency links.
- Use separate database roles for the signing/authority process and the
  custody process; the adapter accepts one DSN, so role separation is a
  deployment grant boundary.
- Run the v3 service behind a TLS reverse proxy and set
  `SIS_V3_ONLY=1`. Configuring the v3 service already isolates legacy
  `/v1` routes unless `SIS_ALLOW_LEGACY_V1=1`.
- Pin dependencies with `requirements-lock.txt`.

## Wiring the service

`sis serve` without options starts only the legacy `/v1` learning surface.
`sis serve --v3-config v3.json` composes the production v3 boundary through
`sis.v3.bootstrap.build_v3_service` and serves it (legacy `/v1` routes are then
isolated unless `SIS_ALLOW_LEGACY_V1=1`). The JSON file carries only public
trust anchors and paths (relative paths resolve against the file's directory);
every key below is mandatory and a missing or malformed one refuses to start:

| Key | Meaning |
| --- | --- |
| `candidate_database` | candidate registry SQLite file |
| `custody_root`, `custody_revocation_keys` | evidence custody directory and its revocation signer keys (signed links are always required) |
| `checkpoint_store`, `authority_keys`, `authority_epoch`, `authority_policy_version` | signed checkpoint log and verifier (`max_checkpoint_age_seconds` optional) |
| `control_plane` | SQLite path or `postgresql://` DSN |
| `repository_registry`, `repository_registry_public_key` | signed repository registry JSONL |
| `execution_identity_keys` | harness keys for execution identities |
| `evaluator_keys`, `operator_keys` | candidate evidence/receipt and decision signers |
| `certificate_keys`, `delivery_keys` | certificate and delivery-attestation signers |
| `evaluation_protocol` | preregistered protocol document (inline or a path) |
| `qualification_policy` | `QualificationPolicy` fields |
| `api_keys_file` | JSON `{token: requester}` (secret; keep it out of the config) |
| `authority_signer` (optional) | `{"seed_file", "key_id", "issuer_identity"}`; binds the `AuthorityJournal` and `custody.bind_on_change(journal.publish)` in this process |

Startup also refuses an authority that is not checkpoint-verified. Receipts and
delivery attestations are resolved from custody and re-authenticated. The same
composition can be built in application code and bound with
`create_server(..., v3_service=...)`; the manual equivalent is:

```python
from sis.server import create_server
from sis.v3.serving import GovernedServingGateway
from sis.v3.serving_service import V3ServingService

gateway = GovernedServingGateway(
    registry,                          # CandidateRegistry, production=True
    repository_registry=repositories,  # RepositoryRegistry
    production=True,
    execution_identity_authority=identities,  # ExecutionIdentityAuthority
    control_plane=control_plane,       # SqliteControlPlane or PostgresControlPlane
)
service = V3ServingService(
    gateway, api_keys={token: {"requester": "agent-1"}})
httpd = create_server("127.0.0.1", 8765, v3_service=service)
httpd.serve_forever()
```

`registry`, `repositories`, `identities` and `control_plane` are the components
described in this document; the snippet is a wiring sketch, not a complete
deployment. Constructing the gateway with `production=True` requires a shared
control plane and rejects a disabled execution identity; each serve additionally
requires a checkpointed registry, a production qualification policy and evidence
custody. Bind `custody.bind_on_change(journal.publish)` before serving so
revocations are witnessed immediately.

## First serve after upgrading from 3.3.1

The control-plane schema is created automatically and records
`SCHEMA_VERSION` in `schema_meta`; a database from a newer release is
refused. The `authority_head` row is seeded from the latest signed checkpoint after the local
candidate and custody state verify against it. If the local state is
ahead of the checkpoint (an interrupted publication), the serve abstains;
run `registry.publish_pending()` to publish the pending state, then retry.

Manual seeding is available through
`CandidateRegistry.seed_authority_head(control_plane)`.

Control-plane schema version 3 adds a unique index on
`guidance_outcome.receipt_digest`: one authenticated evaluator receipt
backs at most one outcome. A version-2 database that already attached
one receipt to several authorizations is refused at open
(`control_plane_outcome_receipt_reused`) for an operator to resolve.
Schema creation and the version row are race-safe across replicas.

## Operator token authorizations

Token-mode promotion decisions record
`operator_token_hmac:<token_sha256>:<HMAC-SHA256(token, decision payload)>`.
Replicas holding only the token digest check the digest; an auditor
holding the token re-verifies every decision with
`PromotionController.verify(operator_token=...)`. The legacy constant
`operator_token_sha256:<digest>` is still read from existing rows but is
refused for new commits.

## Custody links

`EvidenceCustodyStore(require_signed_links=True)` requires every
dependency manifest to be signed. Bind the custody principal before
qualification:

```python
custody = EvidenceCustodyStore(
    root, trusted_revocation_keys={key_id: public_hex},
    require_signed_links=True)
custody.bind_link_signer(seed, key_id)
```

Unsigned legacy links are accepted only when `require_signed_links` is
false, and are cross-checked against the certificate's declared receipt
and delivery digests. Re-link legacy custody before enabling signed
links.

Signed or unsigned, a link manifest is only valid for the certificate
whose digest names it: verification binds the manifest's declared
certificate digest to the path it was read from and compares its
dependency commitments to the certificate's receipt, delivery, and
attestation digests. A valid manifest copied over another certificate's
link file is rejected; missing, cyclic, revoked, or superseded
dependencies are rejected through the same path in `status()` and
`verify()`.

## Revocation publication

Bind `custody.bind_on_change(journal.publish)` so a revocation or
supersession immediately advances the signed checkpoint and the shared
authority head. If publication fails, the log entry is durable but
unwitnessed and serving fails closed until publication succeeds.

## Key rotation

- **Authority checkpoint key:** a new signer must use a strictly higher
  `authority_epoch`. `FileAuthorityCheckpointStore.compare_and_append`
  rejects a signer change at the same or lower epoch. Update
  `AuthorityStateVerifier.expected_epoch` only after the new checkpoint
  is published.
- **Custody / harness keys:** trusted key maps accept multiple key ids.
  Add the new key, publish a checkpoint if custody changed, then remove
  the old key after the overlap window.
- **v3 API keys:** values may be `{"requester": ..., "expires_at": ...}`.
  Expired tokens are rejected with 401. Rotate by adding the new token,
  switching clients, then removing the old token.

## Health and monitoring

`GET /health` returns 200 with `v3.checks` when the authority, custody
and control plane are readable, and 503 with `status=degraded` otherwise.
The check reports the checkpoint digest, custody heads and head
sequence; it does not expose keys or guidance text. There is no metrics
exporter yet; scrape the health endpoint and application logs.

## Disaster recovery

The signed checkpoint file is the independent rollback witness. Restore,
in order:

1. Candidate registry database.
2. Custody objects, links, revocation and supersession logs.
3. Checkpoint file.
4. Empty control-plane database (schema is recreated).

Then call `seed_authority_head` or serve once. A restored older custody
directory or checkpoint fails the head/count comparison; do not bypass
it. A control-plane database restored without the checkpoint file cannot
reconstruct the witness.

## Release verification

```bash
python tools/build_release.py
python tools/package_release.py \
  --release SIS-v3.3.2-AUTHORITY-CONSISTENCY \
  --status IMPLEMENTED_NOT_EFFICACY_QUALIFIED \
  --passed <n> --skipped <n> \
  --provenance-key /secure/release-seed.hex \
  --provenance-key-id release-key-1
python tools/verify_release.py release/SIS-v3.3.2-AUTHORITY-CONSISTENCY.zip
python tools/verify_provenance.py \
  --envelope release/provenance.dsse.json \
  --archive release/SIS-v3.3.2-AUTHORITY-CONSISTENCY.zip \
  --public-key <64-hex-public-key>
```

The provenance statement follows the in-toto Statement v1 / SLSA
provenance v1 shape and is signed as a DSSE envelope. The signing key
must come from the release custodian; a test key is not a trust root.

## Not qualified

- **Evaluator isolation (M6):** `LocalSubprocessExecutor` refuses to run
  in production unless `verified_isolation=True`, and
  `classify_execution(production=True)` requires the
  `isolation:verified` marker. No backend currently emits that marker
  after independent validation, so hostile-code execution is disabled.
- **Efficacy (M9):** no real-agent improvement is claimed.
