# SIS v3.3.2 acceptance matrix

Reconstructed from the plan's five workstreams and M0–M9 acceptance
criteria. Status is based on the tests actually executed on this tree.

| # | Scenario | Test | Status |
|---|---|---|---|
| 1 | Same nonce, two SQLite replicas: one commit | `test_same_nonce_two_replicas_one_commit` | PASS |
| 2 | Same nonce, separate control-plane instances | `test_replay_across_separate_control_plane_instances` | PASS |
| 3 | Same nonce, two PostgreSQL replicas | `test_two_replicas_share_one_serving_decision` | PASS (opt-in) |
| 4 | Duplicate nonce rejected by the control plane | `test_control_plane_rejects_duplicate_nonce` | PASS |
| 5 | Identity cannot be disabled in production | `test_identity_cannot_be_disabled_in_production` | PASS |
| 6 | Missing identity produces no guidance | `test_missing_identity_abstains` | PASS |
| 7 | Expired identity produces no guidance | `test_expired_identity_abstains` | PASS |
| 8 | Over-long identity lifetime rejected | `test_identity_lifetime_is_bounded` | PASS |
| 9 | Requester contradiction produces no guidance | `test_requester_contradiction_abstains` | PASS |
| 10 | Revocation committed before decision blocks serving | `test_revocation_committed_before_decision_blocks_serving` | PASS |
| 11 | Revocation during composition aborts the decision | `test_revocation_during_composition_aborts` | PASS |
| 12 | Restored custody history is detected | `test_restored_revocation_history_is_detected` | PASS |
| 13 | Deleted revocation log is detected | `test_deleted_revocation_log_is_detected` | PASS |
| 14 | Deleted dependency link invalidates the certificate | `test_deleted_dependency_link_invalidates_certificate` | PASS |
| 15 | Tampered signed dependency link is invalid | `test_tampered_signed_link_is_invalid` | PASS |
| 16 | Diamond evidence graph is active | `test_diamond_dependency_is_active` | PASS |
| 17 | Dependency cycle is invalid | `test_cycle_is_invalid` | PASS |
| 18 | Revoked shared dependency propagates | `test_shared_dependency_with_revocation_still_reports_revoked` | PASS |
| 19 | v3 HTTP requires a bearer token | `test_v3_requires_bearer` | PASS |
| 20 | Legacy `/v1` routes are isolated | `test_legacy_v1_routes_are_isolated` | PASS |
| 21 | Advisory is distinct from abstention | `test_valid_bearer_serves_and_returns_authorization` | PASS |
| 22 | Outcome binds to the exact authorization | `test_outcome_endpoint_persists`, `test_outcome_rejects_unknown_authorization_id` | PASS |
| 23 | Control-plane outage fails closed | `test_control_plane_outage_abstains` | PASS |
| 24 | Custody outage fails closed | `test_custody_outage_abstains` | PASS |
| 25 | Fresh control plane seeds from the checkpoint | `test_fresh_control_plane_seeds_from_checkpoint` | PASS |

## Additional controls outside the 25 rows

| Control | Test | Status |
|---|---|---|
| Control-plane schema version recorded/refused/upgraded | `test_schema_version_is_recorded`, `test_newer_schema_is_refused`, `test_older_schema_is_upgraded` | PASS |
| Checkpoint signer rotation requires a new epoch | `test_new_signer_requires_new_epoch` | PASS |
| Expired v3 API token rejected | `test_expired_api_key_is_rejected` | PASS |
| Readiness reports authority/custody/control plane | `test_health_reports_v3_readiness` | PASS |
| Signed SLSA-style provenance binds the archive digest | `test_signed_provenance_binds_archive` | PASS |
| Provenance tamper/wrong-archive/wrong-signer rejected | `test_tampered_payload_fails`, `test_wrong_archive_fails`, `test_wrong_signer_fails` | PASS |
| Production executor refuses unverified isolation | `test_production_executor_refuses_unverified_isolation` | PASS |
| Production classification rejects unverified receipts | `test_production_classification_rejects_unverified_receipt` | PASS |

## Still not covered

| Area | Status | Reason |
|---|---|---|
| Full multi-host PostgreSQL deployment | PARTIAL | A disposable PostgreSQL 14.20 cluster and the CI service job pass; real network, roles and TLS are deployment-specific |
| Evaluator escape / containment validation | OPEN | M6; no OS-validated Linux sandbox and no adversarial escape suite |
| SLSA level conformance | PARTIAL | Signed in-toto/SLSA-shaped statement implemented; not a SLSA level claim |
| Real-agent efficacy | OPEN | M9; external agent quota blocked the prior run |
