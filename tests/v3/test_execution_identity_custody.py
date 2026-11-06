"""PR-03: authenticated execution identity and evidence custody.

Serving must verify the harness-signed execution context rather than
trusting a repository name in task text. Qualification evidence must be
durable: deletion, alteration, revocation or supersession of a receipt,
certificate or delivery attestation prevents trusted serving.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sis.v3 import signatures
from sis.v3.candidates import CandidateError
from sis.v3.checkpoints import (AuthorityJournal, AuthorityStateVerifier,
                                FileAuthorityCheckpointStore)
from sis.v3.control_plane import SqliteControlPlane
from sis.v3.evidence_custody import (EvidenceCustodyError,
                                     EvidenceCustodyStore,
                                     OfflineEvidencePolicy)
from sis.v3.execution_identity import (ExecutionIdentityAuthority,
                                       sign_execution_identity)
from sis.v3.serving import GovernedServingGateway
from tests.v3.authority_testkit import make_registry, register_repo
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_evaluation_certificates import (
    CertificateFixture,
    REPO,
    _keypair,
)

COMMIT = "abc1234"
FAMILY = "fam-a"


class ProductionFixture:
    def __init__(self, root: Path):
        self.root = root
        self.cert = CertificateFixture(root)
        self.stack = self.cert.stack
        self.registry = self.stack.registry

        self.custody_seed, custody_public, self.custody_key = _keypair(
            "custody")
        self.custody = EvidenceCustodyStore(
            root / "custody",
            trusted_revocation_keys={
                self.custody_key: custody_public.hex()},
            require_signed_links=True)
        self.custody.bind_link_signer(self.custody_seed, self.custody_key)
        self.registry.bind_evidence_custody(
            self.custody, require=True,
            delivery_resolver=self.cert.attestations.__getitem__)

        self.authority_seed, authority_public = signatures.generate_keypair()
        self.authority_key = "authority-key-1"
        self.store = FileAuthorityCheckpointStore(
            root / "authority" / "checkpoints.jsonl",
            trusted_authority_keys={
                self.authority_key: authority_public.hex()})
        self.verifier = AuthorityStateVerifier(
            self.store,
            trusted_authority_keys={
                self.authority_key: authority_public.hex()},
            expected_epoch=1,
            expected_policy_version="sis-v3.3.1-authority-policy")
        self.registry.bind_checkpoint_verifier(
            self.verifier, production_serving=True)
        self.control_plane = SqliteControlPlane(
            root / "control" / "plane.db")
        self.journal = AuthorityJournal(
            self.registry, self.store, signer_seed=self.authority_seed,
            signer_key_id=self.authority_key, issuer_identity="authority",
            authority_epoch=1,
            policy_version="sis-v3.3.1-authority-policy",
            control_plane=self.control_plane)
        self.registry.bind_authority_journal(self.journal)
        self.journal.publish()
        self.custody.bind_on_change(self.journal.publish)

        self.repo_registry, self.repo_seed = make_registry()
        register_repo(
            self.repo_registry, self.repo_seed, registry_id="repo-1",
            family_id=FAMILY, base_tree_digest=REPO,
            base_commit=COMMIT)
        self.identity_seed, identity_public, self.identity_key = _keypair(
            "identity")
        self.identity_authority = ExecutionIdentityAuthority(
            trusted_harness_keys={
                self.identity_key: identity_public.hex()},
            repository_registry=self.repo_registry)
        self.gateway = GovernedServingGateway(
            self.registry, repository_registry=self.repo_registry,
            production=True,
            execution_identity_authority=self.identity_authority,
            used_session_nonces=set(),
            control_plane=self.control_plane)

        self.certificate = self.cert.certificate()
        self.cert.qualify(self.certificate)

    def close(self):
        self.stack.close()
        self.control_plane.close()

    def publish(self):
        """Anchor the current candidate and custody state."""
        return self.journal.publish()

    def identity(self, **overrides):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        fields = {
            "schema_version": 1,
            "identity_id": "id-1",
            "requester_identity": "agent-1",
            "repository_id": "repo-1",
            "repository_commit": COMMIT,
            "repository_tree_digest": REPO,
            "workspace_identity": "workspace-1",
            "task_id": "task-1",
            "task_family": FAMILY,
            "harness_identity": "harness-1",
            "session_nonce": "nonce-1",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=10)).isoformat().replace(
                "+00:00", "Z"),
            "signer_key_id": self.identity_key,
        }
        fields.update(overrides)
        return sign_execution_identity(self.identity_seed, **fields)


class ExecutionIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = ProductionFixture(Path(self.temp.name))
        self.addCleanup(self.fixture.close)

    def test_authenticated_identity_serves_qualified_guidance(self):
        identity = self.fixture.identity()
        guidance = self.fixture.gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        self.assertEqual(guidance.decision, "advisory")
        self.assertEqual(guidance.reason_code, "no_qualified_procedure")
        self.assertIn("do the thing", " ".join(
            guidance.helpful_next_checks))
        audit = []
        # A second gateway with a shared audit sink records the identity.
        gateway = GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            production=True,
            execution_identity_authority=self.fixture.identity_authority,
            used_session_nonces=set(), audit_sink=audit.append,
            control_plane=self.fixture.control_plane)
        gateway.serve(_request(), repository_id="repo-1",
                      execution_identity=self.fixture.identity(
                          session_nonce="nonce-audit"))
        self.assertEqual(len(audit), 1)
        self.assertIn("execution_identity", audit[0])
        self.assertEqual(audit[0]["serving_mode"], "production")

    def test_missing_identity_abstains(self):
        guidance = self.fixture.gateway.serve(
            _request(), repository_id="repo-1")
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_mismatched_tree_abstains(self):
        identity = self.fixture.identity(repository_tree_digest="b" * 64)
        guidance = self.fixture.gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_forged_repository_id_abstains(self):
        identity = self.fixture.identity(repository_id="unknown-repo")
        guidance = self.fixture.gateway.serve(
            _request(), repository_id="unknown-repo",
            execution_identity=identity)
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_modified_workspace_identity_breaks_signature(self):
        identity = self.fixture.identity()
        tampered = identity.to_dict()
        tampered["workspace_identity"] = "workspace-evil"
        result = self.fixture.identity_authority.verify(tampered)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason,
                         "execution_identity_signature_invalid")

    def test_expired_identity_abstains(self):
        identity = self.fixture.identity(
            issued_at="2020-01-01T00:00:00Z",
            expires_at="2020-01-02T00:00:00Z")
        guidance = self.fixture.gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_replayed_session_abstains(self):
        identity = self.fixture.identity()
        first = self.fixture.gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        second = self.fixture.gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        self.assertEqual(first.reason_code, "no_qualified_procedure")
        self.assertEqual(second.reason_code, "catalog_unavailable")

    def test_contradictory_request_tree_abstains(self):
        request = _request().to_dict()
        request["repo_snapshot_digest"] = "b" * 64
        guidance = self.fixture.gateway.serve(
            request, repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_commit_mismatch_abstains(self):
        identity = self.fixture.identity(repository_commit="deadbee")
        guidance = self.fixture.gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_family_mismatch_abstains(self):
        identity = self.fixture.identity(task_family="fam-b")
        guidance = self.fixture.gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_untrusted_signer_is_rejected(self):
        wrong_seed, _, _ = _keypair("wrong")
        identity = sign_execution_identity(
            wrong_seed,
            **{k: v for k, v in self.fixture.identity().to_dict().items()
               if k not in {"schema_version", "attestation"}})
        result = self.fixture.identity_authority.verify(identity)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason,
                         "execution_identity_signature_invalid")


class EvidenceCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = ProductionFixture(Path(self.temp.name))
        self.addCleanup(self.fixture.close)

    def _object_paths(self, digest):
        base = self.fixture.custody.root / "objects" / digest[:2]
        return (base / f"{digest}.json", base / f"{digest}.meta.json")

    @staticmethod
    def _unlink(path):
        # Custody objects are read-only on POSIX; Windows also needs the
        # read-only attribute cleared before deletion.
        try:
            os.chmod(path, 0o666)
        except OSError:
            pass
        path.unlink()

    def test_custody_records_certificate_dependencies(self):
        certificate = self.fixture.certificate
        link = self.fixture.custody.link_for(certificate.digest)
        self.assertIsNotNone(link)
        self.assertEqual(len(link["receipts"]), 29)
        self.assertEqual(len(link["deliveries"]), 29)
        self.assertEqual(self.fixture.custody.status(certificate.digest),
                         "active")
        self.assertTrue(self.fixture.custody.verify()["ok"])

    def test_deleted_certificate_blocks_serving(self):
        certificate = self.fixture.certificate
        for path in self._object_paths(certificate.digest):
            self._unlink(path)
        with self.assertRaisesRegex(CandidateError, "evidence_missing"):
            self.fixture.registry.get(self.fixture.cert.candidate.candidate_id)
        guidance = self.fixture.gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_altered_receipt_blocks_serving(self):
        receipt = self.fixture.cert.receipts[0]
        path, _ = self._object_paths(receipt.digest)
        path.chmod(0o644)
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(CandidateError, "evidence_invalid"):
            self.fixture.registry.get(self.fixture.cert.candidate.candidate_id)

    def test_revoked_certificate_blocks_serving(self):
        certificate = self.fixture.certificate
        self.fixture.custody.revoke(
            certificate.digest, kind="certificate", reason="evaluator error",
            seed=self.fixture.custody_seed,
            key_id=self.fixture.custody_key)
        self.fixture.publish()
        with self.assertRaisesRegex(CandidateError, "evidence_revoked"):
            self.fixture.registry.get(self.fixture.cert.candidate.candidate_id)

    def test_revoked_receipt_invalidates_dependent_candidate(self):
        receipt = self.fixture.cert.receipts[0]
        self.fixture.custody.revoke(
            receipt.digest, kind="receipt", reason="bad outcome",
            seed=self.fixture.custody_seed,
            key_id=self.fixture.custody_key)
        self.fixture.publish()
        with self.assertRaisesRegex(CandidateError, "evidence_revoked"):
            self.fixture.registry.get(self.fixture.cert.candidate.candidate_id)

    def test_superseded_certificate_blocks_serving(self):
        certificate = self.fixture.certificate
        self.fixture.custody.supersede(
            certificate.digest, "e" * 64, reason="newer evaluation",
            seed=self.fixture.custody_seed,
            key_id=self.fixture.custody_key)
        self.fixture.publish()
        with self.assertRaisesRegex(CandidateError, "evidence_superseded"):
            self.fixture.registry.get(self.fixture.cert.candidate.candidate_id)

    def test_offline_serving_is_denied_by_default(self):
        with self.assertRaisesRegex(CandidateError,
                                    "offline_evidence_policy_required"):
            self.fixture.registry.check_offline_serving(offline=True)

    def test_explicit_offline_policy_allows_durable_certificates(self):
        self.fixture.registry.bind_evidence_custody(
            self.fixture.custody, require=True,
            delivery_resolver=self.fixture.cert.attestations.__getitem__,
            offline_policy=OfflineEvidencePolicy(
                allow_offline_serving=True,
                max_revocation_age_seconds=86_400,
                expected_revocation_head=self.fixture.custody.revocation_head()))
        result = self.fixture.registry.check_offline_serving(
            offline=True, now="2026-10-26T12:00:00Z")
        self.assertTrue(result["ok"])

    def test_stale_revocation_checkpoint_blocks_offline_serving(self):
        self.fixture.custody.revoke(
            "f" * 64, kind="receipt", reason="test",
            seed=self.fixture.custody_seed,
            key_id=self.fixture.custody_key)
        self.fixture.registry.bind_evidence_custody(
            self.fixture.custody, require=True,
            delivery_resolver=self.fixture.cert.attestations.__getitem__,
            offline_policy=OfflineEvidencePolicy(
                allow_offline_serving=True,
                expected_revocation_head="0" * 64))
        with self.assertRaisesRegex(CandidateError,
                                    "revocation_checkpoint_stale"):
            self.fixture.registry.check_offline_serving(offline=True)

    def test_custody_verification_reports_missing_dependency(self):
        receipt = self.fixture.cert.receipts[0]
        for path in self._object_paths(receipt.digest):
            self._unlink(path)
        report = self.fixture.custody.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("missing" in problem
                            for problem in report["problems"]))

    def test_tampered_revocation_log_fails_closed(self):
        certificate = self.fixture.certificate
        self.fixture.custody.revoke(
            certificate.digest, kind="certificate", reason="test",
            seed=self.fixture.custody_seed,
            key_id=self.fixture.custody_key)
        path = self.fixture.custody.root / "revocations.jsonl"
        path.write_bytes(path.read_bytes().replace(b"test", b"evil"))
        with self.assertRaisesRegex(EvidenceCustodyError,
                                    "revocation_log_signature_invalid"):
            self.fixture.custody.revocations()


if __name__ == "__main__":
    unittest.main()
