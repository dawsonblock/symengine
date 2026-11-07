"""SIS v3.3.2 authority-consistency regression tests.

Each test encodes one of the five reproduced v3.3.1 defects (identity
disablement, cross-replica replay, custody rollback, diamond dependency
traversal, revocation ordering) plus the production boundary added in
M5. They are expected to fail on the v3.3.1 source and pass here.
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from sis.server import create_server
from sis.v3 import serving as serving_mod
from sis.v3.checkpoints import (AuthorityStateVerifier, CheckpointConflict,
                                sign_checkpoint)
from sis.v3.composition import _conflicts
from sis.v3.control_plane import (SCHEMA_VERSION, ControlPlaneError,
                                  SqliteControlPlane)
from sis.v3.evaluation_runtime import (SANDBOX_FAILURE, TASK_PASS,
                                       classify_execution)
from sis.v3.evidence_custody import EvidenceCustodyStore
from sis.v3.learning_qualification import newcombe_difference_interval
from sis.v3 import signatures
from sis.v3.execution_identity import sign_execution_identity
from sis.v3.serving import GovernedServingGateway
from sis.v3.runner import (CommandSpec, LocalSubprocessExecutor,
                           ResourceLimits, RunnerError)
from sis.v3.serving_service import V3ServingService
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_evaluation_certificates import (CertificateFixture, _keypair)
from tests.v3.test_execution_identity_custody import ProductionFixture

TOKEN = "v3-serving-token-for-regression-tests-0001"


class _Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = ProductionFixture(self.root / "stack")
        self.addCleanup(self.fixture.close)

    def gateway(self, **kwargs):
        kwargs.setdefault("production", True)
        kwargs.setdefault("execution_identity_authority",
                          self.fixture.identity_authority)
        kwargs.setdefault("control_plane", self.fixture.control_plane)
        return GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            **kwargs)


class IdentityEnforcementTests(_Base):
    def test_identity_cannot_be_disabled_in_production(self):
        with self.assertRaisesRegex(ValueError,
                                    "production_requires_execution_identity"):
            self.gateway(require_execution_identity=False)

    def test_production_requires_shared_control_plane(self):
        with self.assertRaisesRegex(ValueError,
                                    "production_requires_control_plane"):
            GovernedServingGateway(
                self.fixture.registry,
                repository_registry=self.fixture.repo_registry,
                production=True,
                execution_identity_authority=self.fixture.identity_authority)

    def test_identity_lifetime_is_bounded(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        identity = self.fixture.identity(
            issued_at=(now - timedelta(minutes=1)).isoformat().replace(
                "+00:00", "Z"),
            expires_at=(now + timedelta(hours=6)).isoformat().replace(
                "+00:00", "Z"))
        result = self.fixture.identity_authority.verify(identity)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason,
                         "execution_identity_lifetime_exceeded")

    def test_requester_contradiction_abstains(self):
        guidance = self.gateway().serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity(),
            requester_identity="someone-else")
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_requester_binding_serves_when_matched(self):
        guidance = self.gateway().serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity(),
            requester_identity="agent-1")
        self.assertEqual(guidance.decision, "advisory")


class ReplayTests(_Base):
    def test_same_nonce_two_replicas_one_commit(self):
        identity = self.fixture.identity()
        first = self.gateway().serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        second = self.gateway().serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        self.assertEqual(first.decision, "advisory")
        self.assertEqual(second.decision, "abstain")
        self.assertEqual(second.reason_code, "catalog_unavailable")
        receipt = self.fixture.control_plane.authorization_for_nonce(
            "nonce-1")
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["guidance_digest"], first.digest)

    def test_replay_across_separate_control_plane_instances(self):
        # Two connections to the same database model two serving
        # processes; the uniqueness constraint, not a Python set, decides.
        second_plane = SqliteControlPlane(self.fixture.control_plane.path)
        self.addCleanup(second_plane.close)
        identity = self.fixture.identity()
        first = self.gateway().serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        second = GovernedServingGateway(
            self.fixture.registry,
            repository_registry=self.fixture.repo_registry,
            production=True,
            execution_identity_authority=self.fixture.identity_authority,
            control_plane=second_plane).serve(
                _request(), repository_id="repo-1",
                execution_identity=identity)
        self.assertEqual(first.decision, "advisory")
        self.assertEqual(second.decision, "abstain")
        self.assertEqual(
            self.fixture.control_plane.authorization_for_nonce(
                "nonce-1")["guidance_digest"], first.digest)

    def test_control_plane_outage_abstains(self):
        gateway = self.gateway()
        self.fixture.control_plane.close()
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_schema_version_is_recorded(self):
        plane = SqliteControlPlane(self.root / "schema.db")
        self.addCleanup(plane.close)
        self.assertEqual(plane.schema_version(), SCHEMA_VERSION)

    def test_newer_schema_is_refused(self):
        path = self.root / "schema-new.db"
        plane = SqliteControlPlane(path)
        plane.close()
        con = sqlite3.connect(str(path))
        con.execute("UPDATE schema_meta SET version=99 WHERE singleton=1")
        con.commit()
        con.close()
        with self.assertRaisesRegex(ControlPlaneError,
                                    "control_plane_schema_too_new"):
            SqliteControlPlane(path)

    def test_older_schema_is_upgraded(self):
        path = self.root / "schema-old.db"
        plane = SqliteControlPlane(path)
        plane.close()
        con = sqlite3.connect(str(path))
        con.execute("UPDATE schema_meta SET version=0 WHERE singleton=1")
        con.commit()
        con.close()
        plane = SqliteControlPlane(path)
        self.addCleanup(plane.close)
        self.assertEqual(plane.schema_version(), SCHEMA_VERSION)

    def test_checkpoint_ahead_of_head_abstains_then_recovers(self):
        latest = self.fixture.store.get_latest()
        checkpoint = sign_checkpoint(
            self.fixture.authority_seed, schema_version=1,
            checkpoint_id="cp-crash-window", authority_epoch=1,
            sequence=latest.sequence + 1,
            journal_sequence=latest.journal_sequence,
            previous_digest=latest.digest, journal_head=latest.journal_head,
            candidate_revision_digest=latest.candidate_revision_digest,
            candidate_count=latest.candidate_count,
            qualified_count=latest.qualified_count,
            revocation_head=latest.revocation_head,
            supersession_head=latest.supersession_head,
            custody_entry_count=latest.custody_entry_count,
            issuer_identity="authority",
            policy_version="sis-v3.3.1-authority-policy",
            issued_at="2026-10-27T00:00:00Z",
            signer_key_id=self.fixture.authority_key)
        self.fixture.store.compare_and_append(latest.sequence, checkpoint)
        gateway = self.gateway()
        identity = self.fixture.identity()
        first = gateway.serve(_request(), repository_id="repo-1",
                              execution_identity=identity)
        self.assertEqual(first.decision, "abstain")
        self.assertEqual(first.reason_code, "catalog_unavailable")
        self.fixture.registry.seed_authority_head(
            self.fixture.control_plane)
        second = gateway.serve(_request(), repository_id="repo-1",
                               execution_identity=identity)
        self.assertEqual(second.decision, "advisory")

    def test_fresh_control_plane_seeds_from_checkpoint(self):
        # Simulate a v3.3.1 -> v3.3.2 upgrade: the checkpoint store is
        # authoritative, the control-plane database is empty.
        fresh = SqliteControlPlane(self.root / "fresh-control.db")
        self.addCleanup(fresh.close)
        gateway = self.gateway(control_plane=fresh)
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "advisory")
        head = fresh.authority_head()
        self.assertIsNotNone(head)
        self.assertEqual(head["checkpoint_digest"],
                         self.fixture.store.get_latest().digest)

    def test_control_plane_rejects_duplicate_nonce(self):
        values = dict(
            nonce="nonce-direct", session_digest="b" * 64,
            expires_at="2030-01-01T00:00:00Z", task_id="task-1",
            repository_id="repo-1", guidance_digest="c" * 64,
            decision="advisory", snapshot_digest="d" * 64)
        self.fixture.control_plane.commit_authorization(**values)
        with self.assertRaisesRegex(ControlPlaneError,
                                    "session_nonce_replayed"):
            self.fixture.control_plane.commit_authorization(**values)


class RevocationConsistencyTests(_Base):
    def test_revocation_during_composition_aborts(self):
        original = serving_mod.compose_guidance

        def compose_then_revoke(*args, **kwargs):
            self.fixture.custody.revoke(
                self.fixture.certificate.digest, kind="certificate",
                reason="committed mid-decision",
                seed=self.fixture.custody_seed,
                key_id=self.fixture.custody_key)
            return original(*args, **kwargs)

        with mock.patch.object(serving_mod, "compose_guidance",
                               compose_then_revoke):
            guidance = self.gateway().serve(
                _request(), repository_id="repo-1",
                execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")
        self.assertNotIn("do the thing", " ".join(
            guidance.helpful_next_checks))

    def test_revocation_committed_before_decision_blocks_serving(self):
        self.fixture.custody.revoke(
            self.fixture.certificate.digest, kind="certificate",
            reason="bad evaluation", seed=self.fixture.custody_seed,
            key_id=self.fixture.custody_key)
        self.fixture.publish()
        guidance = self.gateway().serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_restored_revocation_history_is_detected(self):
        backup = self.root / "custody-backup"
        shutil.copytree(self.fixture.custody.root, backup)
        self.fixture.custody.revoke(
            self.fixture.certificate.digest, kind="certificate",
            reason="revoked then rolled back",
            seed=self.fixture.custody_seed,
            key_id=self.fixture.custody_key)
        self.fixture.publish()
        shutil.rmtree(self.fixture.custody.root)
        shutil.copytree(backup, self.fixture.custody.root)
        restored = EvidenceCustodyStore(
            self.fixture.custody.root,
            trusted_revocation_keys={
                self.fixture.custody_key:
                    self.fixture.custody._keys[self.fixture.custody_key]})
        self.assertEqual(restored.status(self.fixture.certificate.digest),
                         "active")
        with self.assertRaisesRegex(Exception,
                                    "revocation_head_mismatch|"
                                    "custody_entry_count_regression"):
            self.fixture.registry.authority_status()
        guidance = self.gateway().serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")

    def test_revocation_is_visible_to_a_second_process(self):
        observer = EvidenceCustodyStore(
            self.fixture.custody.root,
            trusted_revocation_keys={
                self.fixture.custody_key:
                    self.fixture.custody._keys[self.fixture.custody_key]})
        self.assertEqual(
            observer.status(self.fixture.certificate.digest), "active")
        self.fixture.custody.revoke(
            self.fixture.certificate.digest, kind="certificate",
            reason="committed by another process",
            seed=self.fixture.custody_seed,
            key_id=self.fixture.custody_key)
        self.assertEqual(
            observer.status(self.fixture.certificate.digest), "revoked")
        self.assertEqual(
            observer.authority_snapshot()["custody_entry_count"], 1)

    def test_deleted_dependency_link_invalidates_certificate(self):
        link_path = (self.fixture.custody.root / "links"
                     / f"{self.fixture.certificate.digest}.json")
        self.assertTrue(link_path.exists())
        link_path.unlink()
        self.assertEqual(
            self.fixture.custody.status(self.fixture.certificate.digest),
            "invalid")
        self.assertFalse(self.fixture.custody.verify()["ok"])

    def test_custody_outage_abstains(self):
        gateway = self.gateway()
        shutil.move(str(self.fixture.custody.root),
                    str(self.root / "custody-gone"))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_deleted_revocation_log_is_detected(self):
        self.fixture.custody.revoke(
            self.fixture.certificate.digest, kind="certificate",
            reason="history will be deleted",
            seed=self.fixture.custody_seed,
            key_id=self.fixture.custody_key)
        self.fixture.publish()
        (self.fixture.custody.root / "revocations.jsonl").unlink()
        with self.assertRaisesRegex(Exception,
                                    "custody_entry_count_regression|"
                                    "revocation_head_mismatch"):
            self.fixture.registry.authority_status()


class DependencyGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.custody = EvidenceCustodyStore(Path(self.temp.name) / "custody")

    def test_diamond_dependency_is_active(self):
        leaf = self.custody.put({"leaf": "d"})
        left = self.custody.put({"node": "b"})
        right = self.custody.put({"node": "c"})
        root = self.custody.put({"node": "a"})
        self.custody.link(left, receipts=(leaf,))
        self.custody.link(right, receipts=(leaf,))
        self.custody.link(root, receipts=(left, right))
        self.assertEqual(self.custody.status(root), "active")

    def test_cycle_is_invalid(self):
        first = self.custody.put({"node": "first"})
        second = self.custody.put({"node": "second"})
        self.custody.link(first, receipts=(second,))
        self.custody.link(second, receipts=(first,))
        self.assertEqual(self.custody.status(first), "invalid")

    def test_shared_dependency_with_revocation_still_reports_revoked(self):
        leaf = self.custody.put({"leaf": "d"})
        left = self.custody.put({"node": "b"})
        right = self.custody.put({"node": "c"})
        root = self.custody.put({"node": "a"})
        self.custody.link(left, receipts=(leaf,))
        self.custody.link(right, receipts=(leaf,))
        self.custody.link(root, receipts=(left, right))
        seed, public = __import__(
            "sis.v3.signatures", fromlist=["generate_keypair"]
        ).generate_keypair()
        custody = EvidenceCustodyStore(
            self.custody.root,
            trusted_revocation_keys={"k1": public.hex()})
        custody.revoke(leaf, kind="evidence", reason="bad",
                       seed=seed, key_id="k1")
        self.assertEqual(custody.status(root), "revoked")


class ProductionIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "README.txt").write_text("fixture\n")

    def test_production_executor_refuses_unverified_isolation(self):
        executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False, production=True)
        workspace = executor.prepare(self.base)
        spec = CommandSpec(
            argv=(sys.executable, "-c", "print(1)"),
            limits=ResourceLimits(
                cpu_seconds=20, wall_seconds=15, memory_bytes=1 << 30,
                output_bytes=1 << 20, disk_bytes=16 << 20,
                process_count=64))
        with self.assertRaisesRegex(RunnerError,
                                    "verified_isolation_required"):
            executor.run(workspace, spec)

    def test_production_classification_rejects_unverified_receipt(self):
        receipt = SimpleNamespace(
            security_errors=("isolation:unverified_local",),
            timeout=False, exit_status=0)
        self.assertEqual(
            classify_execution(receipt, production=True), SANDBOX_FAILURE)

    def test_production_classification_accepts_verified_marker(self):
        receipt = SimpleNamespace(
            security_errors=("isolation:verified",),
            timeout=False, exit_status=0)
        self.assertEqual(
            classify_execution(receipt, production=True), TASK_PASS)


class SignedLinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seed, public = __import__(
            "sis.v3.signatures", fromlist=["generate_keypair"]
        ).generate_keypair()
        self.key = "link-key-1"
        self.custody = EvidenceCustodyStore(
            self.root / "custody",
            trusted_revocation_keys={self.key: public.hex()},
            require_signed_links=True)
        self.custody.bind_link_signer(self.seed, self.key)

    def test_signed_link_verifies(self):
        leaf = self.custody.put({"leaf": "d"})
        root = self.custody.put({"node": "a"})
        self.custody.link(root, receipts=(leaf,))
        self.assertEqual(self.custody.status(root), "active")
        self.assertTrue(self.custody.verify()["ok"])

    def test_tampered_signed_link_is_invalid(self):
        leaf = self.custody.put({"leaf": "d"})
        other = self.custody.put({"leaf": "e"})
        root = self.custody.put({"node": "a"})
        self.custody.link(root, receipts=(leaf,))
        path = self.custody.root / "links" / f"{root}.json"
        manifest = json.loads(path.read_text())
        manifest["receipts"] = [other]
        path.chmod(0o644)
        path.write_text(json.dumps(manifest, sort_keys=True,
                                   separators=(",", ":")))
        self.assertEqual(self.custody.status(root), "invalid")
        self.assertFalse(self.custody.verify()["ok"])

    def test_unsigned_link_rejected_when_required(self):
        unsigned = EvidenceCustodyStore(
            self.root / "unsigned", require_signed_links=True)
        leaf = unsigned.put({"leaf": "d"})
        root = unsigned.put({"node": "a"})
        with self.assertRaisesRegex(Exception, "link_signer_required"):
            unsigned.link(root, receipts=(leaf,))


class SignedLinkSubstitutionTests(unittest.TestCase):
    """A valid signature must also be bound to the certificate it describes.

    Signing proves a trusted key produced a manifest. It does not prove
    the manifest belongs in *this* certificate's link file, so a manifest
    signed for one certificate could be copied over another's and drop
    the revoked dependencies that made the second one unusable.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = CertificateFixture(self.root)
        self.seed, public, self.key = _keypair("custody")
        self.custody = EvidenceCustodyStore(
            self.root / "custody",
            trusted_revocation_keys={self.key: public.hex()},
            require_signed_links=True)
        self.custody.bind_link_signer(self.seed, self.key)
        for receipt in self.fixture.receipts:
            self.custody.put(receipt)
        for attestation in self.fixture.attestations.values():
            self.custody.put(attestation)

    def _link(self, certificate, *, evidence=()):
        self.custody.put(certificate)
        self.custody.link(
            certificate.digest,
            receipts=[item["receipt_digest"]
                      for item in certificate.individual_task_receipts],
            evidence=evidence,
            deliveries=[item["attestation_digest"]
                        for item in certificate.individual_task_receipts])

    def test_signed_link_cannot_be_substituted_across_certificates(self):
        plain = self.fixture.certificate(grader_identity="grader-A")
        revoked = self.fixture.certificate(grader_identity="grader-B")
        dependency = self.custody.put({"evidence": "depends-on-me"})
        self._link(plain)
        self._link(revoked, evidence=(dependency,))
        self.custody.revoke(
            dependency, kind="evidence", reason="withdrawn",
            seed=self.seed, key_id=self.key)
        self.assertEqual(self.custody.status(revoked.digest), "revoked")

        links = self.root / "custody" / "links"
        target = links / f"{revoked.digest}.json"
        target.chmod(0o644)
        shutil.copyfile(links / f"{plain.digest}.json", target)

        self.assertEqual(self.custody.status(revoked.digest), "invalid")
        report = self.custody.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("certificate_mismatch" in problem
                            for problem in report["problems"]),
                        report["problems"])

    def test_signed_link_must_match_certificate_dependencies(self):
        certificate = self.fixture.certificate()
        self.custody.put(certificate)
        self.custody.link(
            certificate.digest,
            receipts=[item["receipt_digest"]
                      for item in certificate.individual_task_receipts[:1]],
            deliveries=[item["attestation_digest"]
                        for item in certificate.individual_task_receipts])
        self.assertEqual(self.custody.status(certificate.digest), "invalid")
        self.assertFalse(self.custody.verify()["ok"])


class ConflictDetectionTests(unittest.TestCase):
    """Polarity-aware lexical conflict detection."""

    def test_opposite_polarity_instructions_conflict(self):
        self.assertTrue(_conflicts("Always deploy", "Never deploy"))

    def test_same_polarity_instructions_do_not_conflict(self):
        self.assertFalse(_conflicts("Never deploy", "Do not deploy"))
        self.assertFalse(_conflicts("Always deploy", "Must deploy"))

    def test_unrelated_instructions_do_not_conflict(self):
        self.assertFalse(
            _conflicts("Always deploy on Fridays", "Never use fixtures"))

    def test_negation_against_plain_instruction_conflicts(self):
        self.assertTrue(_conflicts(
            "Do not retry failed jobs", "Retry failed jobs"))


class TrustKeyValidationTests(unittest.TestCase):
    """Enrollment rejects keys that are not usable Ed25519 points."""

    def test_identity_public_key_is_rejected(self):
        identity = bytes([1]) + bytes(31)
        signature = identity + bytes(32)
        self.assertFalse(
            signatures.verify(signature, b"any message", identity))

    def test_small_order_public_key_is_rejected(self):
        # The small-order Ed25519 encodings (including the identity
        # point) must never authenticate a signature.
        small_order = [
            bytes([1]) + bytes(31),
            bytes(32),
            bytes([0xEC]) + bytes([0xFF] * 30) + bytes([0x7F]),
            bytes(31) + bytes([0x80]),
            bytes([1]) + bytes(30) + bytes([0x80]),
            bytes.fromhex(
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
            bytes.fromhex(
                "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        ]
        for public in small_order:
            self.assertFalse(signatures.is_valid_public_key(public),
                             public.hex())
            forged = bytes(64)
            self.assertFalse(
                signatures.verify(forged, b"message", public), public.hex())

    def test_genuine_public_key_is_accepted(self):
        seed, public = signatures.generate_keypair()
        self.assertTrue(signatures.is_valid_public_key(public))
        signature = signatures.sign(seed, b"message")
        self.assertTrue(signatures.verify(signature, b"message", public))

    def test_custody_rejects_small_order_trust_key(self):
        from sis.v3.evidence_custody import EvidenceCustodyError
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(
                    EvidenceCustodyError, "revocation_public_key_invalid"):
                EvidenceCustodyStore(
                    tmp, trusted_revocation_keys={
                        "bad": (bytes([1]) + bytes(31)).hex()})

    def test_identity_authority_rejects_small_order_trust_key(self):
        from sis.v3.execution_identity import (
            ExecutionIdentityAuthority, ExecutionIdentityError)
        with self.assertRaisesRegex(
                ExecutionIdentityError, "harness_public_key_invalid"):
            ExecutionIdentityAuthority(
                trusted_harness_keys={
                    "bad": (bytes([1]) + bytes(31)).hex()},
                repository_registry=None)


class KeyRotationTests(_Base):
    def _checkpoint(self, seed, key_id, *, epoch):
        latest = self.fixture.store.get_latest()
        return sign_checkpoint(
            seed, schema_version=1, checkpoint_id="cp-rotate",
            authority_epoch=epoch, sequence=latest.sequence + 1,
            journal_sequence=latest.journal_sequence,
            previous_digest=latest.digest, journal_head=latest.journal_head,
            candidate_revision_digest=latest.candidate_revision_digest,
            candidate_count=latest.candidate_count,
            qualified_count=latest.qualified_count,
            revocation_head=latest.revocation_head,
            supersession_head=latest.supersession_head,
            custody_entry_count=latest.custody_entry_count,
            issuer_identity="authority",
            policy_version="sis-v3.3.1-authority-policy",
            issued_at="2026-10-27T00:00:00Z", signer_key_id=key_id)

    def test_new_signer_requires_new_epoch(self):
        seed, public = signatures.generate_keypair()
        self.fixture.store._keys["authority-key-2"] = public.hex()
        latest = self.fixture.store.get_latest()
        with self.assertRaisesRegex(CheckpointConflict,
                                    "rotation_requires_new_epoch"):
            self.fixture.store.compare_and_append(
                latest.sequence,
                self._checkpoint(seed, "authority-key-2", epoch=1))
        checkpoint = self._checkpoint(seed, "authority-key-2", epoch=2)
        self.fixture.store.compare_and_append(latest.sequence, checkpoint)
        keys = dict(self.fixture.store._keys)
        verifier = AuthorityStateVerifier(
            self.fixture.store, trusted_authority_keys=keys,
            expected_epoch=2,
            expected_policy_version="sis-v3.3.1-authority-policy")
        self.assertTrue(verifier.verify_local_state(
            self.fixture.registry.authority_state()).ok)
        stale = AuthorityStateVerifier(
            self.fixture.store, trusted_authority_keys=keys,
            expected_epoch=1,
            expected_policy_version="sis-v3.3.1-authority-policy")
        result = stale.verify_local_state(
            self.fixture.registry.authority_state())
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "authority_epoch_mismatch")


class LegacyCheckpointTests(unittest.TestCase):
    def test_v331_checkpoint_history_still_verifies(self):
        from sis.v3.checkpoints import FileAuthorityCheckpointStore
        fixture = Path(__file__).parent / "fixtures" / "v331_checkpoints"
        keys = json.loads((fixture / "keys.json").read_text())
        store = FileAuthorityCheckpointStore(
            fixture / "checkpoints.jsonl", trusted_authority_keys=keys)
        self.assertTrue(store.verify()["ok"])
        history = store.history()
        self.assertEqual([item.sequence for item in history], [1, 2])
        self.assertEqual(history[0].previous_digest, "0" * 64)
        self.assertEqual(history[1].previous_digest, history[0].digest)
        self.assertEqual(history[-1].revocation_head, "0" * 64)
        self.assertEqual(history[-1].custody_entry_count, 0)


class ControlPlaneTests(_Base):
    def test_outcome_binds_to_committed_receipt(self):
        identity = self.fixture.identity()
        gateway = self.gateway(
            receipt_authority=lambda digest: SimpleNamespace(
                task_id="task-1", outcome="pass"))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        gateway.record_outcome(
            task_id="task-1", served_digest=guidance.digest,
            receipt_digest="e" * 64, outcome="pass",
            requester="agent-1")
        receipt = self.fixture.control_plane.authorization_for_task("task-1")
        outcome = self.fixture.control_plane.outcome(
            receipt["authorization_id"])
        self.assertEqual(outcome["outcome"], "pass")
        self.assertEqual(receipt["requester"], "agent-1")

    def test_outcome_rejects_unbound_requester(self):
        identity = self.fixture.identity()
        gateway = self.gateway(
            receipt_authority=lambda digest: SimpleNamespace(
                task_id="task-1", outcome="pass"))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        with self.assertRaisesRegex(ValueError,
                                    "outcome_requester_mismatch"):
            gateway.record_outcome(
                task_id="task-1", served_digest=guidance.digest,
                receipt_digest="e" * 64, outcome="pass",
                requester="agent-2")

    def test_outcome_rejects_missing_requester(self):
        identity = self.fixture.identity()
        gateway = self.gateway(
            receipt_authority=lambda digest: SimpleNamespace(
                task_id="task-1", outcome="pass"))
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        with self.assertRaisesRegex(ValueError,
                                    "outcome_requester_mismatch"):
            gateway.record_outcome(
                task_id="task-1", served_digest=guidance.digest,
                receipt_digest="e" * 64, outcome="pass")

    def test_outcome_rejects_wrong_served_digest(self):
        identity = self.fixture.identity()
        gateway = self.gateway(
            receipt_authority=lambda digest: SimpleNamespace(
                task_id="task-1", outcome="pass"))
        gateway.serve(_request(), repository_id="repo-1",
                      execution_identity=identity)
        with self.assertRaisesRegex(ValueError, "served_guidance_unknown"):
            gateway.record_outcome(
                task_id="task-1", served_digest="f" * 64,
                receipt_digest="e" * 64, outcome="pass")

    def test_authority_head_is_monotonic(self):
        current = self.fixture.control_plane.authority_head()
        head = {
            "sequence": current["sequence"] + 1,
            "checkpoint_digest": "a" * 64,
            "journal_head": "b" * 64, "revocation_head": "0" * 64,
            "supersession_head": "0" * 64, "custody_entry_count": 0,
            "updated_at": "2026-10-27T00:00:00Z",
        }
        self.fixture.control_plane.advance_authority_head(head)
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authority_head_rollback"):
            self.fixture.control_plane.advance_authority_head(
                {**head, "sequence": current["sequence"]})
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authority_head_conflict"):
            self.fixture.control_plane.advance_authority_head(
                {**head, "checkpoint_digest": "c" * 64})


class ServingServiceTests(_Base):
    def service(self, *, requester="agent-1"):
        return V3ServingService(
            self.gateway(), api_keys={TOKEN: requester})

    def payload(self, **overrides):
        body = {
            "request": _request().to_dict(),
            "repository_id": "repo-1",
            "execution_identity": self.fixture.identity().to_dict(),
        }
        body.update(overrides)
        return body

    def test_missing_bearer_is_rejected(self):
        code, body = self.service().handle(
            "/v3/guidance", self.payload(), {})
        self.assertEqual(code, 401)
        self.assertEqual(body["error"], "unauthorized")

    def test_unknown_bearer_is_rejected(self):
        code, body = self.service().handle(
            "/v3/guidance", self.payload(),
            {"Authorization": "Bearer " + "x" * 40})
        self.assertEqual(code, 401)

    def test_valid_bearer_serves_and_returns_authorization(self):
        code, body = self.service().handle(
            "/v3/guidance", self.payload(),
            {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "advisory")
        self.assertTrue(body["qualified_advice"])
        self.assertFalse(body["abstained"])
        self.assertIsNotNone(body["authorization"])
        self.assertEqual(body["authorization"]["guidance_digest"],
                         body["guidance_digest"])

    def test_requester_mismatch_abstains(self):
        code, body = self.service(requester="agent-2").handle(
            "/v3/guidance", self.payload(),
            {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "abstain")
        self.assertTrue(body["abstained"])

    def test_unknown_field_is_rejected(self):
        code, body = self.service().handle(
            "/v3/guidance", self.payload(admin=True),
            {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "unknown_field")

    def test_outcome_endpoint_persists(self):
        service = V3ServingService(
            self.gateway(receipt_authority=lambda digest: SimpleNamespace(
                task_id="task-1", outcome="pass")),
            api_keys={TOKEN: "agent-1"})
        code, body = service.handle(
            "/v3/guidance", self.payload(),
            {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(code, 200)
        authorization_id = body["authorization"]["authorization_id"]
        code, body = service.handle(
            "/v3/outcome",
            {"task_id": "task-1",
             "served_digest": body["guidance_digest"],
             "receipt_digest": "e" * 64, "outcome": "pass",
             "authorization_id": authorization_id},
            {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(code, 200)
        self.assertTrue(body["recorded"])

    def test_health_reports_ok(self):
        health = self.service().health()
        self.assertTrue(health["ok"])
        self.assertTrue(health["checks"]["authority"]["ok"])
        self.assertTrue(health["checks"]["custody"]["ok"])
        self.assertTrue(health["checks"]["control_plane"]["ok"])

    def test_health_degrades_when_control_plane_closed(self):
        service = self.service()
        self.fixture.control_plane.close()
        health = service.health()
        self.assertFalse(health["ok"])
        self.assertFalse(health["checks"]["control_plane"]["ok"])

    def test_expired_api_key_is_rejected(self):
        service = V3ServingService(
            self.gateway(),
            api_keys={TOKEN: {"requester": "agent-1",
                              "expires_at": "2020-01-01T00:00:00Z"}})
        code, _ = service.handle(
            "/v3/guidance", self.payload(),
            {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(code, 401)

    def test_future_api_key_is_accepted(self):
        service = V3ServingService(
            self.gateway(),
            api_keys={TOKEN: {"requester": "agent-1",
                              "expires_at": "2030-01-01T00:00:00Z"}})
        code, body = service.handle(
            "/v3/guidance", self.payload(),
            {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "advisory")

    def test_outcome_rejects_unknown_authorization_id(self):
        service = V3ServingService(
            self.gateway(receipt_authority=lambda digest: SimpleNamespace(
                task_id="task-1", outcome="pass")),
            api_keys={TOKEN: "agent-1"})
        code, body = service.handle(
            "/v3/guidance", self.payload(),
            {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(code, 200)
        code, body = service.handle(
            "/v3/outcome",
            {"task_id": "task-1",
             "served_digest": body["guidance_digest"],
             "receipt_digest": "e" * 64, "outcome": "pass",
             "authorization_id": "auth-unknown"},
            {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "served_guidance_unknown")


class HttpBoundaryTests(_Base):
    def setUp(self):
        super().setUp()
        self.service = V3ServingService(
            self.gateway(), api_keys={TOKEN: "agent-1"})
        env = {"SIS_ALLOW_LEGACY_V1": "0"}
        with mock.patch.dict(os.environ, env, clear=False):
            self.httpd = create_server(
                "127.0.0.1", 0, db_path=str(self.root / "legacy.db"),
                v3_service=self.service)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self.httpd.sis_service is not None:
            self.httpd.sis_service.registry.close()
        self.thread.join(timeout=5)

    def request(self, method, path, body=None, *, token=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=8)
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        connection.request(method, path, json.dumps(body or {}), headers)
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        return response.status, payload

    def test_legacy_v1_routes_are_isolated(self):
        status, _ = self.request("GET", "/v1/tools")
        self.assertEqual(status, 404)
        status, _ = self.request(
            "POST", "/v1/predict", {"namespace": "default", "inputs": {}})
        self.assertEqual(status, 404)

    def test_v3_requires_bearer(self):
        status, body = self.request(
            "POST", "/v3/guidance",
            {"request": _request().to_dict(), "repository_id": "repo-1",
             "execution_identity": self.fixture.identity().to_dict()})
        self.assertEqual(status, 401)

    def test_health_reports_v3_readiness(self):
        status, body = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["v3"]["ok"])

    def test_v3_serves_with_bearer(self):
        status, body = self.request(
            "POST", "/v3/guidance",
            {"request": _request().to_dict(), "repository_id": "repo-1",
             "execution_identity": self.fixture.identity().to_dict()},
            token=TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "advisory")


class UnsignedCustodyTests(_Base):
    def test_production_rejects_unsigned_link_custody(self):
        # A custody store that accepts unsigned dependency links is not
        # a production authority: stripping revoked dependencies must not
        # be possible without touching the signed logs.
        unsigned = EvidenceCustodyStore(self.root / "unsigned-custody")
        self.fixture.registry.bind_evidence_custody(unsigned, require=True)
        guidance = self.gateway().serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")


def _strict_recommendation():
    return SimpleNamespace(
        decision="recommend", helpful_next_checks=("run tests",),
        procedure_ids=("proc-1",), revision="f" * 64,
        matched_preconditions=(
            {"kind": "language_is", "value": "python"},),
        contraindications=(),
        evidence_ids=("e" * 64,), approximate_tokens=10)


class _FlipStrict:
    """Strict gateway whose authority fingerprint advances mid-request."""

    def __init__(self):
        self.fingerprint = "a" * 64
        self.flipped = False

    def authority_fingerprint(self):
        return self.fingerprint

    def recommend(self, request, **kwargs):
        # A revocation committed while the decision was being prepared.
        self.fingerprint = "b" * 64
        self.flipped = True
        return _strict_recommendation()


class _StableStrict(_FlipStrict):
    def recommend(self, request, **kwargs):
        return _strict_recommendation()


class StrictAuthoritySnapshotTests(_Base):
    def test_strict_revocation_mid_request_abstains(self):
        strict = _FlipStrict()
        guidance = self.gateway(strict_gateway=strict).serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertTrue(strict.flipped)
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_strict_stable_authority_serves(self):
        strict = _StableStrict()
        guidance = self.gateway(strict_gateway=strict).serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fixture.identity())
        self.assertEqual(guidance.decision, "recommend")


class PairedStatisticsTests(unittest.TestCase):
    """Signed statistical claims must reconstruct from the paired matrix."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = CertificateFixture(Path(self.temp.name))

    def _interval(self, treat_solved, base_solved, n, *,
                  confidence_milli=950):
        from statistics import NormalDist
        z = NormalDist().inv_cdf(
            (1 + min(max(confidence_milli, 1), 999) / 1000) / 2)
        lower, upper = newcombe_difference_interval(
            treat_solved, n, base_solved, n, z=z)
        return {
            "method": "newcombe", "confidence_milli": confidence_milli,
            "lower_milli": round(1000 * lower),
            "upper_milli": round(1000 * upper),
            "point_estimate_milli": round(
                1000 * (treat_solved - base_solved) / n)}

    def test_reconstructed_statistics_accept_consistent_claims(self):
        certificate = self.fixture.certificate()
        validation = self.fixture.validator.validate(
            certificate, self.fixture.candidate)
        self.assertTrue(validation.ok, validation.failures)

    def test_claimed_point_estimate_must_match_receipts(self):
        # The honest point estimate is delta=1.0; claiming anything else
        # fails even when the interval is stated correctly.
        ci = {**self._interval(29, 0, 29), "point_estimate_milli": 900}
        certificate = self.fixture.certificate(confidence_interval=ci)
        validation = self.fixture.validator.validate(
            certificate, self.fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("paired_point_estimate", validation.failures)

    def test_claimed_interval_cannot_be_narrower_than_data(self):
        honest = self._interval(29, 0, 29)
        for ci in (dict(honest, lower_milli=honest["lower_milli"] + 1),
                   dict(honest, upper_milli=honest["upper_milli"] - 1)):
            certificate = self.fixture.certificate(confidence_interval=ci)
            validation = self.fixture.validator.validate(
                certificate, self.fixture.candidate)
            self.assertFalse(validation.ok)
            self.assertIn("paired_interval_not_narrower",
                          validation.failures)

    def test_wider_conservative_interval_is_accepted(self):
        # Agreement is coverage at the claimed confidence, not bit
        # equality: a strictly wider bound remains valid evidence.
        honest = self._interval(29, 0, 29)
        ci = dict(honest, lower_milli=honest["lower_milli"] - 1)
        certificate = self.fixture.certificate(confidence_interval=ci)
        validation = self.fixture.validator.validate(
            certificate, self.fixture.candidate)
        self.assertTrue(validation.ok, validation.failures)

    def test_interval_reconstructed_at_claimed_confidence(self):
        n = len(self.fixture.entries)
        # A bound one milli inside the reconstructed 99% interval is not
        # the reconstruction, even though it fits a 95% interval.
        too_narrow = self._interval(
            n, 0, n, confidence_milli=990)["lower_milli"] + 1
        certificate = self.fixture.certificate(confidence_interval={
            "method": "newcombe", "confidence_milli": 990,
            "lower_milli": too_narrow, "upper_milli": 1000,
            "point_estimate_milli": 1000})
        validation = self.fixture.validator.validate(
            certificate, self.fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("paired_interval_not_narrower", validation.failures)
        certificate = self.fixture.certificate(confidence_interval={
            "method": "newcombe", "confidence_milli": 990,
            "lower_milli": too_narrow - 1, "upper_milli": 1000,
            "point_estimate_milli": 1000})
        validation = self.fixture.validator.validate(
            certificate, self.fixture.candidate)
        self.assertTrue(validation.ok, validation.failures)

    def test_partial_evaluation_cannot_hide_paired_losses(self):
        fixture = self.fixture
        n = len(fixture.entries)
        # Two claimed losses; only one task is left "unevaluated", so at
        # most one loss may go uncounted and regressions=0 must fail.
        for entry in fixture.entries[:2]:
            entry["baseline_outcome"] = "pass"
            entry["outcome"] = "fail"
        ci = self._interval(n - 2, 2, n)
        certificate = fixture.certificate(
            confidence_interval=ci,
            negative_transfer_results={
                "evaluated": n - 1, "regressions": 0,
                "negative_transfer_count": 0, "rate_milli": 0})
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("paired_regressions", validation.failures)
        # Counting the one accountable loss satisfies the bound (the
        # second loss legitimately falls on the unevaluated task).
        certificate = fixture.certificate(
            confidence_interval=ci,
            negative_transfer_results={
                "evaluated": n - 1, "regressions": 1,
                "negative_transfer_count": 0, "rate_milli": 0})
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertNotIn("paired_regressions", validation.failures)

    def test_policy_primary_metric_must_agree(self):
        # Reproduced gap: a policy rebound for a different improvement
        # metric must not qualify a certificate issued for the protocol's
        # metric. Agreement is three-way: policy = certificate = protocol.
        import dataclasses
        from sis.v3.evaluation_certificate import QualificationValidator
        policy = dataclasses.replace(
            self.fixture.policy, primary_metric="cost_reduction")
        validator = QualificationValidator(
            policy,
            certificate_authority=self.fixture.cert_authority,
            delivery_authority=self.fixture.delivery_authority,
            protocol_registry=self.fixture.protocols,
            receipt_resolver=self.fixture.stack.resolve_receipt,
            delivery_resolver=self.fixture.deliveries.__getitem__)
        certificate = self.fixture.certificate(
            qualification_policy_digest=policy.digest)
        validation = validator.validate(
            certificate, self.fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("policy_primary_metric", validation.failures)

    def test_policy_requires_paired_outcomes_by_default(self):
        # The default policy refuses a certificate with no paired
        # matrix; the legacy opt-out must be set explicitly.
        self.assertTrue(self.fixture.policy.require_paired_outcomes)
        for entry in self.fixture.entries:
            del entry["baseline_outcome"]
        certificate = self.fixture.certificate()
        validation = self.fixture.validator.validate(
            certificate, self.fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("paired_outcomes_required", validation.failures)

    def test_explicit_opt_out_allows_unpaired_certificates(self):
        import dataclasses
        from sis.v3.evaluation_certificate import QualificationValidator
        policy = dataclasses.replace(
            self.fixture.policy, require_paired_outcomes=False)
        validator = QualificationValidator(
            policy,
            certificate_authority=self.fixture.cert_authority,
            delivery_authority=self.fixture.delivery_authority,
            protocol_registry=self.fixture.protocols,
            receipt_resolver=self.fixture.stack.resolve_receipt,
            delivery_resolver=self.fixture.deliveries.__getitem__)
        for entry in self.fixture.entries:
            del entry["baseline_outcome"]
        certificate = self.fixture.certificate(
            qualification_policy_digest=policy.digest)
        validation = validator.validate(
            certificate, self.fixture.candidate)
        self.assertTrue(validation.ok, validation.failures)

    def test_partial_pairing_fails_even_with_opt_out(self):
        # A certificate that pairs only a subset of receipts is neither
        # valid strict evidence nor a clean legacy artifact: the opt-out
        # exists for certificates with no paired matrix at all, so
        # selective pairing cannot skip the reconstruction checks under
        # any policy.
        import dataclasses
        from sis.v3.evaluation_certificate import QualificationValidator
        policy = dataclasses.replace(
            self.fixture.policy, require_paired_outcomes=False)
        validator = QualificationValidator(
            policy,
            certificate_authority=self.fixture.cert_authority,
            delivery_authority=self.fixture.delivery_authority,
            protocol_registry=self.fixture.protocols,
            receipt_resolver=self.fixture.stack.resolve_receipt,
            delivery_resolver=self.fixture.deliveries.__getitem__)
        for entry in self.fixture.entries[:3]:
            del entry["baseline_outcome"]
        certificate = self.fixture.certificate(
            qualification_policy_digest=policy.digest)
        validation = validator.validate(
            certificate, self.fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("paired_outcomes_uniform", validation.failures)


if __name__ == "__main__":
    unittest.main()
