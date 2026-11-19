"""Gate 2: Docker isolation qualification contracts.

The live qualification itself needs Docker; these tests pin the policy
digest contract and re-verify the stored attestation against the policy
it names, without requiring a daemon.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import qualify_docker_isolation as gate2
import verify_external_attestation as external
from sis.v3 import signatures
from sis.v3.docker_sandbox import DockerSandboxExecutor
from sis.v3.isolation import (ProductionIsolationPolicy,
                              issue_attestation_for_receipt,
                              verify_production_isolation)
from sis.v3.contracts import ExecutionReceiptV1, IsolationAttestationV1

EVIDENCE = ROOT / "evidence" / "sandbox" / "gate2_isolation"


def _executor(root, image_hex):
    with mock.patch.object(DockerSandboxExecutor, "_require_docker",
                           return_value="test-server"):
        return DockerSandboxExecutor(
            root, image="sis-evaluator@sha256:" + image_hex,
            production=True, runtime="runsc",
            seccomp_profile=gate2.DEFAULT_SECCOMP, image_id=image_hex)


class PolicyDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_policy_digest_is_deterministic_hex(self) -> None:
        first = _executor(self.root / "a", "a" * 64).policy_digest()
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(
            first, _executor(self.root / "b", "a" * 64).policy_digest())

    def test_policy_digest_binds_the_image(self) -> None:
        self.assertNotEqual(
            _executor(self.root / "a", "a" * 64).policy_digest(),
            _executor(self.root / "b", "b" * 64).policy_digest())

    def test_properties_cover_every_probe_check(self) -> None:
        for name in ("net:denied", "fs:root_read_only",
                     "fs:workspace_confined", "user:non_root",
                     "caps:dropped", "proc:no_new_privileges",
                     "kernel:gvisor", "syscalls:seccomp_allowlist"):
            self.assertIn(name, gate2.PROPERTIES)


class StoredEvidenceTests(unittest.TestCase):
    def _load(self):
        if not (EVIDENCE / "qualification.json").exists():
            self.skipTest("Gate 2 qualification evidence is not present")
        record = json.loads((EVIDENCE / "qualification.json").read_text())
        receipt = ExecutionReceiptV1.from_json(
            (EVIDENCE / "receipt.json").read_bytes())
        attestation = IsolationAttestationV1.from_json(
            (EVIDENCE / "attestation.json").read_bytes())
        return record, receipt, attestation

    def _policy(self, record):
        return ProductionIsolationPolicy(
            allowed_backends=frozenset({record["backend"]}),
            trusted_keys={record["signer_key_id"]: record["signer_public_key"]},
            required_policy_digest=record["policy_digest"],
            required_image_digest=record["image_digest"],
            required_properties=frozenset(record["properties"]),
        )

    def test_stored_attestation_verifies_at_issue_time(self) -> None:
        record, receipt, attestation = self._load()
        result = verify_production_isolation(
            attestation, receipt, self._policy(record),
            at_time=record["generated_at"])
        self.assertTrue(result.ok, result.reason)

    def test_stored_attestation_rejects_a_different_image(self) -> None:
        record, receipt, attestation = self._load()
        policy = ProductionIsolationPolicy(
            allowed_backends=frozenset({record["backend"]}),
            trusted_keys={record["signer_key_id"]: record["signer_public_key"]},
            required_policy_digest=record["policy_digest"],
            required_image_digest="0" * 64,
            required_properties=frozenset(record["properties"]),
        )
        result = verify_production_isolation(
            attestation, receipt, policy, at_time=record["generated_at"])
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "image_mismatch")

    def test_stored_receipt_claims_the_docker_backend_not_local(self) -> None:
        _, receipt, _ = self._load()
        self.assertIn("isolation:docker_sandbox", receipt.security_errors)
        self.assertNotIn("isolation:unverified_local", receipt.security_errors)
        self.assertNotIn("docker:image_tag_only", receipt.security_errors)

    def test_no_private_seed_is_stored_with_the_evidence(self) -> None:
        if not EVIDENCE.exists():
            self.skipTest("Gate 2 qualification evidence is not present")
        self.assertEqual(list(EVIDENCE.glob("*.seed")), [])

    def test_stored_evidence_is_current_or_marked_stale(self) -> None:
        # Evidence that no longer describes the executor must say so: it
        # is current only if its policy digest is what the production
        # launch policy for its image produces today.
        record, _receipt, _attestation = self._load()
        with tempfile.TemporaryDirectory() as temp:
            current = _executor(
                Path(temp), record["image_digest"]).policy_digest()
        freshness_path = EVIDENCE / "freshness.json"
        if record["policy_digest"] == current:
            return
        self.assertTrue(freshness_path.is_file(),
                        "stale Gate 2 evidence must carry freshness.json")
        freshness = json.loads(freshness_path.read_text())
        self.assertEqual(freshness["status"], "stale")
        for name, digest in freshness["files"].items():
            self.assertEqual(
                hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest(),
                digest, name)


if __name__ == "__main__":
    unittest.main()


class ExternalAttestationTests(unittest.TestCase):
    """The production path: a key held elsewhere signs, we verify."""

    POLICY_DIGEST = "a" * 64
    IMAGE_DIGEST = "b" * 64

    def setUp(self):
        path = EVIDENCE / "receipt.json"
        if not path.exists():
            self.skipTest("Gate 2 qualification receipt is not present")
        self.receipt = ExecutionReceiptV1.from_json(path.read_bytes())
        self.now = datetime.now(timezone.utc)
        self.issued = self.now.isoformat(
            timespec="seconds").replace("+00:00", "Z")
        self.expires = (self.now + timedelta(minutes=5)).isoformat(
            timespec="seconds").replace("+00:00", "Z")

    def _attestation(self, seed, key_id="external-isolator"):
        return issue_attestation_for_receipt(
            self.receipt, seed, key_id,
            backend="docker_sandbox",
            policy_digest=self.POLICY_DIGEST,
            image_digest=self.IMAGE_DIGEST,
            properties=gate2.PROPERTIES,
            issued_at=self.issued, expires_at=self.expires)

    def test_an_externally_signed_attestation_verifies(self):
        seed, public = signatures.generate_keypair()
        attestation = self._attestation(seed)
        result = external.verify(
            self.receipt, attestation.to_dict(),
            public_key=public.hex(), key_id="external-isolator",
            image_digest=self.IMAGE_DIGEST,
            policy_digest=self.POLICY_DIGEST,
            properties=list(gate2.PROPERTIES), at_time=self.issued)
        self.assertTrue(result.ok, result.reason)

    def test_a_wrong_public_key_fails_closed(self):
        seed, _public = signatures.generate_keypair()
        _other_seed, other_public = signatures.generate_keypair()
        attestation = self._attestation(seed)
        result = external.verify(
            self.receipt, attestation.to_dict(),
            public_key=other_public.hex(), key_id="external-isolator",
            image_digest=self.IMAGE_DIGEST,
            policy_digest=self.POLICY_DIGEST,
            properties=list(gate2.PROPERTIES), at_time=self.issued)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "signature_invalid")

    def test_a_different_image_digest_fails_closed(self):
        seed, public = signatures.generate_keypair()
        attestation = self._attestation(seed)
        result = external.verify(
            self.receipt, attestation.to_dict(),
            public_key=public.hex(), key_id="external-isolator",
            image_digest="c" * 64,
            policy_digest=self.POLICY_DIGEST,
            properties=list(gate2.PROPERTIES), at_time=self.issued)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "image_mismatch")

    def test_cli_writes_a_verification_record(self):
        seed, public = signatures.generate_keypair()
        attestation = self._attestation(seed)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            receipt_path = root / "receipt.json"
            receipt_path.write_bytes(self.receipt.canonical_bytes())
            attestation_path = root / "attestation.json"
            attestation_path.write_text(json.dumps(attestation.to_dict()))
            output = root / "verification.json"
            argv = [
                "--receipt", str(receipt_path),
                "--attestation", str(attestation_path),
                "--public-key", public.hex(),
                "--key-id", "external-isolator",
                "--image-digest", self.IMAGE_DIGEST,
                "--policy-digest", self.POLICY_DIGEST,
                "--output", str(output),
            ]
            for prop in gate2.PROPERTIES:
                argv += ["--property", prop]
            self.assertEqual(external.main(argv), 0)
            record = json.loads(output.read_text())
            self.assertTrue(record["verified"])
            self.assertEqual(record["reason"], "ok")
            self.assertEqual(record["kind"],
                             "external_isolation_verification")
