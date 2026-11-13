"""Gate 2: Docker isolation qualification contracts.

The live qualification itself needs Docker; these tests pin the policy
digest contract and re-verify the stored attestation against the policy
it names, without requiring a daemon.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import qualify_docker_isolation as gate2
from sis.v3.isolation import (ProductionIsolationPolicy,
                              verify_production_isolation)
from sis.v3.contracts import ExecutionReceiptV1, IsolationAttestationV1

EVIDENCE = ROOT / "evidence" / "sandbox" / "gate2_isolation"


class PolicyDigestTests(unittest.TestCase):
    def test_policy_digest_is_deterministic_hex(self) -> None:
        first = gate2.policy_digest("a" * 64)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, gate2.policy_digest("a" * 64))

    def test_policy_digest_binds_the_image(self) -> None:
        self.assertNotEqual(gate2.policy_digest("a" * 64),
                            gate2.policy_digest("b" * 64))

    def test_properties_cover_every_probe_check(self) -> None:
        for name in ("net:denied", "fs:root_read_only",
                     "fs:workspace_confined", "user:non_root",
                     "caps:dropped", "proc:no_new_privileges"):
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


if __name__ == "__main__":
    unittest.main()
